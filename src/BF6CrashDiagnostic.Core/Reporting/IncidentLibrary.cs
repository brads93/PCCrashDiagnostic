using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Reporting;

public sealed record LocalReportCopy(
    string ReportPath,
    bool Imported);

public sealed record IncidentLibraryEntry(
    string SessionId,
    int ReportSchemaVersion,
    string ToolVersion,
    DateTimeOffset StartUtc,
    DateTimeOffset EndUtc,
    IncidentKind Kind,
    string TargetName,
    IReadOnlyList<string> StopCodes,
    IReadOnlyList<string> FailureBuckets,
    IReadOnlyList<string> Modules,
    IReadOnlyList<string> WheaCategories,
    string IncidentFingerprint,
    string ReportPath,
    bool Imported,
    IReadOnlyList<LocalReportCopy>? LocalCopies = null);

public sealed record RecurringIncidentGroup(
    string Category,
    string Value,
    int Count,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    IReadOnlyList<string> SessionIds);

public sealed record IncidentLibrarySnapshot(
    DateTimeOffset BuiltUtc,
    IReadOnlyList<IncidentLibraryEntry> Incidents,
    IReadOnlyList<RecurringIncidentGroup> RecurringGroups,
    IReadOnlyList<CollectionStatus> Statuses);

public sealed record ReportImportResult(
    string SourcePath,
    string? ImportedPath,
    bool Imported,
    string Detail);

public sealed record ValidatedReportArchive(
    int ReportSchemaVersion,
    string SessionId,
    ReadOnlyMemory<byte> ReportJson,
    IReadOnlyList<string> Members);

/// <summary>
/// Builds history directly from report files. The index has no independent retention:
/// deleting an underlying report removes it on the next scan.
/// </summary>
public sealed class IncidentLibrary
{
    private const long MaximumReportJsonBytes = 64L * 1024 * 1024;
    private const long MaximumManifestJsonBytes = 4L * 1024 * 1024;
    private const long MaximumArchiveMemberBytes = 64L * 1024 * 1024;
    private const long MaximumTotalUncompressedBytes = 256L * 1024 * 1024;
    private const long MaximumImportBytes = 512L * 1024 * 1024;
    private const int MaximumArchiveEntries = 128;
    private static readonly HashSet<string> RequiredV2ArchiveMembers = new(StringComparer.OrdinalIgnoreCase)
    {
        "SUMMARY.txt",
        "Report.json",
        "Performance-Samples.csv",
        "Windows-Events.json",
        "Windows-Event-Groups.json",
        "Reliability.json",
        "Artifacts.json",
        "Collection-Status.json",
        "Manifest.json"
    };
    private static readonly HashSet<string> RequiredV3ArchiveMembers = new(StringComparer.OrdinalIgnoreCase)
    {
        "SUMMARY.txt",
        "Report.json",
        "Performance-Samples.csv",
        "Windows-Events.json",
        "Windows-Event-Groups.json",
        "Reliability.json",
        "Artifacts.json",
        "Collection-Status.json",
        "Source-Coverage.json",
        "Incident.json",
        "Bugchecks.json",
        "Crash-Readiness.json",
        "Dump-Inventory.json",
        "Driver-Inventory.json",
        "Manifest.json"
    };
    private static readonly HashSet<string> OptionalV3ArchiveMembers = new(StringComparer.OrdinalIgnoreCase)
    {
        "Debugger-Analysis.json",
        "Dump-Quality.json",
        "Recent-Changes.json",
        "Storage-Health.json",
        "Driver-Verifier.json"
    };
    private static readonly JsonDocumentOptions JsonOptions = new()
    {
        AllowTrailingCommas = false,
        CommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 96
    };
    private static readonly EnumerationOptions SessionEnumerationOptions = new()
    {
        RecurseSubdirectories = true,
        IgnoreInaccessible = true,
        AttributesToSkip = FileAttributes.ReparsePoint
    };

    private readonly string _dataRoot;

    public IncidentLibrary(string dataRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        if (!Path.IsPathFullyQualified(dataRoot))
        {
            throw new ArgumentException("The incident-library root must be an absolute path.", nameof(dataRoot));
        }

        _dataRoot = Path.GetFullPath(dataRoot);
    }

    public string ImportedReportsRoot => Path.Combine(_dataRoot, "Library", "ImportedReports");

    /// <summary>
    /// Opens a standard v2 or v3 report ZIP and verifies its root-only member set,
    /// manifest identity, member sizes, and member SHA-256 values before returning
    /// Report.json. Dump bytes and raw debugger logs are never accepted here.
    /// </summary>
    public static async Task<ValidatedReportArchive> ReadValidatedArchiveAsync(
        string reportPath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reportPath);
        string fullPath = Path.GetFullPath(reportPath);
        if (!Path.GetExtension(fullPath).Equals(".zip", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Select a PC Crash Diagnostic report ZIP.");
        }

        PathSafety.EnsureNoReparseComponents(fullPath);
        var info = new FileInfo(fullPath);
        if (!info.Exists || info.Length is <= 0 or > MaximumImportBytes)
        {
            throw new InvalidDataException("The report ZIP is missing, empty, or exceeds the 512 MiB validation limit.");
        }

        await using FileStream stream = new(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            useAsync: true);
        return await ValidateArchiveAsync(stream, cancellationToken).ConfigureAwait(false);
    }

    public async Task<IncidentLibrarySnapshot> BuildAsync(CancellationToken cancellationToken = default)
    {
        var incidents = new Dictionary<string, IncidentLibraryEntry>(StringComparer.OrdinalIgnoreCase);
        var statuses = new List<CollectionStatus>();

        string sessionsRoot = Path.Combine(_dataRoot, "Sessions");
        if (Directory.Exists(sessionsRoot))
        {
            foreach (string reportPath in Directory.EnumerateFiles(
                         sessionsRoot,
                         "Report.json",
                         SessionEnumerationOptions))
            {
                cancellationToken.ThrowIfCancellationRequested();
                await TryAddJsonReportAsync(reportPath, imported: false, incidents, statuses, cancellationToken).ConfigureAwait(false);
            }
        }

        foreach ((string root, bool imported) in new[]
                 {
                     (Path.Combine(_dataRoot, "Reports"), false),
                     (ImportedReportsRoot, true)
                 })
        {
            if (!Directory.Exists(root))
            {
                continue;
            }

            foreach (string reportPath in Directory.EnumerateFiles(root, "*.zip", SearchOption.TopDirectoryOnly))
            {
                cancellationToken.ThrowIfCancellationRequested();
                await TryAddArchiveReportAsync(reportPath, imported, incidents, statuses, cancellationToken).ConfigureAwait(false);
            }
        }

        IncidentLibraryEntry[] ordered = incidents.Values
            .OrderByDescending(item => item.StartUtc)
            .ThenBy(item => item.SessionId, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        RecurringIncidentGroup[] recurring = BuildGroups(ordered);
        statuses.Add(new CollectionStatus(
            "Local incident library",
            CollectionState.Available,
            $"Read {ordered.Length} report{(ordered.Length == 1 ? string.Empty : "s")}."));
        return new IncidentLibrarySnapshot(DateTimeOffset.UtcNow, ordered, recurring, statuses);
    }

    public async Task<IReadOnlyList<ReportImportResult>> ImportValidatedReportsAsync(
        IEnumerable<string> reportPaths,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(reportPaths);
        string importRoot = PathSafety.EnsureDirectory(_dataRoot, ImportedReportsRoot);
        var results = new List<ReportImportResult>();

        foreach (string suppliedPath in reportPaths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string sourcePath;
            try
            {
                sourcePath = Path.GetFullPath(suppliedPath);
                var info = new FileInfo(sourcePath);
                if (!info.Exists || !info.Extension.Equals(".zip", StringComparison.OrdinalIgnoreCase))
                {
                    results.Add(new ReportImportResult(suppliedPath, null, false, "Select a report ZIP created by version 2 or 3."));
                    continue;
                }

                if (info.Length is <= 0 or > MaximumImportBytes)
                {
                    results.Add(new ReportImportResult(sourcePath, null, false, "The report ZIP is empty or exceeds the 512 MiB import limit."));
                    continue;
                }

                PathSafety.EnsureNoReparseComponents(sourcePath);
                await using FileStream validationStream = new(
                    sourcePath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    128 * 1024,
                    useAsync: true);
                ValidatedReportArchive validated = await ValidateArchiveAsync(validationStream, cancellationToken).ConfigureAwait(false);
                validationStream.Position = 0;
                string hash = Convert.ToHexString(await SHA256.HashDataAsync(validationStream, cancellationToken).ConfigureAwait(false)).ToLowerInvariant();
                string destination = Path.Combine(importRoot, $"report-{validated.ReportSchemaVersion}-{hash[..16]}.zip");
                PathSafety.EnsureContained(importRoot, destination);
                if (!File.Exists(destination))
                {
                    string temporary = PathSafety.CreateRandomTemporaryPath(importRoot, importRoot, "report-import");
                    try
                    {
                        await using (FileStream output = new(
                                         temporary,
                                         FileMode.CreateNew,
                                         FileAccess.Write,
                                         FileShare.None,
                                         128 * 1024,
                                         useAsync: true))
                        {
                            validationStream.Position = 0;
                            await validationStream.CopyToAsync(output, 128 * 1024, cancellationToken).ConfigureAwait(false);
                            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                        }

                        PathSafety.EnsureSafeFileCommit(importRoot, temporary, destination);
                        File.Move(temporary, destination);
                    }
                    finally
                    {
                        PathSafety.TryDeleteFile(importRoot, temporary);
                    }
                }
                else
                {
                    PathSafety.EnsureSafeExistingFile(importRoot, destination);
                    await using FileStream existing = new(
                        destination,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.Read,
                        128 * 1024,
                        useAsync: true);
                    string existingHash = Convert.ToHexString(
                        await SHA256.HashDataAsync(existing, cancellationToken).ConfigureAwait(false)).ToLowerInvariant();
                    if (!string.Equals(existingHash, hash, StringComparison.Ordinal))
                    {
                        throw new InvalidDataException("An existing imported-report file did not match the validated source archive.");
                    }
                }

                results.Add(new ReportImportResult(sourcePath, destination, true, $"Imported schema-v{validated.ReportSchemaVersion} report {validated.SessionId}."));
            }
            catch (Exception exception) when (exception is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
            {
                results.Add(new ReportImportResult(suppliedPath, null, false, $"The report was not imported: {exception.Message}"));
            }
        }

        return results;
    }

    public static IReadOnlyList<string> FindLegacyV2Reports(string legacyDataRoot)
    {
        if (string.IsNullOrWhiteSpace(legacyDataRoot) || !Path.IsPathFullyQualified(legacyDataRoot))
        {
            return [];
        }

        string reportsRoot = Path.Combine(Path.GetFullPath(legacyDataRoot), "Reports");
        if (!Directory.Exists(reportsRoot))
        {
            return [];
        }

        return Directory.EnumerateFiles(reportsRoot, "BF6-Diagnostic-Report-*.zip", SearchOption.TopDirectoryOnly)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static async Task TryAddJsonReportAsync(
        string reportPath,
        bool imported,
        IDictionary<string, IncidentLibraryEntry> incidents,
        ICollection<CollectionStatus> statuses,
        CancellationToken cancellationToken)
    {
        try
        {
            PathSafety.EnsureNoReparseComponents(reportPath);
            var info = new FileInfo(reportPath);
            if (info.Length is <= 0 or > MaximumReportJsonBytes)
            {
                throw new InvalidDataException("Report.json is empty or too large.");
            }

            await using FileStream stream = new(reportPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 64 * 1024, useAsync: true);
            using JsonDocument document = await JsonDocument.ParseAsync(stream, JsonOptions, cancellationToken).ConfigureAwait(false);
            IncidentLibraryEntry entry = ParseReport(document.RootElement, reportPath, imported);
            MergeIncidentEntry(incidents, entry);
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
        {
            statuses.Add(new CollectionStatus("Incident report", CollectionState.Error, $"Skipped {Path.GetFileName(reportPath)}: {exception.Message}"));
        }
    }

    private static async Task TryAddArchiveReportAsync(
        string reportPath,
        bool imported,
        IDictionary<string, IncidentLibraryEntry> incidents,
        ICollection<CollectionStatus> statuses,
        CancellationToken cancellationToken)
    {
        try
        {
            PathSafety.EnsureNoReparseComponents(reportPath);
            await using FileStream stream = new(reportPath, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024, useAsync: true);
            ValidatedReportArchive validated = await ValidateArchiveAsync(stream, cancellationToken).ConfigureAwait(false);
            using JsonDocument report = JsonDocument.Parse(validated.ReportJson, JsonOptions);
            IncidentLibraryEntry entry = ParseReport(report.RootElement, reportPath, imported);
            MergeIncidentEntry(incidents, entry);
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or UnauthorizedAccessException or JsonException)
        {
            statuses.Add(new CollectionStatus("Incident report", CollectionState.Error, $"Skipped {Path.GetFileName(reportPath)}: {exception.Message}"));
        }
    }

    private static bool PreferArchiveEntry(IncidentLibraryEntry candidate, IncidentLibraryEntry existing)
    {
        bool candidateIsArchive = Path.GetExtension(candidate.ReportPath).Equals(".zip", StringComparison.OrdinalIgnoreCase);
        bool existingIsArchive = Path.GetExtension(existing.ReportPath).Equals(".zip", StringComparison.OrdinalIgnoreCase);
        if (candidateIsArchive != existingIsArchive)
        {
            return candidateIsArchive;
        }

        if (candidate.Imported != existing.Imported)
        {
            return !candidate.Imported;
        }

        return SafeLastWriteUtc(candidate.ReportPath) > SafeLastWriteUtc(existing.ReportPath);
    }

    private static void MergeIncidentEntry(
        IDictionary<string, IncidentLibraryEntry> incidents,
        IncidentLibraryEntry candidate)
    {
        if (!incidents.TryGetValue(candidate.SessionId, out IncidentLibraryEntry? existing))
        {
            incidents[candidate.SessionId] = candidate;
            return;
        }

        IncidentLibraryEntry preferred = PreferArchiveEntry(candidate, existing) ? candidate : existing;
        LocalReportCopy[] copies = (existing.LocalCopies ?? [])
            .Concat(candidate.LocalCopies ?? [])
            .DistinctBy(copy => Path.GetFullPath(copy.ReportPath), StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(copy => string.Equals(
                Path.GetFullPath(copy.ReportPath),
                Path.GetFullPath(preferred.ReportPath),
                StringComparison.OrdinalIgnoreCase))
            .ThenBy(copy => copy.Imported)
            .ThenBy(copy => copy.ReportPath, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        incidents[candidate.SessionId] = preferred with { LocalCopies = copies };
    }

    private static DateTime SafeLastWriteUtc(string path)
    {
        try
        {
            return File.GetLastWriteTimeUtc(path);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return DateTime.MinValue;
        }
    }

    private static async Task<ValidatedReportArchive> ValidateArchiveAsync(
        Stream stream,
        CancellationToken cancellationToken)
    {
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        if (archive.Entries.Count is 0 or > MaximumArchiveEntries)
        {
            throw new InvalidDataException("The report archive has an unexpected number of files.");
        }

        var entries = new Dictionary<string, ZipArchiveEntry>(StringComparer.OrdinalIgnoreCase);
        long totalUncompressedBytes = 0;
        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            string name = entry.FullName;
            if (!IsSafeRootMemberName(name))
            {
                throw new InvalidDataException("The report archive contains an unsafe path.");
            }

            if (!entries.TryAdd(name, entry))
            {
                throw new InvalidDataException("The report archive contains duplicate member names.");
            }

            if (entry.Length is < 0 or > MaximumArchiveMemberBytes)
            {
                throw new InvalidDataException($"The report member {name} exceeds its fixed size limit.");
            }

            try
            {
                totalUncompressedBytes = checked(totalUncompressedBytes + entry.Length);
            }
            catch (OverflowException)
            {
                throw new InvalidDataException("The report archive's declared size is invalid.");
            }

            if (totalUncompressedBytes > MaximumTotalUncompressedBytes)
            {
                throw new InvalidDataException("The report archive exceeds the total uncompressed-size limit.");
            }
        }

        if (!entries.TryGetValue("Report.json", out ZipArchiveEntry? reportEntry) ||
            reportEntry.Length is <= 0 or > MaximumReportJsonBytes)
        {
            throw new InvalidDataException("The archive does not contain one valid root Report.json member.");
        }

        if (!entries.TryGetValue("Manifest.json", out ZipArchiveEntry? manifestEntry) ||
            manifestEntry.Length is <= 0 or > MaximumManifestJsonBytes)
        {
            throw new InvalidDataException("The archive does not contain one valid root Manifest.json member.");
        }

        byte[] reportJson = await ReadEntryBytesAsync(
            reportEntry,
            MaximumReportJsonBytes,
            cancellationToken).ConfigureAwait(false);
        byte[] manifestJson = await ReadEntryBytesAsync(
            manifestEntry,
            MaximumManifestJsonBytes,
            cancellationToken).ConfigureAwait(false);
        using JsonDocument report = JsonDocument.Parse(reportJson, JsonOptions);
        JsonElement root = report.RootElement;
        int schemaVersion = ReadInt(root, "ReportSchemaVersion") ?? 0;
        string sessionId = ReadString(root, "SessionId") ?? string.Empty;
        if (schemaVersion is not (2 or 3) || !SessionIdValidator.IsValid(sessionId))
        {
            throw new InvalidDataException("Only validated schema-v2 or schema-v3 diagnostic reports can be imported.");
        }

        ValidateArchiveMemberSet(entries.Keys, schemaVersion);
        using JsonDocument manifest = JsonDocument.Parse(manifestJson, JsonOptions);
        IReadOnlyDictionary<string, ManifestMember> manifestMembers = ParseAndValidateManifest(
            manifest.RootElement,
            schemaVersion,
            sessionId);
        ZipArchiveEntry[] payloadEntries = entries.Values
            .Where(entry => !entry.FullName.Equals("Manifest.json", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (manifestMembers.Count != payloadEntries.Length)
        {
            throw new InvalidDataException("Manifest.json does not describe every standard report member exactly once.");
        }

        foreach (ZipArchiveEntry entry in payloadEntries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!manifestMembers.TryGetValue(entry.FullName, out ManifestMember? expected))
            {
                throw new InvalidDataException($"Manifest.json does not describe {entry.FullName}.");
            }

            if (expected.SizeBytes != entry.Length)
            {
                throw new InvalidDataException($"The recorded size for {entry.FullName} does not match the archive member.");
            }

            string actualHash = entry.FullName.Equals("Report.json", StringComparison.OrdinalIgnoreCase)
                ? Convert.ToHexString(SHA256.HashData(reportJson)).ToLowerInvariant()
                : await ComputeEntrySha256Async(entry, cancellationToken).ConfigureAwait(false);
            if (!string.Equals(actualHash, expected.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException($"The SHA-256 for {entry.FullName} does not match Manifest.json.");
            }
        }

        return new ValidatedReportArchive(
            schemaVersion,
            sessionId,
            reportJson,
            entries.Keys.Order(StringComparer.OrdinalIgnoreCase).ToArray());
    }

    private static bool IsSafeRootMemberName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) ||
            name.Length > 128 ||
            name.Contains('\\') ||
            name.Contains('/') ||
            name is "." or ".." ||
            Path.IsPathRooted(name) ||
            !string.Equals(name, Path.GetFileName(name), StringComparison.Ordinal))
        {
            return false;
        }

        return name.All(character =>
            !char.IsControl(character) && character is not (':' or '*' or '?' or '"' or '<' or '>' or '|'));
    }

    private static void ValidateArchiveMemberSet(IEnumerable<string> memberNames, int schemaVersion)
    {
        var actual = new HashSet<string>(memberNames, StringComparer.OrdinalIgnoreCase);
        HashSet<string> required = schemaVersion == 2 ? RequiredV2ArchiveMembers : RequiredV3ArchiveMembers;
        if (!required.IsSubsetOf(actual))
        {
            string missing = string.Join(", ", required.Except(actual, StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase));
            throw new InvalidDataException($"The schema-v{schemaVersion} report is missing required members: {missing}.");
        }

        IEnumerable<string> allowed = schemaVersion == 2
            ? required
            : required.Concat(OptionalV3ArchiveMembers);
        string[] unexpected = actual.Except(allowed, StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (unexpected.Length > 0)
        {
            throw new InvalidDataException(
                $"The standard report contains unexpected members: {string.Join(", ", unexpected)}. Dump bytes and raw debugger logs are not allowed.");
        }
    }

    private static IReadOnlyDictionary<string, ManifestMember> ParseAndValidateManifest(
        JsonElement root,
        int reportSchemaVersion,
        string reportSessionId)
    {
        int manifestSchemaVersion = ReadInt(root, "ReportSchemaVersion") ?? 0;
        string manifestSessionId = ReadString(root, "SessionId") ?? string.Empty;
        if (manifestSchemaVersion != reportSchemaVersion ||
            !string.Equals(manifestSessionId, reportSessionId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Manifest.json does not match Report.json schema and session identity.");
        }

        if (!TryGetProperty(root, "Files", out JsonElement files) || files.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidDataException("Manifest.json does not contain its report-member list.");
        }

        var members = new Dictionary<string, ManifestMember>(StringComparer.OrdinalIgnoreCase);
        foreach (JsonElement item in files.EnumerateArray())
        {
            string name = ReadString(item, "Name") ?? string.Empty;
            long sizeBytes = ReadLong(item, "SizeBytes") ?? -1;
            string sha256 = ReadString(item, "Sha256") ?? string.Empty;
            if (!IsSafeRootMemberName(name) ||
                name.Equals("Manifest.json", StringComparison.OrdinalIgnoreCase) ||
                sizeBytes is < 0 or > MaximumArchiveMemberBytes ||
                sha256.Length != 64 ||
                sha256.Any(character => !Uri.IsHexDigit(character)))
            {
                throw new InvalidDataException("Manifest.json contains an invalid report-member identity.");
            }

            if (!members.TryAdd(name, new ManifestMember(sizeBytes, sha256.ToLowerInvariant())))
            {
                throw new InvalidDataException("Manifest.json contains duplicate report-member names.");
            }
        }

        return members;
    }

    private static async Task<byte[]> ReadEntryBytesAsync(
        ZipArchiveEntry entry,
        long maximumBytes,
        CancellationToken cancellationToken)
    {
        if (entry.Length < 0 || entry.Length > maximumBytes || entry.Length > int.MaxValue)
        {
            throw new InvalidDataException($"The report member {entry.FullName} exceeds its fixed size limit.");
        }

        await using Stream input = entry.Open();
        using var output = new MemoryStream(checked((int)entry.Length));
        byte[] buffer = new byte[64 * 1024];
        long totalRead = 0;
        while (true)
        {
            int read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            totalRead += read;
            if (totalRead > maximumBytes || totalRead > entry.Length)
            {
                throw new InvalidDataException($"The decompressed report member {entry.FullName} exceeded its declared size.");
            }

            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        if (totalRead != entry.Length)
        {
            throw new InvalidDataException($"The decompressed report member {entry.FullName} did not match its declared size.");
        }

        return output.ToArray();
    }

    private static async Task<string> ComputeEntrySha256Async(
        ZipArchiveEntry entry,
        CancellationToken cancellationToken)
    {
        await using Stream input = entry.Open();
        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        byte[] buffer = new byte[64 * 1024];
        long totalRead = 0;
        while (true)
        {
            int read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            totalRead += read;
            if (totalRead > entry.Length || totalRead > MaximumArchiveMemberBytes)
            {
                throw new InvalidDataException($"The decompressed report member {entry.FullName} exceeded its declared size.");
            }

            hash.AppendData(buffer.AsSpan(0, read));
        }

        if (totalRead != entry.Length)
        {
            throw new InvalidDataException($"The decompressed report member {entry.FullName} did not match its declared size.");
        }

        return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
    }

    private static IncidentLibraryEntry ParseReport(JsonElement root, string reportPath, bool imported)
    {
        int schema = ReadInt(root, "ReportSchemaVersion") ?? throw new InvalidDataException("Report schema is missing.");
        if (schema is not (2 or 3))
        {
            throw new InvalidDataException($"Report schema {schema} is not supported.");
        }

        string sessionId = ReadString(root, "SessionId") ?? throw new InvalidDataException("Session ID is missing.");
        if (!SessionIdValidator.IsValid(sessionId))
        {
            throw new InvalidDataException("Session ID is invalid.");
        }

        string toolVersion = ReadString(root, "ToolVersion") ?? "Unknown";
        DateTimeOffset startUtc = ReadDate(root, "StartUtc") ?? DateTimeOffset.MinValue;
        DateTimeOffset endUtc = ReadDate(root, "EndUtc") ?? startUtc;
        IncidentKind kind = ReadIncidentKind(root);
        string targetName = schema == 2 ? "Battlefield 6" : ReadNestedString(root, "TargetProfile", "DisplayName") ?? "PC";
        string[] stopCodes = ReadStopCodes(root, schema);
        string[] failureBuckets = ReadDebuggerValues(root, "FailureBucket");
        string[] modules = ReadDebuggerValues(root, "ModuleName", "ImageName");
        string[] wheaCategories = ReadWheaCategories(root);
        string fingerprint = ReadNestedString(root, "IncidentFingerprint", "Value")
            ?? CreateLibraryFingerprint(kind, targetName, stopCodes, failureBuckets, modules, wheaCategories);

        LocalReportCopy[] localCopies = Path.GetExtension(reportPath).Equals(".zip", StringComparison.OrdinalIgnoreCase)
            ? [new LocalReportCopy(Path.GetFullPath(reportPath), imported)]
            : [];
        return new IncidentLibraryEntry(
            sessionId,
            schema,
            toolVersion,
            startUtc,
            endUtc,
            kind,
            targetName,
            stopCodes,
            failureBuckets,
            modules,
            wheaCategories,
            fingerprint,
            reportPath,
            imported,
            localCopies);
    }

    private static IncidentKind ReadIncidentKind(JsonElement root)
    {
        if (TryGetProperty(root, "IncidentSelection", out JsonElement selection) &&
            TryGetProperty(selection, "Candidate", out JsonElement candidate) &&
            TryGetProperty(candidate, "Kind", out JsonElement kind))
        {
            if (kind.ValueKind == JsonValueKind.Number && kind.TryGetInt32(out int numeric) && Enum.IsDefined((IncidentKind)numeric))
            {
                return (IncidentKind)numeric;
            }

            if (kind.ValueKind == JsonValueKind.String && Enum.TryParse(kind.GetString(), true, out IncidentKind parsed))
            {
                return parsed;
            }
        }

        string? completion = ReadString(root, "CompletionReason");
        if (TryGetProperty(root, "Anchor", out JsonElement anchor) && anchor.ValueKind == JsonValueKind.Object)
        {
            if (!string.IsNullOrWhiteSpace(ReadString(anchor, "BugCheckCode")))
            {
                return IncidentKind.Bugcheck;
            }

            int eventId = ReadInt(anchor, "EventId") ?? 0;
            return eventId switch
            {
                41 or 6008 => IncidentKind.UnexpectedRestart,
                1000 => IncidentKind.ApplicationCrash,
                1002 => IncidentKind.ApplicationHang,
                4101 => IncidentKind.GpuTimeout,
                _ => IncidentKind.Unknown
            };
        }

        return completion?.Contains("exit", StringComparison.OrdinalIgnoreCase) == true
            ? IncidentKind.Unknown
            : IncidentKind.Unknown;
    }

    private static string[] ReadStopCodes(JsonElement root, int schema)
    {
        var codes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (schema == 3 && TryGetProperty(root, "Bugchecks", out JsonElement bugchecks) && bugchecks.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement bugcheck in bugchecks.EnumerateArray())
            {
                AddNonEmpty(codes, ReadString(bugcheck, "NormalizedCode"));
            }
        }

        if (TryGetProperty(root, "Anchor", out JsonElement anchor) && anchor.ValueKind == JsonValueKind.Object)
        {
            AddNonEmpty(codes, ReadString(anchor, "BugCheckCode"));
        }

        return codes.Order(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static string[] ReadDebuggerValues(JsonElement root, params string[] properties)
    {
        var values = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (TryGetProperty(root, "DebuggerAnalysis", out JsonElement analysis) && analysis.ValueKind == JsonValueKind.Object)
        {
            foreach (string property in properties)
            {
                AddNonEmpty(values, ReadString(analysis, property));
            }
        }

        return values.Order(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static string[] ReadWheaCategories(JsonElement root)
    {
        var categories = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!TryGetProperty(root, "Events", out JsonElement events) || events.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        foreach (JsonElement diagnosticEvent in events.EnumerateArray())
        {
            string? provider = ReadString(diagnosticEvent, "ProviderName");
            int eventId = ReadInt(diagnosticEvent, "EventId") ?? -1;
            if (!string.Equals(provider, WheaEventCatalog.ProviderName, StringComparison.OrdinalIgnoreCase) ||
                !WheaEventCatalog.IsKnown(eventId))
            {
                continue;
            }

            string material = string.Empty;
            if (TryGetProperty(diagnosticEvent, "Data", out JsonElement data) && data.ValueKind == JsonValueKind.Object)
            {
                if (TryGetProperty(data, "CperSectionCategories", out JsonElement cperCategories) &&
                    cperCategories.ValueKind == JsonValueKind.String &&
                    AddCperCategories(categories, cperCategories.GetString()))
                {
                    continue;
                }

                material = string.Join(' ', data.EnumerateObject()
                    .Where(property => property.Name.Contains("Error", StringComparison.OrdinalIgnoreCase) ||
                                       property.Name.Contains("Section", StringComparison.OrdinalIgnoreCase) ||
                                       property.Name.Contains("Type", StringComparison.OrdinalIgnoreCase))
                    .Select(property => property.Value.ValueKind == JsonValueKind.String ? property.Value.GetString() : null)
                    .Where(value => !string.IsNullOrWhiteSpace(value)));
            }

            categories.Add(ClassifyWhea(material));
        }

        return categories.Order(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static bool AddCperCategories(ISet<string> destination, string? value)
    {
        bool added = false;
        foreach (string category in (value ?? string.Empty).Split(
                     ',',
                     StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string? normalized = category.ToUpperInvariant() switch
            {
                "PROCESSOR" => "Processor hardware record",
                "MEMORY" => "Memory hardware record",
                "PCIE" => "PCIe hardware record",
                "GENERIC HARDWARE" => "Generic hardware record",
                _ => null
            };
            if (normalized is not null)
            {
                destination.Add(normalized);
                added = true;
            }
        }

        return added;
    }

    private static string ClassifyWhea(string material)
    {
        if (material.Contains("memory", StringComparison.OrdinalIgnoreCase))
        {
            return "Memory hardware record";
        }

        if (material.Contains("pci", StringComparison.OrdinalIgnoreCase))
        {
            return "PCIe hardware record";
        }

        if (material.Contains("processor", StringComparison.OrdinalIgnoreCase) ||
            material.Contains("machine check", StringComparison.OrdinalIgnoreCase) ||
            material.Contains("cache", StringComparison.OrdinalIgnoreCase) ||
            material.Contains("tlb", StringComparison.OrdinalIgnoreCase))
        {
            return "Processor hardware record";
        }

        return "Generic hardware record";
    }

    private static RecurringIncidentGroup[] BuildGroups(IReadOnlyList<IncidentLibraryEntry> incidents)
    {
        var keyed = new List<(string Category, string Value, IncidentLibraryEntry Incident)>();
        foreach (IncidentLibraryEntry incident in incidents)
        {
            keyed.AddRange(incident.StopCodes.Select(value => ("Stop code", value, incident)));
            keyed.AddRange(incident.FailureBuckets.Select(value => ("WinDbg failure bucket", value, incident)));
            keyed.AddRange(incident.Modules.Select(value => ("WinDbg named module", value, incident)));
            keyed.AddRange(incident.WheaCategories.Select(value => ("WHEA category", value, incident)));
            if (!string.IsNullOrWhiteSpace(incident.TargetName))
            {
                keyed.Add(("Selected target", incident.TargetName, incident));
            }
        }

        return keyed
            .GroupBy(item => new GroupKey(item.Category, item.Value), GroupKeyComparer.Instance)
            .Select(group => new RecurringIncidentGroup(
                group.Key.Category,
                group.Key.Value,
                group.Select(item => item.Incident.SessionId).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                group.Min(item => item.Incident.StartUtc),
                group.Max(item => item.Incident.EndUtc),
                group.Select(item => item.Incident.SessionId).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToArray()))
            .Where(group => group.Count > 1)
            .OrderByDescending(group => group.Count)
            .ThenBy(group => group.Category, StringComparer.OrdinalIgnoreCase)
            .ThenBy(group => group.Value, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string CreateLibraryFingerprint(
        IncidentKind kind,
        string target,
        IReadOnlyList<string> stopCodes,
        IReadOnlyList<string> buckets,
        IReadOnlyList<string> modules,
        IReadOnlyList<string> whea)
    {
        string material = string.Join('|',
            kind,
            target.Trim().ToUpperInvariant(),
            string.Join(',', stopCodes).ToUpperInvariant(),
            string.Join(',', buckets).ToUpperInvariant(),
            string.Join(',', modules).ToUpperInvariant(),
            string.Join(',', whea).ToUpperInvariant());
        return Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(material))).ToLowerInvariant();
    }

    private static void AddNonEmpty(ISet<string> values, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            values.Add(value.Trim());
        }
    }

    private static string? ReadNestedString(JsonElement element, string objectName, string propertyName) =>
        TryGetProperty(element, objectName, out JsonElement nested) && nested.ValueKind == JsonValueKind.Object
            ? ReadString(nested, propertyName)
            : null;

    private static string? ReadString(JsonElement element, string name) =>
        TryGetProperty(element, name, out JsonElement value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static int? ReadInt(JsonElement element, string name) =>
        TryGetProperty(element, name, out JsonElement value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int number)
            ? number
            : null;

    private static long? ReadLong(JsonElement element, string name) =>
        TryGetProperty(element, name, out JsonElement value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out long number)
            ? number
            : null;

    private static DateTimeOffset? ReadDate(JsonElement element, string name) =>
        TryGetProperty(element, name, out JsonElement value) && value.ValueKind == JsonValueKind.String &&
        DateTimeOffset.TryParse(value.GetString(), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind, out DateTimeOffset date)
            ? date
            : null;

    private static bool TryGetProperty(JsonElement element, string name, out JsonElement value)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            foreach (JsonProperty property in element.EnumerateObject())
            {
                if (property.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    value = property.Value;
                    return true;
                }
            }
        }

        value = default;
        return false;
    }

    private sealed record ManifestMember(long SizeBytes, string Sha256);

    private sealed record GroupKey(string Category, string Value);

    private sealed class GroupKeyComparer : IEqualityComparer<GroupKey>
    {
        public static GroupKeyComparer Instance { get; } = new();

        public bool Equals(GroupKey? x, GroupKey? y) =>
            x is not null && y is not null &&
            string.Equals(x.Category, y.Category, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(x.Value, y.Value, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode(GroupKey key) => HashCode.Combine(
            StringComparer.OrdinalIgnoreCase.GetHashCode(key.Category),
            StringComparer.OrdinalIgnoreCase.GetHashCode(key.Value));
    }
}
