using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Reporting;

public sealed class ReportWriter
{
    private static readonly UTF8Encoding Utf8NoBom = new(false);
    private static readonly string[] ReportPayloadFileNames =
    [
        "SUMMARY.txt",
        "Report.json",
        "Performance-Samples.csv",
        "Windows-Events.json",
        "Windows-Event-Groups.json",
        "Reliability.json",
        "Artifacts.json",
        "Collection-Status.json"
    ];
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };

    private readonly string _dataRoot;

    public ReportWriter(string dataRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        _dataRoot = Path.GetFullPath(dataRoot);
    }

    public string SessionsRoot => Path.Combine(_dataRoot, "Sessions");

    public string ReportsRoot => Path.Combine(_dataRoot, "Reports");

    public async Task<ReportPackage> WriteAsync(DiagnosticReport report, CancellationToken cancellationToken = default)
    {
        PathSafety.EnsureDirectory(_dataRoot, _dataRoot);
        string sessionsRoot = PathSafety.EnsureDirectory(_dataRoot, SessionsRoot);
        string reportsRoot = PathSafety.EnsureDirectory(_dataRoot, ReportsRoot);

        string sessionFolder = PathSafety.EnsureDirectory(
            sessionsRoot,
            Path.Combine(sessionsRoot, ValidateSessionId(report.SessionId)));

        await WriteTextAsync(sessionFolder, Path.Combine(sessionFolder, "SUMMARY.txt"), report.Summary, cancellationToken).ConfigureAwait(false);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Report.json"), report, cancellationToken).ConfigureAwait(false);
        await WriteSamplesAsync(sessionFolder, Path.Combine(sessionFolder, "Performance-Samples.csv"), report.Samples, cancellationToken).ConfigureAwait(false);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Windows-Events.json"), report.Events, cancellationToken).ConfigureAwait(false);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Windows-Event-Groups.json"), report.EventGroups, cancellationToken).ConfigureAwait(false);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Reliability.json"), report.Reliability, cancellationToken).ConfigureAwait(false);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Artifacts.json"), report.Artifacts, cancellationToken).ConfigureAwait(false);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Collection-Status.json"), report.CollectionStatus, cancellationToken).ConfigureAwait(false);

        IReadOnlyList<ManifestEntry> entries = await CreateManifestEntriesAsync(sessionFolder, cancellationToken).ConfigureAwait(false);
        var manifest = new ReportManifest(2, report.SessionId, DateTimeOffset.UtcNow, entries);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Manifest.json"), manifest, cancellationToken).ConfigureAwait(false);

        string baseName = $"BF6-Diagnostic-Report-{report.StartUtc:yyyyMMdd-HHmmss}-{ShortId(report.SessionId)}";
        (string finalZip, string shaPath) = GetAvailablePackagePaths(reportsRoot, baseName);
        string partialZip = PathSafety.CreateRandomTemporaryPath(reportsRoot, reportsRoot, "report-archive");
        string partialSha = PathSafety.CreateRandomTemporaryPath(reportsRoot, reportsRoot, "report-checksum");
        bool checksumPublished = false;
        bool packagePublished = false;

        try
        {
            await CreateReportArchiveAsync(sessionFolder, partialZip, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();

            PathSafety.EnsureSafeExistingFile(reportsRoot, partialZip);
            string sha256 = await ComputeSha256Async(partialZip, cancellationToken).ConfigureAwait(false);
            await using (FileStream checksumStream = new(
                             partialSha,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             4096,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                byte[] checksumBytes = Utf8NoBom.GetBytes(
                    $"{sha256} *{Path.GetFileName(finalZip)}{Environment.NewLine}");
                await checksumStream.WriteAsync(checksumBytes, cancellationToken).ConfigureAwait(false);
                await checksumStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            cancellationToken.ThrowIfCancellationRequested();

            // The two renames are the deliberately non-cancellable commit: checksum first,
            // archive last. A final-looking ZIP can therefore never lack its checksum.
            PathSafety.EnsureSafeFileCommit(reportsRoot, partialSha, shaPath);
            File.Move(partialSha, shaPath);
            checksumPublished = true;
            PathSafety.EnsureSafeFileCommit(reportsRoot, partialZip, finalZip);
            File.Move(partialZip, finalZip);
            packagePublished = true;
            return new ReportPackage(report, sessionFolder, finalZip, shaPath, sha256);
        }
        finally
        {
            PathSafety.TryDeleteFile(reportsRoot, partialZip);
            PathSafety.TryDeleteFile(reportsRoot, partialSha);

            if (!packagePublished && checksumPublished)
            {
                PathSafety.TryDeleteFile(reportsRoot, shaPath);
            }
        }
    }

    public async Task<ReportPackageV3> WriteV3Async(
        DiagnosticReportV3 report,
        CancellationToken cancellationToken = default)
    {
        if (report.ReportSchemaVersion != 3)
        {
            throw new ArgumentException("The v3 writer accepts only report schema version 3.", nameof(report));
        }

        PathSafety.EnsureDirectory(_dataRoot, _dataRoot);
        string sessionsRoot = PathSafety.EnsureDirectory(_dataRoot, SessionsRoot);
        string reportsRoot = PathSafety.EnsureDirectory(_dataRoot, ReportsRoot);
        string sessionFolder = PathSafety.EnsureDirectory(
            sessionsRoot,
            Path.Combine(sessionsRoot, ValidateSessionId(report.SessionId)));

        await WriteTextAsync(sessionFolder, Path.Combine(sessionFolder, "SUMMARY.txt"), report.Summary, cancellationToken).ConfigureAwait(false);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Report.json"), report, cancellationToken).ConfigureAwait(false);
        await WriteTargetSamplesAsync(sessionFolder, Path.Combine(sessionFolder, "Performance-Samples.csv"), report.Samples, cancellationToken).ConfigureAwait(false);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Windows-Events.json"), report.Events, cancellationToken).ConfigureAwait(false);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Windows-Event-Groups.json"), report.EventGroups, cancellationToken).ConfigureAwait(false);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Reliability.json"), report.Reliability, cancellationToken).ConfigureAwait(false);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Artifacts.json"), report.Artifacts, cancellationToken).ConfigureAwait(false);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Collection-Status.json"), report.CollectionStatus, cancellationToken).ConfigureAwait(false);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Source-Coverage.json"), report.SourceCoverage, cancellationToken).ConfigureAwait(false);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Incident.json"), new
        {
            report.IncidentSelection,
            report.TargetProfile,
            report.IncidentFingerprint,
            report.CrashCorrelation,
            report.BootSession,
            report.WheaEvidence
        }, cancellationToken).ConfigureAwait(false);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Bugchecks.json"), report.Bugchecks, cancellationToken).ConfigureAwait(false);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Crash-Readiness.json"), report.CrashReadiness, cancellationToken).ConfigureAwait(false);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Dump-Inventory.json"), report.DumpInventory, cancellationToken).ConfigureAwait(false);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Driver-Inventory.json"), report.DriverInventory, cancellationToken).ConfigureAwait(false);

        var payloadNames = new List<string>
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
            "Driver-Inventory.json"
        };

        if (report.DebuggerAnalysis is not null)
        {
            DebuggerAnalysis exportAnalysis = report.DebuggerAnalysis with { LocalRawLogPath = null };
            await WriteJsonAsync(
                sessionFolder,
                Path.Combine(sessionFolder, "Debugger-Analysis.json"),
                exportAnalysis,
                cancellationToken).ConfigureAwait(false);
            payloadNames.Add("Debugger-Analysis.json");
        }

        if (report.DumpQuality is not null)
        {
            await WriteJsonAsync(
                sessionFolder,
                Path.Combine(sessionFolder, "Dump-Quality.json"),
                report.DumpQuality,
                cancellationToken).ConfigureAwait(false);
            payloadNames.Add("Dump-Quality.json");
        }

        if (report.RecentChanges is not null)
        {
            await WriteJsonAsync(
                sessionFolder,
                Path.Combine(sessionFolder, "Recent-Changes.json"),
                report.RecentChanges,
                cancellationToken).ConfigureAwait(false);
            payloadNames.Add("Recent-Changes.json");
        }

        if (report.StorageHealth is not null)
        {
            await WriteJsonAsync(
                sessionFolder,
                Path.Combine(sessionFolder, "Storage-Health.json"),
                report.StorageHealth,
                cancellationToken).ConfigureAwait(false);
            payloadNames.Add("Storage-Health.json");
        }

        if (report.DriverVerifier is not null)
        {
            await WriteJsonAsync(
                sessionFolder,
                Path.Combine(sessionFolder, "Driver-Verifier.json"),
                report.DriverVerifier,
                cancellationToken).ConfigureAwait(false);
            payloadNames.Add("Driver-Verifier.json");
        }

        IReadOnlyList<ManifestEntry> entries = await CreateManifestEntriesAsync(
            sessionFolder,
            payloadNames,
            cancellationToken).ConfigureAwait(false);
        var manifest = new ReportManifest(3, report.SessionId, DateTimeOffset.UtcNow, entries);
        await WriteJsonAsync(sessionFolder, Path.Combine(sessionFolder, "Manifest.json"), manifest, cancellationToken).ConfigureAwait(false);

        string baseName = $"PCCrashDiagnostic-Report-{report.StartUtc:yyyyMMdd-HHmmss}-{ShortId(report.SessionId)}";
        (string finalZip, string shaPath) = GetAvailablePackagePaths(reportsRoot, baseName);
        string partialZip = PathSafety.CreateRandomTemporaryPath(reportsRoot, reportsRoot, "report-archive");
        string partialSha = PathSafety.CreateRandomTemporaryPath(reportsRoot, reportsRoot, "report-checksum");
        bool checksumPublished = false;
        bool packagePublished = false;

        try
        {
            await CreateReportArchiveAsync(sessionFolder, partialZip, payloadNames, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();

            PathSafety.EnsureSafeExistingFile(reportsRoot, partialZip);
            string sha256 = await ComputeSha256Async(partialZip, cancellationToken).ConfigureAwait(false);
            await using (FileStream checksumStream = new(
                             partialSha,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             4096,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                byte[] checksumBytes = Utf8NoBom.GetBytes(
                    $"{sha256} *{Path.GetFileName(finalZip)}{Environment.NewLine}");
                await checksumStream.WriteAsync(checksumBytes, cancellationToken).ConfigureAwait(false);
                await checksumStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            cancellationToken.ThrowIfCancellationRequested();
            PathSafety.EnsureSafeFileCommit(reportsRoot, partialSha, shaPath);
            File.Move(partialSha, shaPath);
            checksumPublished = true;
            PathSafety.EnsureSafeFileCommit(reportsRoot, partialZip, finalZip);
            File.Move(partialZip, finalZip);
            packagePublished = true;
            return new ReportPackageV3(report, sessionFolder, finalZip, shaPath, sha256);
        }
        finally
        {
            PathSafety.TryDeleteFile(reportsRoot, partialZip);
            PathSafety.TryDeleteFile(reportsRoot, partialSha);
            if (!packagePublished && checksumPublished)
            {
                PathSafety.TryDeleteFile(reportsRoot, shaPath);
            }
        }
    }

    private static async Task WriteTargetSamplesAsync(
        string trustedRoot,
        string path,
        IReadOnlyList<TargetPerformanceSample> samples,
        CancellationToken cancellationToken)
    {
        string[] headers =
        [
            "TimestampUtc", "TargetRunning", "TargetProcessCount", "SystemCpuPct",
            "SystemMemoryUsedGB", "SystemMemoryAvailableGB", "SystemCommittedGB", "SystemCommitLimitGB",
            "SystemCommitPct", "TargetWorkingSetMB", "TargetPrivateMB", "TargetCpuPct", "TargetGpu3DPct",
            "TargetGpuMaxEnginePct", "TargetDedicatedGpuMB", "TargetSharedGpuMB", "SampleCollectionMs"
        ];

        await WriteAtomicallyAsync(trustedRoot, path, async (stream, token) =>
        {
            await using var writer = new StreamWriter(stream, Utf8NoBom, 64 * 1024, leaveOpen: true);
            await writer.WriteLineAsync(string.Join(',', headers)).ConfigureAwait(false);
            foreach (TargetPerformanceSample sample in samples)
            {
                token.ThrowIfCancellationRequested();
                string[] row =
                [
                    sample.TimestampUtc.ToString("O", CultureInfo.InvariantCulture),
                    sample.TargetRunning.ToString(CultureInfo.InvariantCulture),
                    FormatValue(sample.TargetProcessCount),
                    FormatValue(sample.SystemCpuPct),
                    FormatValue(sample.SystemMemoryUsedGB),
                    FormatValue(sample.SystemMemoryAvailableGB),
                    FormatValue(sample.SystemCommittedGB),
                    FormatValue(sample.SystemCommitLimitGB),
                    FormatValue(sample.SystemCommitPct),
                    FormatValue(sample.TargetWorkingSetMB),
                    FormatValue(sample.TargetPrivateMB),
                    FormatValue(sample.TargetCpuPct),
                    FormatValue(sample.TargetGpu3DPct),
                    FormatValue(sample.TargetGpuMaxEnginePct),
                    FormatValue(sample.TargetDedicatedGpuMB),
                    FormatValue(sample.TargetSharedGpuMB),
                    FormatValue(sample.SampleCollectionMs)
                ];
                await writer.WriteLineAsync(string.Join(',', row.Select(EscapeCsv))).ConfigureAwait(false);
            }

            await writer.FlushAsync(token).ConfigureAwait(false);
        }, cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteSamplesAsync(
        string trustedRoot,
        string path,
        IReadOnlyList<PerformanceSample> samples,
        CancellationToken cancellationToken)
    {
        string[] headers =
        [
            "TimestampUtc", "BF6Running", "BF6Pid", "BF6ProcessName", "SystemCpuPct",
            "SystemMemoryUsedGB", "SystemMemoryAvailableGB", "SystemCommittedGB", "SystemCommitLimitGB",
            "SystemCommitPct", "BF6WorkingSetMB", "BF6PrivateMB", "BF6CpuPct", "BF6Gpu3DPct",
            "BF6GpuMaxEnginePct", "BF6DedicatedGpuMB", "BF6SharedGpuMB", "SampleCollectionMs"
        ];

        await WriteAtomicallyAsync(trustedRoot, path, async (stream, token) =>
        {
            await using var writer = new StreamWriter(stream, Utf8NoBom, 64 * 1024, leaveOpen: true);
            await writer.WriteLineAsync(string.Join(',', headers)).ConfigureAwait(false);
            foreach (PerformanceSample sample in samples)
            {
                token.ThrowIfCancellationRequested();
                string[] row =
                [
                    sample.TimestampUtc.ToString("O", CultureInfo.InvariantCulture),
                    sample.BF6Running.ToString(CultureInfo.InvariantCulture),
                    FormatValue(sample.BF6Pid),
                    sample.BF6ProcessName,
                    FormatValue(sample.SystemCpuPct),
                    FormatValue(sample.SystemMemoryUsedGB),
                    FormatValue(sample.SystemMemoryAvailableGB),
                    FormatValue(sample.SystemCommittedGB),
                    FormatValue(sample.SystemCommitLimitGB),
                    FormatValue(sample.SystemCommitPct),
                    FormatValue(sample.BF6WorkingSetMB),
                    FormatValue(sample.BF6PrivateMB),
                    FormatValue(sample.BF6CpuPct),
                    FormatValue(sample.BF6Gpu3DPct),
                    FormatValue(sample.BF6GpuMaxEnginePct),
                    FormatValue(sample.BF6DedicatedGpuMB),
                    FormatValue(sample.BF6SharedGpuMB),
                    FormatValue(sample.SampleCollectionMs)
                ];
                await writer.WriteLineAsync(string.Join(',', row.Select(EscapeCsv))).ConfigureAwait(false);
            }

            await writer.FlushAsync(token).ConfigureAwait(false);
        }, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<IReadOnlyList<ManifestEntry>> CreateManifestEntriesAsync(string folder, CancellationToken cancellationToken)
    {
        var entries = new List<ManifestEntry>();
        foreach (string name in ReportPayloadFileNames.Order(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            string file = Path.Combine(folder, name);
            PathSafety.EnsureSafeExistingFile(folder, file);
            if (!File.Exists(file))
            {
                throw new InvalidDataException($"Required report member is missing: {name}");
            }

            var info = new FileInfo(file);
            entries.Add(new ManifestEntry(info.Name, info.Length, await ComputeSha256Async(file, cancellationToken).ConfigureAwait(false)));
        }

        return entries;
    }

    private static async Task<IReadOnlyList<ManifestEntry>> CreateManifestEntriesAsync(
        string folder,
        IReadOnlyList<string> payloadFileNames,
        CancellationToken cancellationToken)
    {
        var entries = new List<ManifestEntry>();
        foreach (string name in payloadFileNames.Order(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            string file = Path.Combine(folder, name);
            PathSafety.EnsureSafeExistingFile(folder, file);
            var info = new FileInfo(file);
            entries.Add(new ManifestEntry(
                info.Name,
                info.Length,
                await ComputeSha256Async(file, cancellationToken).ConfigureAwait(false)));
        }

        return entries;
    }

    private static async Task CreateReportArchiveAsync(
        string sessionFolder,
        string archivePath,
        CancellationToken cancellationToken)
    {
        string reportsRoot = Path.GetDirectoryName(archivePath)
            ?? throw new InvalidDataException("The report archive path has no parent folder.");
        PathSafety.EnsureNoReparseComponents(reportsRoot, archivePath);
        await using FileStream output = new(
            archivePath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            128 * 1024,
            useAsync: true);
        using var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true);
        foreach (string name in ReportPayloadFileNames
                     .Append("Manifest.json")
                     .Order(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            string file = Path.Combine(sessionFolder, name);
            PathSafety.EnsureSafeExistingFile(sessionFolder, file);
            if (!File.Exists(file))
            {
                throw new InvalidDataException($"Required report member is missing: {name}");
            }

            ZipArchiveEntry entry = archive.CreateEntry(name, CompressionLevel.Optimal);
            await using FileStream input = new(
                file,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                useAsync: true);
            await using Stream entryStream = entry.Open();
            await input.CopyToAsync(entryStream, 128 * 1024, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task CreateReportArchiveAsync(
        string sessionFolder,
        string archivePath,
        IReadOnlyList<string> payloadFileNames,
        CancellationToken cancellationToken)
    {
        string reportsRoot = Path.GetDirectoryName(archivePath)
            ?? throw new InvalidDataException("The report archive path has no parent folder.");
        PathSafety.EnsureNoReparseComponents(reportsRoot, archivePath);
        await using FileStream output = new(
            archivePath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            128 * 1024,
            useAsync: true);
        using var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true);
        foreach (string name in payloadFileNames
                     .Append("Manifest.json")
                     .Order(StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();
            string file = Path.Combine(sessionFolder, name);
            PathSafety.EnsureSafeExistingFile(sessionFolder, file);
            ZipArchiveEntry entry = archive.CreateEntry(name, CompressionLevel.Optimal);
            await using FileStream input = new(
                file,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                useAsync: true);
            await using Stream entryStream = entry.Open();
            await input.CopyToAsync(entryStream, 128 * 1024, cancellationToken).ConfigureAwait(false);
        }
    }

    private static Task WriteJsonAsync<T>(
        string trustedRoot,
        string path,
        T value,
        CancellationToken cancellationToken)
    {
        return WriteAtomicallyAsync(
            trustedRoot,
            path,
            (stream, token) => JsonSerializer.SerializeAsync(stream, value, JsonOptions, token),
            cancellationToken);
    }

    private static Task WriteTextAsync(
        string trustedRoot,
        string path,
        string text,
        CancellationToken cancellationToken)
    {
        byte[] bytes = Utf8NoBom.GetBytes(text);
        return WriteAtomicallyAsync(
            trustedRoot,
            path,
            (stream, token) => stream.WriteAsync(bytes, token).AsTask(),
            cancellationToken);
    }

    private static async Task WriteAtomicallyAsync(
        string trustedRoot,
        string path,
        Func<Stream, CancellationToken, Task> writeAsync,
        CancellationToken cancellationToken)
    {
        string fullPath = PathSafety.EnsureContained(trustedRoot, path);
        string directory = Path.GetDirectoryName(fullPath)
            ?? throw new InvalidDataException("The report member path has no parent folder.");
        PathSafety.EnsureDirectory(trustedRoot, directory);
        PathSafety.EnsureNoReparseComponents(trustedRoot, fullPath);
        string temporary = PathSafety.CreateRandomTemporaryPath(trustedRoot, directory, Path.GetFileName(fullPath));
        bool committed = false;
        try
        {
            await using (FileStream stream = new(
                             temporary,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             64 * 1024,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await writeAsync(stream, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            cancellationToken.ThrowIfCancellationRequested();
            PathSafety.EnsureSafeFileCommit(trustedRoot, temporary, fullPath);
            File.Move(temporary, fullPath, overwrite: true);
            committed = true;
        }
        finally
        {
            if (!committed)
            {
                PathSafety.TryDeleteFile(trustedRoot, temporary);
            }
        }
    }

    private static async Task<string> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024, useAsync: true);
        byte[] hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static string EscapeCsv(string? value)
    {
        string safe = value ?? string.Empty;
        if (safe.Length > 0 && safe[0] is '=' or '+' or '-' or '@')
        {
            safe = "'" + safe;
        }

        return '"' + safe.Replace("\"", "\"\"") + '"';
    }

    private static string FormatValue(object? value) =>
        value is IFormattable formattable
            ? formattable.ToString(null, CultureInfo.InvariantCulture)
            : value?.ToString() ?? string.Empty;

    private static string ValidateSessionId(string value)
    {
        if (!SessionIdValidator.IsValid(value))
        {
            throw new ArgumentException("The report session ID must be a non-empty single safe path segment.", nameof(value));
        }

        return value;
    }

    private static (string ZipPath, string ShaPath) GetAvailablePackagePaths(string reportsRoot, string baseName)
    {
        for (int suffix = 0; suffix < 10_000; suffix++)
        {
            string candidateName = suffix == 0 ? baseName : $"{baseName}-{suffix}";
            string zipPath = Path.Combine(reportsRoot, candidateName + ".zip");
            string shaPath = zipPath + ".sha256";
            if (!File.Exists(zipPath) &&
                !File.Exists(shaPath))
            {
                return (zipPath, shaPath);
            }
        }

        throw new IOException("Could not allocate a unique report package name.");
    }

    private static string ShortId(string value)
    {
        string compact = new(value.Where(char.IsLetterOrDigit).ToArray());
        return compact.Length <= 8 ? compact : compact[^8..];
    }

    private sealed record ManifestEntry(string Name, long SizeBytes, string Sha256);

    private sealed record ReportManifest(int ReportSchemaVersion, string SessionId, DateTimeOffset CreatedUtc, IReadOnlyList<ManifestEntry> Files);
}

internal static class PathSafety
{
    private const int MaximumTemporaryNameAttempts = 64;

    public static string EnsureContained(string trustedRoot, string candidate)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(trustedRoot);
        ArgumentException.ThrowIfNullOrWhiteSpace(candidate);
        string root = NormalizePath(trustedRoot);
        string fullCandidate = Path.GetFullPath(candidate);
        string rootPrefix = root.EndsWith(Path.DirectorySeparatorChar)
            ? root
            : root + Path.DirectorySeparatorChar;
        if (!string.Equals(fullCandidate, root, StringComparison.OrdinalIgnoreCase) &&
            !fullCandidate.StartsWith(rootPrefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("The requested path is outside the trusted diagnostic folder.");
        }

        return fullCandidate;
    }

    public static string EnsureDirectory(string trustedRoot, string directory)
    {
        string fullDirectory = EnsureContained(trustedRoot, directory);
        EnsureNoReparseComponents(trustedRoot, fullDirectory);
        Directory.CreateDirectory(fullDirectory);
        EnsureNoReparseComponents(trustedRoot, fullDirectory);
        return fullDirectory;
    }

    public static void EnsureNoReparseComponents(string trustedRoot, string candidate)
    {
        string fullCandidate = EnsureContained(trustedRoot, candidate);
        EnsureNoReparseComponents(fullCandidate);
    }

    public static void EnsureNoReparseComponents(string candidate)
    {
        string fullCandidate = Path.GetFullPath(candidate);
        string pathRoot = Path.GetPathRoot(fullCandidate)
            ?? throw new IOException("The requested path has no filesystem root.");
        string current = pathRoot;
        string remainder = fullCandidate[pathRoot.Length..];
        foreach (string component in remainder.Split(
                     [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                     StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, component);
            try
            {
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                {
                    throw new IOException($"Reparse points are not allowed in diagnostic paths: {current}");
                }
            }
            catch (FileNotFoundException)
            {
                // A later create is followed by another complete path validation.
            }
            catch (DirectoryNotFoundException)
            {
                // A later create is followed by another complete path validation.
            }
        }
    }

    public static void EnsureSafeExistingFile(string trustedRoot, string path)
    {
        string fullPath = EnsureContained(trustedRoot, path);
        EnsureNoReparseComponents(trustedRoot, fullPath);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("A required diagnostic file is missing.", fullPath);
        }

        if (Directory.Exists(fullPath))
        {
            throw new IOException("A diagnostic file path resolves to a directory.");
        }
    }

    public static void EnsureSafeFileCommit(string trustedRoot, string temporaryPath, string finalPath)
    {
        string temporary = EnsureContained(trustedRoot, temporaryPath);
        string final = EnsureContained(trustedRoot, finalPath);
        EnsureSafeExistingFile(trustedRoot, temporary);
        EnsureNoReparseComponents(trustedRoot, final);
        if (Directory.Exists(final))
        {
            throw new IOException("A diagnostic output file path resolves to a directory.");
        }
    }

    public static string CreateRandomTemporaryPath(string trustedRoot, string directory, string tag)
    {
        string fullDirectory = EnsureDirectory(trustedRoot, directory);
        string safeTag = new(tag.Where(character => char.IsLetterOrDigit(character) || character is '-' or '_').ToArray());
        if (safeTag.Length == 0)
        {
            safeTag = "diagnostic";
        }

        for (int attempt = 0; attempt < MaximumTemporaryNameAttempts; attempt++)
        {
            string suffix = Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant();
            string candidate = Path.Combine(fullDirectory, $".{safeTag}.{suffix}.partial");
            EnsureNoReparseComponents(trustedRoot, candidate);
            if (!File.Exists(candidate) && !Directory.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new IOException("Could not allocate a random diagnostic temporary-file name.");
    }

    public static void TryDeleteFile(string trustedRoot, string path)
    {
        try
        {
            string fullPath = EnsureContained(trustedRoot, path);
            EnsureNoReparseComponents(trustedRoot, fullPath);
            if (File.Exists(fullPath))
            {
                File.Delete(fullPath);
            }
        }
        catch (IOException)
        {
            // Best effort: never follow or delete through a changed path during cleanup.
        }
        catch (UnauthorizedAccessException)
        {
            // Best effort: never broaden cleanup outside the trusted root.
        }
    }

    private static string NormalizePath(string path)
    {
        string fullPath = Path.GetFullPath(path);
        string pathRoot = Path.GetPathRoot(fullPath) ?? string.Empty;
        return fullPath.Length == pathRoot.Length
            ? fullPath
            : fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }
}
