using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Core.Sharing;

public sealed class SafeSummaryService
{
    private const int MaximumActivePreviews = 32;
    private static readonly TimeSpan DefaultLifetime = TimeSpan.FromMinutes(15);
    private static readonly string[] IncludedCategories =
    [
        "System specifications",
        "Normalized bugcheck values",
        "Allowlisted Windows signal counts",
        "Crash-capture readiness",
        "Bounded dump metadata",
        "Privacy-filtered driver context",
        "Privacy-filtered storage and recent-change facts",
        "Source coverage"
    ];
    private static readonly string[] ExcludedCategories =
    [
        "Event and reliability messages",
        "Usernames, paths, session IDs, device IDs, and hashes",
        "Dump bytes and raw debugger output",
        "Finding prose and collector error details",
        "Process IDs, command lines, module paths and unfiltered module lists, inputs, and anti-cheat data"
    ];

    private readonly ConcurrentDictionary<string, PreviewEntry> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _lifetime;
    private readonly Action? _beforeDestinationLeaseAcquisition;
    private static readonly JsonSerializerOptions ReportJsonOptions = new()
    {
        AllowTrailingCommas = false,
        PropertyNameCaseInsensitive = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        MaxDepth = 96
    };

    public SafeSummaryService(TimeProvider? timeProvider = null, TimeSpan? previewLifetime = null)
        : this(timeProvider, previewLifetime, beforeDestinationLeaseAcquisition: null)
    {
    }

    internal SafeSummaryService(
        TimeProvider? timeProvider,
        TimeSpan? previewLifetime,
        Action? beforeDestinationLeaseAcquisition)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _lifetime = previewLifetime ?? DefaultLifetime;
        _beforeDestinationLeaseAcquisition = beforeDestinationLeaseAcquisition;
        if (_lifetime <= TimeSpan.Zero || _lifetime > TimeSpan.FromHours(1))
        {
            throw new ArgumentOutOfRangeException(nameof(previewLifetime), "Preview lifetime must be between zero and one hour.");
        }
    }

    public async Task<SafeSummaryPreview> CreatePreviewAsync(
        UiReportHandle handle,
        ReportHandleRegistry registry,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(handle);
        ArgumentNullException.ThrowIfNull(registry);
        ResolvedReportHandle resolved = registry.Resolve(handle);
        ReportHandleFile source = resolved.Files.FirstOrDefault(item =>
                Path.GetExtension(item.FullPath).Equals(".zip", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidDataException("Safe Summary currently requires a validated standard report ZIP.");
        ValidatedReportArchive archive = await IncidentLibrary.ReadValidatedArchiveAsync(source.FullPath, cancellationToken)
            .ConfigureAwait(false);
        if (!string.Equals(archive.SessionId, resolved.SessionId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The registered report identity does not match its validated archive.");
        }

        DiagnosticReportV3 report = DeserializeReport(archive);
        if (report.ReportSchemaVersion != 3 ||
            !string.Equals(report.SessionId, resolved.SessionId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The report payload does not match the selected report identity.");
        }

        source.Snapshot.VerifyUnchanged();
        return CreatePreviewCore(report, new ReportBinding(registry, handle, source, resolved.SessionId));
    }

    internal SafeSummaryPreview CreatePreview(DiagnosticReportV3 report) =>
        CreatePreviewCore(report, binding: null);

    private SafeSummaryPreview CreatePreviewCore(DiagnosticReportV3 report, ReportBinding? binding)
    {
        SafeSummaryV1 projection = SafeSummaryProjector.Project(report);
        byte[] bytes = SafeSummaryRenderer.RenderUtf8(projection);
        string text = new UTF8Encoding(false, true).GetString(bytes);
        DateTimeOffset now = _timeProvider.GetUtcNow();
        RemoveExpired(now);
        if (_entries.Count >= MaximumActivePreviews)
        {
            PreviewEntry? oldest = _entries.Values.OrderBy(item => item.CreatedUtc).FirstOrDefault();
            if (oldest is not null)
            {
                _entries.TryRemove(oldest.Token, out _);
            }
        }

        string token = CreateToken();
        var entry = new PreviewEntry(token, now, now + _lifetime, bytes, binding);
        if (!_entries.TryAdd(token, entry))
        {
            throw new CryptographicException("Could not allocate a unique Safe Summary preview token.");
        }

        string suggestedName = "PCCrashDiagnostic-Support-Summary-" +
                               report.EndUtc.ToUniversalTime().ToString("yyyyMMdd-HHmm'Z'") + ".txt";
        return new SafeSummaryPreview(
            token,
            text,
            suggestedName,
            entry.ExpiresUtc,
            IncludedCategories,
            ExcludedCategories);
    }

    internal string GetPreviewText(string previewToken)
    {
        PreviewEntry entry = Resolve(previewToken);
        return new UTF8Encoding(false, true).GetString(entry.Bytes);
    }

    public SafeExportDestinationAssessment AssessDestination(string destinationPath) =>
        SafeExportPathValidator.ValidateNewTextFile(destinationPath).Assessment;

    public async Task<ReadOnlyMemory<byte>> GetExactUtf8Async(
        string previewToken,
        CancellationToken cancellationToken = default)
    {
        PreviewEntry entry = await ResolveAndValidateAsync(previewToken, cancellationToken).ConfigureAwait(false);
        return entry.Bytes.ToArray();
    }

    public async Task<string> GetExactTextAsync(
        string previewToken,
        CancellationToken cancellationToken = default)
    {
        ReadOnlyMemory<byte> bytes = await GetExactUtf8Async(previewToken, cancellationToken).ConfigureAwait(false);
        return new UTF8Encoding(false, true).GetString(bytes.Span);
    }

    public async Task<SafeSummaryExportResult> ExportAsync(
        string previewToken,
        string destinationPath,
        CancellationToken cancellationToken = default)
    {
        PreviewEntry entry = await ResolveAndValidateAsync(previewToken, cancellationToken).ConfigureAwait(false);
        ValidatedExportDestination destination = SafeExportPathValidator.ValidateNewTextFile(destinationPath);
        string temporaryPath = Path.Combine(
            destination.ParentDirectory,
            ".pcd-safe-summary-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant() + ".partial");
        _beforeDestinationLeaseAcquisition?.Invoke();
        using StableDirectoryLease lease = WindowsFileIdentity.AcquireStableDirectory(
            destination.ParentDirectory,
            destination.ParentIdentity);
        lease.VerifyDestinationAbsent(destination.FullPath);
        try
        {
            using var temporaryHandle = WindowsFileIdentity.CreateExclusiveExportFile(temporaryPath);
            await using (var stream = new FileStream(
                             temporaryHandle,
                             FileAccess.Write,
                             64 * 1024,
                             isAsync: true))
            {
                await ValidateBindingOrRevokeAsync(entry, cancellationToken).ConfigureAwait(false);
                await stream.WriteAsync(entry.Bytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
                stream.Flush(flushToDisk: true);
                LocalFileIdentity temporaryIdentity = WindowsFileIdentity.Capture(stream.SafeFileHandle);
                if (temporaryIdentity.IsDirectory || temporaryIdentity.IsReparsePoint ||
                    temporaryIdentity.SizeBytes != entry.Bytes.Length)
                {
                    throw new IOException("The Safe Summary temporary file failed identity validation.");
                }

                await ValidateBindingOrRevokeAsync(entry, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                lease.VerifyDestinationAbsent(destination.FullPath);
                WindowsFileIdentity.RenameToLockedDestination(
                    stream.SafeFileHandle,
                    destination.FullPath);
                string publishedPath = WindowsFileIdentity.GetFinalPath(stream.SafeFileHandle);
                if (!string.Equals(Path.GetFullPath(publishedPath), destination.FullPath, StringComparison.OrdinalIgnoreCase))
                {
                    throw new IOException($"The completed export was assigned an unexpected filename '{Path.GetFileName(publishedPath)}'.");
                }
            }

            return new SafeSummaryExportResult(
                Path.GetFileName(destination.FullPath),
                entry.Bytes.Length,
                destination.Assessment);
        }
        finally
        {
            try
            {
                if (File.Exists(temporaryPath))
                {
                    File.Delete(temporaryPath);
                }
            }
            catch (IOException)
            {
                // The partial file remains conspicuously named; never broaden cleanup.
            }
            catch (UnauthorizedAccessException)
            {
                // The partial file remains conspicuously named; never broaden cleanup.
            }
        }
    }

    public bool Revoke(string previewToken) =>
        !string.IsNullOrWhiteSpace(previewToken) && _entries.TryRemove(previewToken, out _);

    public void RevokeAll() => _entries.Clear();

    public int RevokeForReport(UiReportHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        int removed = 0;
        foreach (PreviewEntry entry in _entries.Values)
        {
            if (entry.Binding?.Handle.Equals(handle) == true && _entries.TryRemove(entry.Token, out _))
            {
                removed++;
            }
        }

        return removed;
    }

    private PreviewEntry Resolve(string previewToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(previewToken);
        DateTimeOffset now = _timeProvider.GetUtcNow();
        if (!_entries.TryGetValue(previewToken, out PreviewEntry? entry) || entry.ExpiresUtc <= now)
        {
            _entries.TryRemove(previewToken, out _);
            throw new InvalidOperationException("The Safe Summary preview expired or is no longer valid. Preview it again before exporting.");
        }

        return entry;
    }

    private void RemoveExpired(DateTimeOffset now)
    {
        foreach (PreviewEntry entry in _entries.Values)
        {
            if (entry.ExpiresUtc <= now)
            {
                _entries.TryRemove(entry.Token, out _);
            }
        }
    }

    private static string CreateToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();

    private async Task<PreviewEntry> ResolveAndValidateAsync(
        string previewToken,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        PreviewEntry entry = Resolve(previewToken);
        await ValidateBindingOrRevokeAsync(entry, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return entry;
    }

    private async Task ValidateBindingOrRevokeAsync(PreviewEntry entry, CancellationToken cancellationToken)
    {
        try
        {
            await ValidateBindingAsync(entry, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            _entries.TryRemove(entry.Token, out _);
            throw;
        }
    }

    private static async Task ValidateBindingAsync(PreviewEntry entry, CancellationToken cancellationToken)
    {
        if (entry.Binding is null)
        {
            return;
        }

        ResolvedReportHandle current = entry.Binding.Registry.Resolve(entry.Binding.Handle);
        if (!string.Equals(current.SessionId, entry.Binding.SessionId, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The selected report identity changed after preview.");
        }

        ReportHandleFile source = current.Files.FirstOrDefault(item =>
                string.Equals(item.FullPath, entry.Binding.Source.FullPath, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException("The selected report is no longer registered.");
        entry.Binding.Source.Snapshot.VerifyUnchanged();
        source.Snapshot.VerifyUnchanged();
        ValidatedReportArchive archive = await IncidentLibrary.ReadValidatedArchiveAsync(source.FullPath, cancellationToken)
            .ConfigureAwait(false);
        if (archive.ReportSchemaVersion is not (2 or 3) ||
            !string.Equals(archive.SessionId, entry.Binding.SessionId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The report changed after Safe Summary preview.");
        }

        DiagnosticReportV3 currentReport = DeserializeReport(archive);
        if (!string.Equals(currentReport.SessionId, entry.Binding.SessionId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The report identity changed after Safe Summary preview.");
        }

        byte[] currentBytes = SafeSummaryRenderer.RenderUtf8(SafeSummaryProjector.Project(currentReport));
        if (currentBytes.Length != entry.Bytes.Length ||
            !CryptographicOperations.FixedTimeEquals(currentBytes, entry.Bytes))
        {
            throw new InvalidDataException("The Safe Summary content changed after preview. Preview it again before exporting.");
        }
    }

    private static DiagnosticReportV3 DeserializeReport(ValidatedReportArchive archive) => archive.ReportSchemaVersion switch
    {
        3 => JsonSerializer.Deserialize<DiagnosticReportV3>(archive.ReportJson.Span, ReportJsonOptions)
             ?? throw new InvalidDataException("The report archive contains no schema-3 report."),
        2 => LegacyV2ReportAdapter.ToDiagnosticReportV3(
            JsonSerializer.Deserialize<DiagnosticReport>(archive.ReportJson.Span, ReportJsonOptions)
            ?? throw new InvalidDataException("The report archive contains no schema-2 report.")),
        _ => throw new InvalidDataException("Safe Summary accepts validated report schema 2 or 3 only.")
    };

    private sealed record PreviewEntry(
        string Token,
        DateTimeOffset CreatedUtc,
        DateTimeOffset ExpiresUtc,
        byte[] Bytes,
        ReportBinding? Binding);

    private sealed record ReportBinding(
        ReportHandleRegistry Registry,
        UiReportHandle Handle,
        ReportHandleFile Source,
        string SessionId);
}
