using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;
using BF6CrashDiagnostic.Core.Sharing;
using PCCrashDiagnostic.Core;
using PCCrashDiagnostic.LocalTools;

namespace PCCrashDiagnostic.App.Services;

public sealed class CoreReadOnlyDiagnosticService : IReadOnlyDiagnosticService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private readonly ReadOnlyDiagnosticCoordinator _coordinator;
    private readonly ReportHandleRegistry _registry;
    private readonly SafeSummaryService _safeSummaries = new();
    private readonly TechnicalReportExportValidator _technicalReports;
    private readonly RecycleBinDeletionService _recycleBin;
    private readonly ReportWriter _reportWriter;
    private readonly ILocalDebuggerService _localTools;
    private readonly SummaryBuilderV3 _summaryBuilder = new();
    private readonly CrashCorrelator _correlator = new();
    private readonly ExtendedEvidenceAnalyzer _extendedEvidence = new();
    private readonly ConcurrentDictionary<UiReportHandle, DiagnosticReportV3> _reports = new();
    private readonly ConcurrentDictionary<UiReportHandle, string> _historyPaths = new();
    private readonly ConcurrentDictionary<string, BoundDumpChoice> _dumpChoices = new(StringComparer.Ordinal);

    public CoreReadOnlyDiagnosticService(string? dataRoot = null)
    {
        string root = dataRoot ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "PCCrashDiagnostic");
        _coordinator = new ReadOnlyDiagnosticCoordinator(root);
        _registry = new ReportHandleRegistry(root);
        _technicalReports = new TechnicalReportExportValidator(_registry);
        _recycleBin = new RecycleBinDeletionService(root, _registry, _safeSummaries);
        _reportWriter = new ReportWriter(root);
        _localTools = new LocalDebuggerService(root);
    }

    public Task<IncidentSearchResult> FindRecentIncidentsAsync(
        IncidentSearchOptions options,
        CancellationToken cancellationToken = default) =>
        _coordinator.FindRecentIncidentsAsync(options, cancellationToken);

    public async Task<UiCollectedReport> AnalyzeSelectedIncidentAsync(
        IncidentSelection selection,
        TargetProfile? targetProfile = null,
        IProgress<DiagnosticProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        DiagnosticOperationResultV3 result = await _coordinator.AnalyzeSelectedIncidentAsync(
            selection,
            targetProfile,
            progress,
            cancellationToken).ConfigureAwait(false);
        return await RegisterAsync(result, ReportOrigin.Generated, cancellationToken).ConfigureAwait(false);
    }

    public async Task<UiCollectedReport> MonitorSelectedTargetAsync(
        TargetProfile targetProfile,
        IProgress<TargetMonitorProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        DiagnosticOperationResultV3 result = await _coordinator.MonitorSelectedTargetAsync(
            targetProfile,
            progress,
            cancellationToken).ConfigureAwait(false);
        return await RegisterAsync(result, ReportOrigin.Generated, cancellationToken).ConfigureAwait(false);
    }

    public async Task<UiCollectedReport> OpenPreviousReportAsync(
        string reportPath,
        CancellationToken cancellationToken = default)
    {
        IReadOnlyList<ReportImportResult> imported = await _coordinator.IncidentLibrary
            .ImportValidatedReportsAsync([reportPath], cancellationToken)
            .ConfigureAwait(false);
        string localPath = imported.SingleOrDefault()?.ImportedPath ??
                           throw new InvalidDataException(imported.SingleOrDefault()?.Detail ?? "The report could not be imported.");
        DiagnosticReportV3 report = await ReadReportAsync(localPath, cancellationToken).ConfigureAwait(false);
        UiReportHandle handle = await RegisterSessionCopiesAsync(
            report.SessionId,
            new LocalReportCopy(localPath, Imported: true),
            cancellationToken).ConfigureAwait(false);
        _reports[handle] = report;
        return new UiCollectedReport(
            handle,
            new DiagnosticOperationResultV3(
                new ReportPackageV3(report, string.Empty, string.Empty, string.Empty, string.Empty),
                report.CrashCorrelation?.RelatedDumps ?? [],
                false,
                report.CollectionStatus
                    .Where(status => status.State != CollectionState.Available)
                    .Select(status => $"{status.Source}: {status.State}")
                    .ToArray()));
    }

    public async Task<IReadOnlyList<UiHistoryReport>> GetHistoryAsync(CancellationToken cancellationToken = default)
    {
        IncidentLibrarySnapshot snapshot = await _coordinator.IncidentLibrary.BuildAsync(cancellationToken).ConfigureAwait(false);
        var result = new List<UiHistoryReport>();
        foreach (IncidentLibraryEntry entry in snapshot.Incidents)
        {
            try
            {
                IReadOnlyList<LocalReportCopy> copies = entry.LocalCopies is { Count: > 0 }
                    ? entry.LocalCopies
                    : [new LocalReportCopy(entry.ReportPath, entry.Imported)];
                UiReportHandle handle = await _registry.RegisterValidatedCopiesAsync(
                    copies,
                    cancellationToken).ConfigureAwait(false);
                result.Add(new UiHistoryReport(
                    handle,
                    entry.SessionId,
                    entry.StartUtc,
                    entry.Kind,
                    entry.TargetName,
                    entry.StopCodes));
                _historyPaths[handle] = entry.ReportPath;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException)
            {
                // A file can disappear while history is refreshing. Omit it and
                // let the next scan rebuild from the remaining validated files.
            }
        }

        return result;
    }

    public async Task<UiCollectedReport> OpenHistoryReportAsync(
        UiHistoryReport report,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(report);
        if (!_registry.IsValid(report.Handle) || !_historyPaths.TryGetValue(report.Handle, out string? path))
        {
            throw new InvalidOperationException("The history selection expired. Refresh history and try again.");
        }

        DiagnosticReportV3 diagnosticReport = await ReadReportAsync(path, cancellationToken).ConfigureAwait(false);
        _reports[report.Handle] = diagnosticReport;
        return new UiCollectedReport(
            report.Handle,
            new DiagnosticOperationResultV3(
                new ReportPackageV3(diagnosticReport, string.Empty, path, string.Empty, string.Empty),
                diagnosticReport.CrashCorrelation?.RelatedDumps ?? [],
                false,
                diagnosticReport.CollectionStatus
                    .Where(status => status.State != CollectionState.Available)
                    .Select(status => $"{status.Source}: {status.State}")
                    .ToArray()));
    }

    public Task<SafeSummaryPreview> CreateSupportSummaryPreviewAsync(
        UiReportHandle report,
        CancellationToken cancellationToken = default) =>
        _safeSummaries.CreatePreviewAsync(report, _registry, cancellationToken);

    public Task<string> GetExactSupportSummaryTextAsync(
        string previewToken,
        CancellationToken cancellationToken = default) =>
        _safeSummaries.GetExactTextAsync(previewToken, cancellationToken);

    public UiExportDestination PrepareSupportSummaryDestination(string destinationPath) =>
        new(Path.GetFullPath(destinationPath), _safeSummaries.AssessDestination(destinationPath));

    public Task<SafeSummaryExportResult> ExportSupportSummaryAsync(
        string previewToken,
        UiExportDestination destination,
        CancellationToken cancellationToken = default) =>
        _safeSummaries.ExportAsync(previewToken, destination.FullPath, cancellationToken);

    public Task<TechnicalReportExportTicket> PrepareTechnicalReportExportAsync(
        UiReportHandle report,
        CancellationToken cancellationToken = default) =>
        _technicalReports.PrepareAsync(report, cancellationToken);

    public Task<TechnicalReportExportResult> ExportTechnicalReportAsync(
        string ticket,
        UiExportDestination destination,
        CancellationToken cancellationToken = default) =>
        _technicalReports.ExportAsync(ticket, destination.FullPath, cancellationToken);

    public UiExportDestination PrepareTechnicalReportDestination(string destinationPath) =>
        new(Path.GetFullPath(destinationPath), _technicalReports.AssessDestination(destinationPath));

    public Task<UiLocalToolOptions> GetLocalToolOptionsAsync(
        UiReportHandle report,
        CancellationToken cancellationToken = default) =>
        Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            DiagnosticReportV3 diagnosticReport = ResolveReport(report);
            foreach ((string token, BoundDumpChoice choice) in _dumpChoices.ToArray())
            {
                if (choice.Report.Equals(report))
                {
                    _dumpChoices.TryRemove(token, out _);
                }
            }

            DumpCandidate[] candidates = (diagnosticReport.CrashCorrelation?.RelatedDumps ?? [])
                .Where(candidate =>
                    candidate.InspectionState == DumpInspectionState.Recognized &&
                    candidate.Format != DumpFormat.Unknown &&
                    !string.IsNullOrWhiteSpace(candidate.OriginalPath))
                .DistinctBy(DumpIdentity, StringComparer.OrdinalIgnoreCase)
                .Take(24)
                .ToArray();
            UiDumpChoice[] choices = candidates.Select(candidate =>
            {
                string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
                _dumpChoices[token] = new BoundDumpChoice(report, candidate);
                string display = $"{DumpKindLabel(candidate.Kind)} · {candidate.Format} · {FormatBytes(candidate.SizeBytes)} · {candidate.LastWriteUtc.ToLocalTime():g}";
                return new UiDumpChoice(token, display);
            }).ToArray();

            return new UiLocalToolOptions(
                _localTools.InspectDebuggerAvailability(),
                _localTools.InspectDumpCheckerAvailability(),
                choices);
        }, cancellationToken);

    public async Task<UiCollectedReport> RunDumpQualityAsync(
        UiReportHandle report,
        string dumpChoiceToken,
        bool runInstalledDumpChk,
        IProgress<DiagnosticProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        (DiagnosticReportV3 prior, DumpCandidate dump, CrashCorrelation correlation) =
            ResolveDumpChoice(report, dumpChoiceToken);
        progress?.Report(new DiagnosticProgress(
            "Dump check",
            runInstalledDumpChk
                ? "Running the installed Microsoft DumpChk tool offline."
                : "Checking the dump header and bounded metadata.",
            0.2));
        DumpQuality quality = await _localTools.InspectDumpQualityAsync(
            dump,
            runInstalledDumpChk,
            prior.TargetProfile,
            cancellationToken).ConfigureAwait(false);
        CollectionStatus dumpStatus = CreateDumpQualityStatus(quality);
        CollectionStatus[] statuses = prior.CollectionStatus
            .Where(status => !status.Source.Equals("Dump quality", StringComparison.OrdinalIgnoreCase))
            .Append(dumpStatus)
            .ToArray();
        DiagnosticFinding[] findings = prior.Findings
            .Where(finding => !IsExtendedEvidenceFinding(finding.Id))
            .Concat(_extendedEvidence.Analyze(
                quality,
                prior.RecentChanges,
                prior.StorageHealth,
                prior.DriverVerifier))
            .OrderBy(finding => finding.Rank)
            .ThenBy(finding => finding.Id, StringComparer.Ordinal)
            .ToArray();
        SourceCoverage[] coverage = prior.SourceCoverage
            .Where(source => !source.Source.Equals("Dump quality", StringComparison.OrdinalIgnoreCase))
            .Append(new SourceCoverage("Dump quality", dumpStatus.State, 1, dumpStatus.Detail))
            .OrderBy(source => source.Source, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        string summary = _summaryBuilder.Build(
            prior.ToolVersion,
            prior.SessionId,
            prior.StartUtc,
            prior.EndUtc,
            prior.CompletionReason,
            prior.IncidentSelection,
            prior.TargetProfile,
            findings,
            coverage,
            correlation,
            prior.DebuggerAnalysis,
            prior.CrashReadiness,
            quality,
            prior.RecentChanges,
            prior.StorageHealth,
            prior.DriverVerifier,
            prior.BootSession);
        DiagnosticReportV3 updated = prior with
        {
            Findings = findings,
            CollectionStatus = statuses,
            SourceCoverage = coverage,
            CrashCorrelation = correlation,
            DumpQuality = quality,
            Summary = summary
        };
        progress?.Report(new DiagnosticProgress("Packaging", "Writing the structured dump-quality result to a new local report.", 0.85));
        return await WriteUpdatedReportAsync(updated, correlation.RelatedDumps, cancellationToken).ConfigureAwait(false);
    }

    public async Task<UiCollectedReport> RunWinDbgAnalysisAsync(
        UiReportHandle report,
        string dumpChoiceToken,
        bool allowMicrosoftSymbolDownload,
        IProgress<DiagnosticProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        (DiagnosticReportV3 prior, DumpCandidate dump, CrashCorrelation correlation) =
            ResolveDumpChoice(report, dumpChoiceToken);
        progress?.Report(new DiagnosticProgress(
            "WinDbg",
            allowMicrosoftSymbolDownload
                ? "Running WinDbg and allowing downloads only from Microsoft's public symbol server."
                : "Running WinDbg offline with the local symbol cache.",
            0.2));
        DebuggerAnalysis analysis = await _localTools.RunWinDbgAnalysisAsync(
            dump,
            prior.SessionId,
            allowMicrosoftSymbolDownload,
            prior.TargetProfile,
            cancellationToken).ConfigureAwait(false);
        string summary = _summaryBuilder.Build(
            prior.ToolVersion,
            prior.SessionId,
            prior.StartUtc,
            prior.EndUtc,
            prior.CompletionReason,
            prior.IncidentSelection,
            prior.TargetProfile,
            prior.Findings,
            prior.SourceCoverage,
            correlation,
            analysis,
            prior.CrashReadiness,
            prior.DumpQuality,
            prior.RecentChanges,
            prior.StorageHealth,
            prior.DriverVerifier,
            prior.BootSession);
        DiagnosticReportV3 updated = prior with
        {
            CrashCorrelation = correlation,
            DebuggerAnalysis = analysis,
            Summary = summary
        };
        progress?.Report(new DiagnosticProgress("Packaging", "Writing only the allowlisted WinDbg fields to a new local report.", 0.85));
        return await WriteUpdatedReportAsync(updated, correlation.RelatedDumps, cancellationToken).ConfigureAwait(false);
    }

    public bool RevokeSupportSummary(string previewToken) => _safeSummaries.Revoke(previewToken);

    public ReportDeletionPreview PreviewRecycleReport(UiReportHandle report) =>
        _recycleBin.PreviewSelected(report);

    public Task<ReportDeletionPreview> PreviewRecycleAllHistoryAsync(
        CancellationToken cancellationToken = default) =>
        _recycleBin.PreviewAllHistoryAsync(cancellationToken);

    public Task<ReportDeletionResult> RecycleAsync(
        string previewToken,
        CancellationToken cancellationToken = default) =>
        _recycleBin.RecycleAsync(previewToken, cancellationToken);

    public void Dispose()
    {
        _safeSummaries.RevokeAll();
        _historyPaths.Clear();
        _dumpChoices.Clear();
        _registry.RevokeAll();
        _coordinator.Dispose();
    }

    private async Task<UiCollectedReport> RegisterAsync(
        DiagnosticOperationResultV3 result,
        ReportOrigin origin,
        CancellationToken cancellationToken)
    {
        UiReportHandle handle = await RegisterSessionCopiesAsync(
            result.Package.Report.SessionId,
            new LocalReportCopy(result.Package.ZipPath, origin == ReportOrigin.Imported),
            cancellationToken).ConfigureAwait(false);
        _reports[handle] = result.Package.Report;
        return new UiCollectedReport(handle, result);
    }

    private async Task<UiReportHandle> RegisterSessionCopiesAsync(
        string sessionId,
        LocalReportCopy preferredCopy,
        CancellationToken cancellationToken)
    {
        IncidentLibrarySnapshot snapshot = await _coordinator.IncidentLibrary
            .BuildAsync(cancellationToken)
            .ConfigureAwait(false);
        IncidentLibraryEntry? entry = snapshot.Incidents.FirstOrDefault(item =>
            string.Equals(item.SessionId, sessionId, StringComparison.Ordinal));
        LocalReportCopy[] copies = new[] { preferredCopy }
            .Concat(entry?.LocalCopies ?? [])
            .DistinctBy(copy => Path.GetFullPath(copy.ReportPath), StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return await _registry.RegisterValidatedCopiesAsync(copies, cancellationToken).ConfigureAwait(false);
    }

    private DiagnosticReportV3 ResolveReport(UiReportHandle handle)
    {
        if (!_registry.IsValid(handle) || !_reports.TryGetValue(handle, out DiagnosticReportV3? report))
        {
            throw new InvalidOperationException("The selected report expired or changed. Select it again.");
        }

        return report;
    }

    private (DiagnosticReportV3 Report, DumpCandidate Dump, CrashCorrelation Correlation) ResolveDumpChoice(
        UiReportHandle report,
        string dumpChoiceToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dumpChoiceToken);
        DiagnosticReportV3 diagnosticReport = ResolveReport(report);
        if (!_dumpChoices.TryGetValue(dumpChoiceToken, out BoundDumpChoice? choice) ||
            !choice.Report.Equals(report))
        {
            throw new InvalidOperationException("The dump selection expired. Refresh the optional local-analysis choices.");
        }

        CrashCorrelation original = diagnosticReport.CrashCorrelation ??
            throw new InvalidOperationException("This report has no crash-dump correlation to analyze.");
        CrashCorrelation selected = _correlator.SelectDump(original, choice.Dump);
        return (diagnosticReport, selected.SelectedDump!, selected);
    }

    private async Task<UiCollectedReport> WriteUpdatedReportAsync(
        DiagnosticReportV3 report,
        IReadOnlyList<DumpCandidate> dumpChoices,
        CancellationToken cancellationToken)
    {
        ReportPackageV3 package = await _reportWriter.WriteV3Async(report, cancellationToken).ConfigureAwait(false);
        string[] failures = report.CollectionStatus
            .Where(status => status.State != CollectionState.Available)
            .Select(status => $"{status.Source}: {status.State}")
            .ToArray();
        var result = new DiagnosticOperationResultV3(package, dumpChoices, false, failures);
        _safeSummaries.RevokeAll();
        _dumpChoices.Clear();
        return await RegisterAsync(result, ReportOrigin.Generated, cancellationToken).ConfigureAwait(false);
    }

    private static CollectionStatus CreateDumpQualityStatus(DumpQuality quality)
    {
        CollectionState state = quality.Classification switch
        {
            DumpQualityClassification.Inaccessible => CollectionState.Denied,
            DumpQualityClassification.AnalysisUnavailable => CollectionState.Unavailable,
            _ => CollectionState.Available
        };
        return new CollectionStatus("Dump quality", state, quality.Detail);
    }

    private static bool IsExtendedEvidenceFinding(string id) =>
        id.StartsWith("dump-quality-", StringComparison.Ordinal) ||
        id.Equals("storage-health-warning", StringComparison.Ordinal) ||
        id.Equals("driver-verifier-enabled", StringComparison.Ordinal) ||
        id.Equals("recent-system-changes", StringComparison.Ordinal);

    private static string DumpIdentity(DumpCandidate candidate) => string.Join(
        '|',
        candidate.Kind,
        candidate.OriginalPath ?? candidate.RedactedPath,
        candidate.SizeBytes,
        candidate.LastWriteUtc.ToUniversalTime().Ticks);

    private static string DumpKindLabel(DumpKind kind) => kind switch
    {
        DumpKind.WindowsMemoryDump => "Windows memory dump",
        DumpKind.WindowsMinidump => "Windows minidump",
        DumpKind.LiveKernelDump => "Live-kernel dump",
        DumpKind.ApplicationDump => "Application dump",
        _ => "Crash dump"
    };

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024 * 1024)
        {
            return $"{Math.Max(0, bytes) / 1024d:0.0} KiB";
        }

        if (bytes < 1024L * 1024 * 1024)
        {
            return $"{bytes / (1024d * 1024):0.0} MiB";
        }

        return $"{bytes / (1024d * 1024 * 1024):0.0} GiB";
    }

    private static async Task<DiagnosticReportV3> ReadReportAsync(string path, CancellationToken cancellationToken)
    {
        ValidatedReportArchive archive = await IncidentLibrary.ReadValidatedArchiveAsync(path, cancellationToken).ConfigureAwait(false);
        return archive.ReportSchemaVersion switch
        {
            3 => JsonSerializer.Deserialize<DiagnosticReportV3>(archive.ReportJson.Span, JsonOptions) ??
                 throw new InvalidDataException("The validated schema-3 report JSON could not be read."),
            2 => LegacyV2ReportAdapter.ToDiagnosticReportV3(
                JsonSerializer.Deserialize<DiagnosticReport>(archive.ReportJson.Span, JsonOptions) ??
                throw new InvalidDataException("The validated schema-2 report JSON could not be read.")),
            _ => throw new NotSupportedException("Only validated schema-2 and schema-3 reports can be opened.")
        };
    }

    private sealed record BoundDumpChoice(UiReportHandle Report, DumpCandidate Dump);
}
