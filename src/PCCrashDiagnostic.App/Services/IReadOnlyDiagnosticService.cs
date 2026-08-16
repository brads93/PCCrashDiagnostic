using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;
using BF6CrashDiagnostic.Core.Sharing;
using PCCrashDiagnostic.LocalTools;

namespace PCCrashDiagnostic.App.Services;

public sealed record UiCollectedReport(
    UiReportHandle Handle,
    DiagnosticOperationResultV3 Result);

public sealed record UiHistoryReport(
    UiReportHandle Handle,
    string SessionId,
    DateTimeOffset StartUtc,
    IncidentKind Kind,
    string TargetName,
    IReadOnlyList<string> StopCodes);

public sealed record UiDumpChoice(
    string ChoiceToken,
    string DisplayText);

public sealed record UiLocalToolOptions(
    DebuggerAvailability Debugger,
    DumpCheckerAvailability DumpChecker,
    IReadOnlyList<UiDumpChoice> DumpChoices);

public sealed class UiExportDestination
{
    internal UiExportDestination(string fullPath, SafeExportDestinationAssessment assessment)
    {
        FullPath = fullPath;
        Assessment = assessment;
    }

    internal string FullPath { get; }

    public SafeExportDestinationAssessment Assessment { get; }
}

public interface IReadOnlyDiagnosticService : IDisposable
{
    Task<IncidentSearchResult> FindRecentIncidentsAsync(
        IncidentSearchOptions options,
        CancellationToken cancellationToken = default);

    Task<UiCollectedReport> AnalyzeSelectedIncidentAsync(
        IncidentSelection selection,
        TargetProfile? targetProfile = null,
        IProgress<DiagnosticProgress>? progress = null,
        CancellationToken cancellationToken = default);

    Task<UiCollectedReport> MonitorSelectedTargetAsync(
        TargetProfile targetProfile,
        IProgress<TargetMonitorProgress>? progress = null,
        CancellationToken cancellationToken = default);

    Task<UiCollectedReport> OpenPreviousReportAsync(
        string reportPath,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<UiHistoryReport>> GetHistoryAsync(CancellationToken cancellationToken = default);

    Task<UiCollectedReport> OpenHistoryReportAsync(
        UiHistoryReport report,
        CancellationToken cancellationToken = default);

    Task<SafeSummaryPreview> CreateSupportSummaryPreviewAsync(
        UiReportHandle report,
        CancellationToken cancellationToken = default);

    Task<string> GetExactSupportSummaryTextAsync(
        string previewToken,
        CancellationToken cancellationToken = default);

    UiExportDestination PrepareSupportSummaryDestination(string destinationPath);

    Task<SafeSummaryExportResult> ExportSupportSummaryAsync(
        string previewToken,
        UiExportDestination destination,
        CancellationToken cancellationToken = default);

    Task<TechnicalReportExportTicket> PrepareTechnicalReportExportAsync(
        UiReportHandle report,
        CancellationToken cancellationToken = default);

    Task<TechnicalReportExportResult> ExportTechnicalReportAsync(
        string ticket,
        UiExportDestination destination,
        CancellationToken cancellationToken = default);

    UiExportDestination PrepareTechnicalReportDestination(string destinationPath);

    Task<UiLocalToolOptions> GetLocalToolOptionsAsync(
        UiReportHandle report,
        CancellationToken cancellationToken = default);

    Task<UiCollectedReport> RunDumpQualityAsync(
        UiReportHandle report,
        string dumpChoiceToken,
        bool runInstalledDumpChk,
        IProgress<DiagnosticProgress>? progress = null,
        CancellationToken cancellationToken = default);

    Task<UiCollectedReport> RunWinDbgAnalysisAsync(
        UiReportHandle report,
        string dumpChoiceToken,
        bool allowMicrosoftSymbolDownload,
        IProgress<DiagnosticProgress>? progress = null,
        CancellationToken cancellationToken = default);

    bool RevokeSupportSummary(string previewToken);

    ReportDeletionPreview PreviewRecycleReport(UiReportHandle report);

    Task<ReportDeletionPreview> PreviewRecycleAllHistoryAsync(
        CancellationToken cancellationToken = default);

    Task<ReportDeletionResult> RecycleAsync(
        string previewToken,
        CancellationToken cancellationToken = default);
}
