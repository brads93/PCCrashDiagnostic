using BF6CrashDiagnostic.App.Models;

namespace BF6CrashDiagnostic.App.Services;

internal interface IDiagnosticService
{
    bool SupportsCrashPreparation => false;

    bool SupportsPerAppCrashCaptureApply => false;

    bool SupportsDumpCheck => false;

    Task<UiSystemSnapshot> GetSystemSnapshotAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<UiDiagnosticResult>> RecoverInterruptedSessionsAsync(
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken);

    Task<IReadOnlyList<UiIncidentCandidate>> FindRecentIncidentsAsync(
        UiIncidentSearchOptions options,
        CancellationToken cancellationToken);

    Task<UiDiagnosticResult> AnalyzeIncidentAsync(
        UiIncidentSelection selection,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken);

    Task<UiDiagnosticResult> MonitorTargetAsync(
        UiTargetProfile target,
        IProgress<UiDiagnosticProgress> progress,
        IProgress<UiTelemetrySample> telemetry,
        CancellationToken cancellationToken);

    Task<UiIncidentHistory> OpenPreviousReportsAsync(CancellationToken cancellationToken);

    Task<int> GetLegacyV2ReportCountAsync(CancellationToken cancellationToken);

    Task<int> CompleteLegacyV2ImportOfferAsync(bool importReports, CancellationToken cancellationToken);

    Task<UiDiagnosticResult> LoadPreviousReportAsync(
        UiPreviousReport report,
        CancellationToken cancellationToken);

    Task<string> PackageCrashDumpAsync(
        UiDiagnosticResult result,
        UiDumpChoice dump,
        UiProtectedDumpConsent? protectedDumpConsent,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken);

    Task<UiProtectedOperationResult> InspectProtectedDumpAsync(
        UiDiagnosticResult result,
        UiDumpChoice dump,
        UiProtectedDumpConsent consent,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken);

    Task<UiDiagnosticResult> RetryProtectedEvidenceSourceAsync(
        UiDiagnosticResult result,
        UiProtectedEvidenceSourceChoice source,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken);

    Task<UiDiagnosticResult> RunDebuggerAnalysisAsync(
        UiDiagnosticResult result,
        UiDumpChoice dump,
        bool allowMicrosoftSymbolDownload,
        UiProtectedDumpConsent? protectedDumpConsent,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken);

    Task<UiDiagnosticResult> RunDumpCheckAsync(
        UiDiagnosticResult result,
        UiDumpChoice dump,
        UiProtectedDumpConsent? protectedDumpConsent,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken) =>
        Task.FromException<UiDiagnosticResult>(
            new NotSupportedException("DumpChk is not available in this build."));

    Task<UiRestorableConfigurationReceipts> DiscoverRestorableConfigurationReceiptsAsync(
        CancellationToken cancellationToken) =>
        Task.FromResult(UiRestorableConfigurationReceipts.Empty);

    Task<UiCrashPreparationPreview> PreviewCrashCapturePreparationAsync(
        UiDiagnosticResult result,
        UiCrashPreparationPreset preset,
        bool includePerAppCapture,
        CancellationToken cancellationToken) =>
        Task.FromResult(UiCrashPreparationPreview.Unavailable(
            "Crash-capture preparation is not available in this build."));

    Task<UiCrashPreparationOutcome> PrepareCrashCaptureAsync(
        UiDiagnosticResult result,
        UiCrashPreparationPreview preview,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken) =>
        Task.FromResult(new UiCrashPreparationOutcome(
            UiCrashPreparationState.Unavailable,
            "Crash-capture preparation is not available in this build."));

    Task<UiCrashPreparationOutcome> RestoreCrashCaptureAsync(
        string receiptId,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken) =>
        Task.FromResult(new UiCrashPreparationOutcome(
            UiCrashPreparationState.Unavailable,
            "Crash-capture restore is not available in this build."));

    Task<UiCrashPreparationPreview> PreviewPerAppCrashCaptureAsync(
        UiDiagnosticResult result,
        bool ordinaryAppConfirmed,
        CancellationToken cancellationToken) =>
        Task.FromResult(UiCrashPreparationPreview.Unavailable(
            "Per-app crash capture is not available in this build."));

    Task<UiCrashPreparationOutcome> EnablePerAppCrashCaptureAsync(
        UiDiagnosticResult result,
        UiCrashPreparationPreview preview,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken) =>
        Task.FromResult(new UiCrashPreparationOutcome(
            UiCrashPreparationState.Unavailable,
            "Per-app crash capture is not available in this build."));

    Task<UiCrashPreparationOutcome> RestorePerAppCrashCaptureAsync(
        string receiptId,
        IProgress<UiDiagnosticProgress> progress,
        CancellationToken cancellationToken) =>
        Task.FromResult(new UiCrashPreparationOutcome(
            UiCrashPreparationState.Unavailable,
            "Per-app crash-capture restore is not available in this build."));
}
