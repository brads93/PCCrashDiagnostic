using System.Text.Json.Serialization;

namespace BF6CrashDiagnostic.Core.Models;

public enum DebuggerAnalysisState
{
    NotRequested,
    DebuggerNotFound,
    BlockedWhileProtectedTargetRunning,
    InvalidDebuggerSignature,
    Completed,
    TimedOut,
    Cancelled,
    Failed
}

public enum SymbolAccessMode
{
    LocalOnly,
    MicrosoftPublicServer
}

public sealed record TargetPerformanceSample(
    DateTimeOffset TimestampUtc,
    bool TargetRunning,
    int TargetProcessCount,
    double? SystemCpuPct,
    double SystemMemoryUsedGB,
    double SystemMemoryAvailableGB,
    double SystemCommittedGB,
    double SystemCommitLimitGB,
    double SystemCommitPct,
    double? TargetWorkingSetMB,
    double? TargetPrivateMB,
    double? TargetCpuPct,
    double? TargetGpu3DPct,
    double? TargetGpuMaxEnginePct,
    double? TargetDedicatedGpuMB,
    double? TargetSharedGpuMB,
    double SampleCollectionMs);

public sealed record DebuggerAnalysis(
    DebuggerAnalysisState State,
    DateTimeOffset? StartedUtc,
    DateTimeOffset? CompletedUtc,
    SymbolAccessMode SymbolAccess,
    string DebuggerVersion,
    string DumpSha256,
    string BugcheckCode,
    IReadOnlyList<string> BugcheckParameters,
    string FailureBucket,
    string ModuleName,
    string ImageName,
    string ProcessName,
    string SymbolStatus,
    IReadOnlyList<string> StackModules,
    string Limitation,
    [property: JsonIgnore]
    string? LocalRawLogPath = null,
    DebuggerBlackboxSummary? Blackbox = null);

public sealed record SourceCoverage(
    string Source,
    CollectionState State,
    int RecordCount,
    string Detail);

public sealed record DiagnosticReportV3(
    int ReportSchemaVersion,
    string ToolVersion,
    string ProductName,
    string SessionId,
    DiagnosticMode Mode,
    DateTimeOffset StartUtc,
    DateTimeOffset EndUtc,
    string CompletionReason,
    IncidentSelection? IncidentSelection,
    TargetProfile? TargetProfile,
    SystemSnapshot? StartSnapshot,
    SystemSnapshot? EndSnapshot,
    IReadOnlyList<TargetPerformanceSample> Samples,
    IReadOnlyList<DiagnosticEvent> Events,
    IReadOnlyList<DuplicateEventGroup> EventGroups,
    IReadOnlyList<ReliabilityRecord> Reliability,
    IReadOnlyList<CrashArtifact> Artifacts,
    IReadOnlyList<DiagnosticFinding> Findings,
    IReadOnlyList<CollectionStatus> CollectionStatus,
    IReadOnlyList<SourceCoverage> SourceCoverage,
    IReadOnlyList<BugcheckRecord> Bugchecks,
    CrashReadiness? CrashReadiness,
    DumpInventory DumpInventory,
    DriverInventory? DriverInventory,
    CrashCorrelation? CrashCorrelation,
    DebuggerAnalysis? DebuggerAnalysis,
    IncidentFingerprint? IncidentFingerprint,
    string Summary,
    DumpQuality? DumpQuality = null,
    RecentChangeTimeline? RecentChanges = null,
    StorageHealthSnapshot? StorageHealth = null,
    DriverVerifierState? DriverVerifier = null);

public sealed record ReportPackageV3(
    DiagnosticReportV3 Report,
    string SessionFolder,
    string ZipPath,
    string Sha256Path,
    string Sha256);

public sealed record DiagnosticOperationResultV3(
    ReportPackageV3 Package,
    IReadOnlyList<DumpCandidate> DumpChoices,
    bool DumpSelectionRequired,
    IReadOnlyList<string> CollectionFailures);

public sealed record IncidentSearchOptions(
    DateTimeOffset StartUtc,
    DateTimeOffset EndUtc,
    TargetProfile? TargetProfile = null)
{
    public static IncidentSearchOptions LastSevenDays(TargetProfile? targetProfile = null) =>
        new(DateTimeOffset.UtcNow.AddDays(-7), DateTimeOffset.UtcNow, targetProfile);
}

public sealed record IncidentSearchResult(
    DateTimeOffset WindowStartUtc,
    DateTimeOffset WindowEndUtc,
    IReadOnlyList<IncidentCandidate> Candidates,
    IReadOnlyList<SourceCoverage> SourceCoverage,
    IReadOnlyList<CollectionStatus> CollectionStatus);

public sealed record TargetMonitorProgress(
    string Stage,
    string Message,
    TargetPerformanceSample? Sample = null,
    double? Percent = null);

public sealed record ActiveTargetSessionMarker(
    int MarkerSchemaVersion,
    string SessionId,
    int OwnerProcessId,
    DateTimeOffset StartedUtc,
    DateTimeOffset? StartBootUtc,
    DateTimeOffset LastSampleUtc,
    string SessionFolder,
    TargetProfile TargetProfile);

public sealed record TargetRecoveryCandidate(
    ActiveTargetSessionMarker Marker,
    bool BootChanged,
    string CompletionReason);
