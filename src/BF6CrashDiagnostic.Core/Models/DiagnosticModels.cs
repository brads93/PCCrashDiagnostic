using System.Text.Json.Serialization;

namespace BF6CrashDiagnostic.Core.Models;

public enum DiagnosticMode
{
    Retrospective,
    Monitor,
    Recovered
}

public enum CollectionState
{
    Available,
    Unavailable,
    Denied,
    TimedOut,
    Error
}

public enum FindingSeverity
{
    Critical,
    Warning,
    Information,
    Context
}

public enum FindingConfidence
{
    High,
    Medium,
    Low
}

public sealed record CollectionStatus(
    string Source,
    CollectionState State,
    string Detail);

public sealed record CrashAnchor(
    DateTimeOffset TimeUtc,
    string Source,
    int EventId,
    string Description,
    string? BugCheckCode = null,
    string? DumpPath = null,
    int Priority = 0);

public sealed record DiagnosticEvent(
    DateTimeOffset TimeUtc,
    string LogName,
    string ProviderName,
    Guid? ProviderGuid,
    int EventId,
    byte? Level,
    string LevelName,
    string Message,
    IReadOnlyDictionary<string, string> Data);

public sealed record DuplicateEventGroup(
    string Key,
    string ProviderName,
    Guid? ProviderGuid,
    int EventId,
    string Message,
    int Count,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    IReadOnlyList<DateTimeOffset> OccurrencesUtc);

public sealed record ReliabilityRecord(
    DateTimeOffset TimeUtc,
    string SourceName,
    string ProductName,
    string EventIdentifier,
    string Message);

public sealed record CrashArtifact(
    string Kind,
    string Name,
    string RedactedPath,
    long SizeBytes,
    DateTimeOffset LastWriteUtc,
    bool MayContainSensitiveData,
    [property: JsonIgnore]
    string? OriginalPath = null);

public sealed record MemoryModuleInfo(
    ulong CapacityBytes,
    uint? SpeedMtPerSecond,
    uint? ConfiguredSpeedMtPerSecond,
    string Manufacturer,
    string PartNumber);

public sealed record GpuInfo(
    string Name,
    string DriverVersion,
    ulong? AdapterRamBytes);

public sealed record SystemSnapshot(
    DateTimeOffset CapturedUtc,
    string ComputerManufacturer,
    string ComputerModel,
    string MotherboardManufacturer,
    string MotherboardProduct,
    string BiosVersion,
    string BiosReleaseDate,
    string CpuName,
    ulong TotalPhysicalMemoryBytes,
    IReadOnlyList<MemoryModuleInfo> MemoryModules,
    IReadOnlyList<GpuInfo> Gpus,
    string WindowsCaption,
    string WindowsVersion,
    string WindowsBuild,
    string WindowsArchitecture,
    string WindowsChannel,
    bool PreviewBuildDetected,
    DateTimeOffset? LastBootUtc);

public sealed record PerformanceSample(
    DateTimeOffset TimestampUtc,
    bool BF6Running,
    int? BF6Pid,
    string BF6ProcessName,
    double? SystemCpuPct,
    double SystemMemoryUsedGB,
    double SystemMemoryAvailableGB,
    double SystemCommittedGB,
    double SystemCommitLimitGB,
    double SystemCommitPct,
    double? BF6WorkingSetMB,
    double? BF6PrivateMB,
    double? BF6CpuPct,
    double? BF6Gpu3DPct,
    double? BF6GpuMaxEnginePct,
    double? BF6DedicatedGpuMB,
    double? BF6SharedGpuMB,
    double SampleCollectionMs);

public sealed record DiagnosticFinding(
    string Id,
    int Rank,
    FindingSeverity Severity,
    FindingConfidence Confidence,
    string Category,
    string Title,
    string Evidence,
    string Meaning,
    string DoesNotProve,
    string NextCheck,
    int OccurrenceCount = 1,
    DateTimeOffset? FirstSeenUtc = null,
    DateTimeOffset? LastSeenUtc = null);

public sealed record DiagnosticReport(
    int ReportSchemaVersion,
    string ToolVersion,
    string SessionId,
    DiagnosticMode Mode,
    DateTimeOffset StartUtc,
    DateTimeOffset EndUtc,
    string CompletionReason,
    CrashAnchor? Anchor,
    SystemSnapshot? StartSnapshot,
    SystemSnapshot? EndSnapshot,
    IReadOnlyList<PerformanceSample> Samples,
    IReadOnlyList<DiagnosticEvent> Events,
    IReadOnlyList<DuplicateEventGroup> EventGroups,
    IReadOnlyList<ReliabilityRecord> Reliability,
    IReadOnlyList<CrashArtifact> Artifacts,
    IReadOnlyList<DiagnosticFinding> Findings,
    IReadOnlyList<CollectionStatus> CollectionStatus,
    string Summary);

public sealed record ReportPackage(
    DiagnosticReport Report,
    string SessionFolder,
    string ZipPath,
    string Sha256Path,
    string Sha256);

public sealed record DiagnosticOperationResult(
    ReportPackage Package,
    string? EligibleDumpPath,
    IReadOnlyList<string> CollectionFailures);

public sealed record DiagnosticProgress(
    string Stage,
    string Message,
    double? Percent = null,
    string? CollectionFailure = null);

public sealed record ActiveSessionMarker(
    int MarkerSchemaVersion,
    string SessionId,
    int OwnerProcessId,
    DateTimeOffset StartedUtc,
    DateTimeOffset? StartBootUtc,
    DateTimeOffset LastSampleUtc,
    string SessionFolder,
    string ProcessName,
    DiagnosticMode Mode);

public sealed record RecoveryCandidate(
    ActiveSessionMarker Marker,
    bool BootChanged,
    DateTimeOffset EvidenceEndUtc,
    string CompletionReason);
