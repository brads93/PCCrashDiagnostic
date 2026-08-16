using System.Text.Json.Serialization;

namespace BF6CrashDiagnostic.Core.Models;

public enum DumpInternalQualityState
{
    Valid,
    HeaderOnly,
    Invalid,
    Unavailable,
    Denied,
    Failed
}

public enum DumpChkState
{
    NotRequested,
    NotFound,
    Rejected,
    Passed,
    Failed,
    TimedOut,
    Cancelled,
    Error
}

[JsonConverter(typeof(JsonStringEnumConverter<DumpQualityClassification>))]
public enum DumpQualityClassification
{
    Recognized,
    Valid,
    Truncated,
    Corrupt,
    Inaccessible,
    AnalysisUnavailable
}

public sealed record DumpChkInstallation(
    string Path,
    string Version,
    string Source,
    bool IsMicrosoftSigned,
    bool IsX64,
    string Signer);

public sealed record DumpQuality(
    DateTimeOffset CheckedUtc,
    DumpQualityClassification Classification,
    DumpFormat Format,
    DumpInternalQualityState InternalState,
    bool SignatureRecognized,
    bool SizePlausible,
    bool? MiniDumpDirectoryBoundsValid,
    DumpChkState DumpChkState,
    string DumpChkVersion,
    string Detail);

public sealed record DumpQualityRequest(
    DumpCandidate Dump,
    bool RunDumpChk = false,
    DumpChkInstallation? DumpChk = null,
    TimeSpan? Timeout = null);

public enum RecentChangeKind
{
    WindowsUpdate,
    DriverInstallation
}

public sealed record RecentSystemChange(
    DateTimeOffset TimeUtc,
    RecentChangeKind Kind,
    string Title,
    string Operation,
    string Result,
    string ErrorCode,
    TimeSpan? TimeBeforeIncident = null,
    bool Within24Hours = false,
    bool WithinSevenDays = false);

public sealed record RecentChangeTimeline(
    DateTimeOffset CapturedUtc,
    DateTimeOffset WindowStartUtc,
    DateTimeOffset WindowEndUtc,
    IReadOnlyList<RecentSystemChange> Records,
    IReadOnlyList<CollectionStatus> CollectionStatus);

public sealed record StorageHealthRecord(
    int Ordinal,
    string Model,
    string MediaType,
    string BusType,
    string FirmwareVersion,
    string HealthStatus,
    IReadOnlyList<string> OperationalStatus,
    ulong? SizeBytes,
    byte? TemperatureCelsius,
    byte? MaximumTemperatureCelsius,
    byte? WearPercent,
    ulong? ReadErrorsTotal,
    ulong? ReadErrorsUncorrected,
    ulong? WriteErrorsTotal,
    ulong? WriteErrorsUncorrected,
    ulong? ReadLatencyMaximumMilliseconds,
    ulong? WriteLatencyMaximumMilliseconds,
    ulong? FlushLatencyMaximumMilliseconds,
    ushort? PowerOnHours);

public sealed record StorageHealthSnapshot(
    DateTimeOffset CapturedUtc,
    IReadOnlyList<StorageHealthRecord> Devices,
    IReadOnlyList<CollectionStatus> CollectionStatus);

[JsonConverter(typeof(JsonStringEnumConverter<DriverVerifierStatusKind>))]
public enum DriverVerifierStatusKind
{
    Disabled,
    Enabled,
    Indeterminate,
    Unavailable,
    Rejected,
    TimedOut,
    Cancelled,
    Failed
}

public sealed record DriverVerifierState(
    DateTimeOffset CapturedUtc,
    DriverVerifierStatusKind Status,
    string Flags,
    IReadOnlyList<string> VerifiedDriverBasenames,
    string Detail);

public sealed record DebuggerBlackboxBootStatus(
    bool? LastBootSucceeded,
    bool? LastBootShutdown,
    bool? SleepInProgress,
    bool? ConnectedStandbyInProgress,
    bool? UserShutdownInProgress,
    bool? SystemShutdownInProgress,
    bool? PowerButtonShutdownInProgress,
    uint? BootAttemptCount,
    uint? LastBootId,
    uint? LastSuccessfulShutdownBootId,
    uint? LastReportedAbnormalShutdownBootId);

public sealed record DebuggerServiceControlRequest(
    string ServiceName,
    uint? ControlCode);

public sealed record DebuggerBlackboxSummary(
    IReadOnlyList<string> AvailableSources,
    DebuggerBlackboxBootStatus? BootStatus,
    IReadOnlyList<DebuggerServiceControlRequest> ServiceControlRequests);
