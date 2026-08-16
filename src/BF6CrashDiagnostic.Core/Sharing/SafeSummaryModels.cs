using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;
using PCCrashDiagnostic.Contracts;

namespace BF6CrashDiagnostic.Core.Sharing;

public enum SafeEvidenceSignalKind
{
    BugcheckReport,
    UnexpectedPowerLoss,
    UnexpectedShutdown,
    DumpWriteFailure,
    GpuReset,
    StorageError,
    FileSystemError,
    MemoryDiagnostic,
    ApplicationCrash,
    ApplicationHang,
    ResourceExhaustion
}

public enum SafeFindingKind
{
    Bugcheck,
    HardwareError,
    DumpWriteFailure,
    GpuTimeout,
    ResourceExhaustion,
    RisingMemoryUse,
    ApplicationFailure,
    UnexpectedShutdown,
    DumpQuality,
    StorageHealthWarning,
    DriverVerifierEnabled,
    RecentSystemChanges
}

public enum SafeCoverageSource
{
    SystemEvents,
    ApplicationEvents,
    KernelEventTracing,
    ReliabilityHistory,
    CrashArtifacts,
    CrashReadiness,
    DumpInventory,
    DriverInventory,
    WindowsUpdateHistory,
    DriverInstallHistory,
    StorageHealth,
    DriverVerifier,
    SystemSnapshot,
    Unknown
}

public enum SafeSizeBucket
{
    Unknown,
    Empty,
    UnderOneMiB,
    OneToSixteenMiB,
    SixteenToTwoHundredFiftySixMiB,
    TwoHundredFiftySixMiBToOneGiB,
    OneToEightGiB,
    EightToThirtyTwoGiB,
    OverThirtyTwoGiB
}

public enum SafeStorageMediaType
{
    Unknown,
    Hdd,
    Ssd,
    Scm
}

public enum SafeStorageBusType
{
    Unknown,
    Ata,
    Sata,
    Sas,
    Nvme,
    Usb,
    Sd,
    Mmc,
    Virtual,
    Raid,
    StorageSpaces
}

public enum SafeStorageHealth
{
    Unknown,
    Healthy,
    Warning,
    Unhealthy
}

public enum SafeRecentChangeResult
{
    Unknown,
    Succeeded,
    SucceededWithErrors,
    Failed,
    InProgress
}

public enum SafeSymbolStatus
{
    Unknown,
    Loaded,
    Partial,
    Missing,
    Deferred,
    Error
}

public enum SafeDriverProvider
{
    Unknown,
    Microsoft,
    Nvidia,
    Amd,
    Intel,
    Realtek,
    Broadcom,
    Qualcomm,
    Marvell,
    MediaTek,
    Logitech,
    Corsair,
    SteelSeries,
    Asus,
    Gigabyte,
    Msi
}

public enum SafeDriverDeviceClass
{
    Unknown,
    Display,
    Hdc,
    ScsiAdapter,
    Net,
    Media,
    System,
    Processor,
    Memory,
    Usb,
    Bluetooth
}

public enum SafeMotherboardVendor
{
    Unknown,
    Asus,
    Gigabyte,
    Msi,
    Asrock,
    Dell,
    Hp,
    Lenovo,
    Acer,
    Microsoft,
    Framework,
    Supermicro
}

public enum SafeExportDestinationKind
{
    LocalFixed,
    Removable,
    OtherLocal
}

public sealed record SafeSystemFacts(
    string? CpuName,
    IReadOnlyList<string> GpuNames,
    ulong? TotalPhysicalMemoryBytes,
    string? WindowsCaption,
    string? WindowsVersion,
    string? WindowsBuild,
    string? WindowsArchitecture,
    bool PreviewBuildDetected,
    SafeMotherboardVendor MotherboardVendor = SafeMotherboardVendor.Unknown,
    string? MotherboardProduct = null,
    string? BiosVersion = null);

public sealed record SafeBugcheck(
    uint Code,
    string? CatalogName,
    IReadOnlyList<ulong?> Parameters,
    BugcheckEvidenceSource EvidenceSource);

public sealed record SafeWheaSignal(
    int EventId,
    WheaEventClassification Classification,
    WheaEvidenceCategory? Category,
    int Count);

public sealed record SafeEvidenceSignal(
    SafeEvidenceSignalKind Kind,
    int EventId,
    int Count);

public sealed record SafeReadinessFacts(
    CrashDumpMode DumpMode,
    CrashReadinessState Assessment,
    CrashCaptureActivationState ActivationState,
    bool? EventLoggingEnabled,
    bool? OverwriteEnabled,
    bool? SystemManagedPageFile,
    bool? DumpDestinationAccessible,
    SafeSizeBucket RequiredBacking,
    SafeSizeBucket AvailableDestinationSpace);

public sealed record SafeDumpFact(
    DumpKind Kind,
    DumpFormat Format,
    DumpInspectionState InspectionState,
    SafeSizeBucket Size);

public sealed record SafeDumpQualityFact(
    DumpQualityClassification Classification,
    DumpFormat Format,
    DumpChkState DumpChkState);

public sealed record SafeStorageFact(
    int Ordinal,
    SafeStorageMediaType MediaType,
    SafeStorageBusType BusType,
    SafeStorageHealth Health,
    byte? TemperatureCelsius,
    byte? WearPercent,
    bool HasReportedErrors,
    bool HasReportedHighLatency);

public sealed record SafeRecentChangeFact(
    RecentChangeKind Kind,
    string? Reference,
    SafeRecentChangeResult Result,
    bool Within24Hours,
    bool WithinSevenDays);

public sealed record SafeDriverVerifierFact(
    DriverVerifierStatusKind Status,
    uint? Flags,
    IReadOnlyList<string> VerifiedDriverBasenames,
    int OmittedDriverCount);

public sealed record SafeDriverFact(
    SafeDriverProvider Provider,
    SafeDriverDeviceClass DeviceClass,
    string? Version,
    DateOnly? DriverDateUtc,
    string? InfBasename,
    bool? IsSigned,
    int? DeviceManagerProblemCode);

public sealed record SafeDebuggerFact(
    DebuggerAnalysisState State,
    SymbolAccessMode SymbolAccess,
    string? FailureBucket,
    string? ModuleBasename,
    string? ImageBasename,
    string? ProcessBasename,
    SafeSymbolStatus SymbolStatus,
    IReadOnlyList<string> StackModuleBasenames,
    int OmittedStackModuleCount);

public sealed record SafeCoverageFact(
    SafeCoverageSource Source,
    CollectionState State,
    int RecordCount);

/// <summary>
/// A privacy-bounded, typed projection of report schema 3. No source path, identifier,
/// free-form event message, finding prose, debugger log, or dump bytes can be represented.
/// </summary>
public sealed record SafeSummaryV1(
    int FormatVersion,
    string GeneratorVersion,
    ProductFeatureProfile GeneratorProfile,
    string SourceReportVersion,
    IncidentKind IncidentKind,
    DateTimeOffset? IncidentTimeUtc,
    string? TargetExecutable,
    SafeSystemFacts? System,
    IReadOnlyList<SafeBugcheck> Bugchecks,
    IReadOnlyList<SafeWheaSignal> WheaSignals,
    IReadOnlyList<SafeEvidenceSignal> EvidenceSignals,
    SafeReadinessFacts? CrashReadiness,
    IReadOnlyList<SafeDumpFact> Dumps,
    SafeDumpQualityFact? DumpQuality,
    IReadOnlyList<SafeStorageFact> Storage,
    IReadOnlyList<SafeRecentChangeFact> RecentChanges,
    IReadOnlyList<SafeDriverFact> Drivers,
    SafeDriverVerifierFact? DriverVerifier,
    SafeDebuggerFact? Debugger,
    IReadOnlyList<SafeCoverageFact> Coverage,
    IReadOnlyList<SafeFindingKind> Findings,
    bool ValuesWereOmitted);

public sealed record SafeSummaryPreview(
    string PreviewToken,
    string Text,
    string SuggestedFileName,
    DateTimeOffset ExpiresUtc,
    IReadOnlyList<string> IncludedCategories,
    IReadOnlyList<string> ExcludedCategories);

public sealed record SafeSummaryExportResult(
    string DestinationFileName,
    long BytesWritten,
    SafeExportDestinationAssessment Destination);

public sealed record SafeExportDestinationAssessment(
    SafeExportDestinationKind Kind,
    bool IsSyncManaged,
    bool RequiresPrivacyAcknowledgement,
    string Warning);
