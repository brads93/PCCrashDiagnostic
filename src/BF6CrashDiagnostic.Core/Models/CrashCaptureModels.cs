namespace BF6CrashDiagnostic.Core.Models;

public enum CrashCapturePreset
{
    AutomaticMemoryDump
}

public enum CrashCaptureSetting
{
    CrashDumpEnabled,
    FilterPages,
    DumpFile,
    MinidumpDirectory,
    EventLogging,
    OverwriteExistingDump,
    AutomaticManagedPagefile
}

public enum CrashCaptureActivationState
{
    Unknown,
    Active,
    PendingRestart,
    Restored,
    FailedRolledBack,
    FailedRollbackIncomplete
}

public sealed record PageFileConfigurationSnapshot(
    bool AutomaticManagementStateKnown,
    bool AutomaticManagementEnabled,
    bool PagingFilesValueExists,
    IReadOnlyList<string> PagingFiles);

public sealed record CrashCaptureChange(
    CrashCaptureSetting Setting,
    bool PreviousValueExists,
    string? PreviousValue,
    bool DesiredValueExists,
    string? DesiredValue,
    bool RequiresRestart,
    PageFileConfigurationSnapshot? PreviousPageFileConfiguration = null,
    int? PreviousRegistryValueKind = null,
    int? DesiredRegistryValueKind = null,
    PageFileConfigurationSnapshot? AppliedPageFileConfiguration = null);

public sealed record WerLocalDumpPlan(
    int SchemaVersion,
    string PlanId,
    string ReportSessionId,
    string ReportSha256,
    DateTimeOffset CreatedUtc,
    DateTimeOffset ExpiresUtc,
    string ExecutableName,
    bool PreviousKeyExists,
    bool PreviousDumpTypeExists,
    int? PreviousDumpType,
    bool PreviousDumpCountExists,
    int? PreviousDumpCount,
    bool PreviousDumpFolderExists,
    string? PreviousDumpFolder,
    int DesiredDumpType,
    int DesiredDumpCount,
    string DesiredDumpFolder,
    TargetProfile? TargetProfile = null,
    int? PreviousDumpTypeRegistryValueKind = null,
    int? PreviousDumpCountRegistryValueKind = null,
    int? PreviousDumpFolderRegistryValueKind = null);

public sealed record CrashCapturePlan(
    int SchemaVersion,
    string PlanId,
    string ReportSessionId,
    string ReportSha256,
    DateTimeOffset CreatedUtc,
    DateTimeOffset ExpiresUtc,
    CrashCapturePreset Preset,
    IReadOnlyList<CrashCaptureChange> Changes,
    CrashReadiness BeforeReadiness,
    bool RequiresElevation,
    bool RequiresRestart,
    WerLocalDumpPlan? WerLocalDumpPlan = null,
    TargetProfile? TargetProfile = null);

public sealed record WerLocalDumpReceipt(
    int SchemaVersion,
    string ReceiptId,
    string PlanId,
    string ReportSessionId,
    string ReportSha256,
    DateTimeOffset AppliedUtc,
    string ExecutableName,
    bool PreviousKeyExists,
    bool PreviousDumpTypeExists,
    int? PreviousDumpType,
    bool PreviousDumpCountExists,
    int? PreviousDumpCount,
    bool PreviousDumpFolderExists,
    string? PreviousDumpFolder,
    int AppliedDumpType,
    int AppliedDumpCount,
    string AppliedDumpFolder,
    bool Restored,
    DateTimeOffset? RestoredUtc = null,
    TargetProfile? TargetProfile = null,
    int? PreviousDumpTypeRegistryValueKind = null,
    int? PreviousDumpCountRegistryValueKind = null,
    int? PreviousDumpFolderRegistryValueKind = null);

public sealed record CrashCaptureReceipt(
    int SchemaVersion,
    string ReceiptId,
    string PlanId,
    string ReportSessionId,
    string ReportSha256,
    DateTimeOffset AppliedUtc,
    DateTimeOffset? BootUtcAtApply,
    IReadOnlyList<CrashCaptureChange> AppliedChanges,
    CrashCaptureActivationState ActivationState,
    WerLocalDumpReceipt? WerLocalDumpReceipt,
    bool Restored,
    DateTimeOffset? RestoredUtc = null,
    TargetProfile? TargetProfile = null);

public sealed record CrashCapturePreparationResult(
    bool Succeeded,
    string Message,
    CrashCapturePlan? Plan,
    CrashCaptureReceipt? Receipt,
    WerLocalDumpReceipt? WerReceipt,
    CrashReadiness? BeforeReadiness,
    CrashReadiness? AfterReadiness,
    CrashCaptureActivationState ActivationState,
    bool RollbackAttempted,
    bool RollbackSucceeded);

public sealed record RestorableConfigurationReceipts(
    CrashCaptureReceipt? CrashCaptureReceipt,
    IReadOnlyList<WerLocalDumpReceipt> WerLocalDumpReceipts,
    IReadOnlyList<string> Warnings);
