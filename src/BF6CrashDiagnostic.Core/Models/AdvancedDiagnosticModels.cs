using System.Text.Json.Serialization;

namespace BF6CrashDiagnostic.Core.Models;

public enum MiniDumpMetadataState
{
    RecognizedKernelDump,
    ParsedUserModeMiniDump,
    Unrecognized,
    Unavailable,
    Denied,
    Invalid,
    Failed
}

public sealed record MiniDumpMetadata(
    MiniDumpMetadataState State,
    DumpFormat Format,
    string ProcessorArchitecture,
    int? ProcessorCount,
    int? WindowsMajorVersion,
    int? WindowsMinorVersion,
    int? WindowsBuildNumber,
    uint? ProcessId,
    DateTimeOffset? ProcessCreateTimeUtc,
    int? ThreadCount,
    int? ModuleCount,
    IReadOnlyList<string> StreamsRead,
    string Detail);

public sealed record CdbInstallation(
    string Path,
    string Version,
    string Source,
    bool IsMicrosoftSigned,
    bool IsX64,
    string Signer);

public sealed record WinDbgAnalysisRequest(
    DumpCandidate Dump,
    CdbInstallation Debugger,
    SymbolAccessMode SymbolAccess,
    string SymbolCachePath,
    string RawLogDirectory,
    bool MicrosoftSymbolDownloadConsent,
    TimeSpan Timeout,
    Func<bool> IsProtectedTargetRunning);

public enum ProtectedEvidenceOperation
{
    RetryNamedSource,
    CopySelectedDump,
    ApplyCrashCapturePlan,
    RestoreCrashCapturePlan,
    ApplyWerLocalDumpPlan,
    RestoreWerLocalDumpPlan
}

public enum ProtectedEvidenceSource
{
    SystemEventLog,
    ApplicationEventLog,
    WindowsMemoryDump,
    WindowsMinidumps,
    LiveKernelReports
}

public sealed record ProtectedEvidenceRequest(
    ProtectedEvidenceOperation Operation,
    ProtectedEvidenceSource? Source,
    string? DumpPath,
    long? ExpectedSizeBytes,
    DateTimeOffset? ExpectedLastWriteUtc,
    bool PrivacyConfirmed,
    bool SizeConfirmed,
    bool FreeSpaceConfirmed,
    string? ReportSessionId = null,
    string? ReportSha256 = null,
    DateTimeOffset? WindowStartUtc = null,
    DateTimeOffset? WindowEndUtc = null,
    TargetProfile? TargetProfile = null,
    CrashCapturePlan? CrashCapturePlan = null,
    WerLocalDumpPlan? WerLocalDumpPlan = null,
    string? ConfigurationReceiptId = null);

public sealed record ProtectedEvidenceProbe(
    ProtectedEvidenceSource Source,
    CollectionState State,
    int RecordCount,
    string Detail);

/// <summary>
/// Privacy-filtered metadata for one dump discovered by the one-shot helper.
/// ApprovedPath is carried only through the ACL-restricted helper channel and
/// is mapped to DumpCandidate.OriginalPath, which report serialization omits.
/// </summary>
public sealed record ProtectedDumpEvidence(
    DumpKind Kind,
    string Source,
    string Name,
    string RedactedPath,
    long SizeBytes,
    DateTimeOffset LastWriteUtc,
    DumpFormat Format,
    DumpInspectionState InspectionState,
    int HeaderBytesRead,
    bool SizePlausible,
    string Detail,
    string ApprovedPath);

/// <summary>
/// Strictly bounded evidence returned for one report-bound retry. It never
/// contains event XML, dump bytes, debugger output, or process identifiers.
/// </summary>
public sealed record ProtectedEvidenceBatch(
    int SchemaVersion,
    string ReportSessionId,
    string ReportSha256,
    ProtectedEvidenceSource Source,
    DateTimeOffset WindowStartUtc,
    DateTimeOffset WindowEndUtc,
    IReadOnlyList<DiagnosticEvent> Events,
    IReadOnlyList<ProtectedDumpEvidence> Dumps,
    IReadOnlyList<CollectionStatus> Statuses,
    bool Truncated);

public sealed record StagedDump(
    string StagingDirectory,
    string Path,
    long SizeBytes,
    string Sha256,
    string SourceType,
    DateTimeOffset CreatedUtc,
    [property: JsonIgnore]
    string? OriginalPath = null);

public sealed record ProtectedEvidenceResponse(
    bool Succeeded,
    string Message,
    ProtectedEvidenceProbe? Probe = null,
    StagedDump? StagedDump = null,
    ProtectedEvidenceBatch? EvidenceBatch = null,
    CrashCaptureReceipt? CrashCaptureReceipt = null,
    WerLocalDumpReceipt? WerLocalDumpReceipt = null,
    bool RollbackAttempted = false,
    bool RollbackSucceeded = false);

public sealed record ProtectedDumpCopyConfirmation(
    bool PrivacyConfirmed,
    bool SizeConfirmed,
    bool FreeSpaceConfirmed)
{
    public bool IsComplete => PrivacyConfirmed && SizeConfirmed && FreeSpaceConfirmed;
}

public sealed record ProtectedDumpInspection(
    DumpFormat Format,
    DumpInspectionState InspectionState,
    MiniDumpMetadata? Metadata,
    long SizeBytes,
    string Sha256,
    string Detail);

public sealed record ProtectedDumpOperationResult<T>(
    bool Succeeded,
    string Message,
    T? Value);

public sealed record ProtectedEvidenceCleanupResult(
    int StagingDirectoriesRemoved,
    int RequestArtifactsRemoved);
