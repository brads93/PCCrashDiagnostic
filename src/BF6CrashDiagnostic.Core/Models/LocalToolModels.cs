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

public enum DebuggerAvailabilityState
{
    Available,
    NotFound
}

/// <summary>
/// Path-free runtime status suitable for reports and UI. The discovered
/// executable path remains local to the debugger-launch boundary.
/// </summary>
public sealed record DebuggerAvailability(
    DebuggerAvailabilityState State,
    string Version,
    string Source,
    string Detail)
{
    public bool IsAvailable => State == DebuggerAvailabilityState.Available;
}

public sealed record WinDbgAnalysisRequest(
    DumpCandidate Dump,
    CdbInstallation Debugger,
    SymbolAccessMode SymbolAccess,
    string SymbolCachePath,
    string RawLogDirectory,
    bool MicrosoftSymbolDownloadConsent,
    TimeSpan Timeout,
    Func<bool> IsProtectedTargetRunning);
