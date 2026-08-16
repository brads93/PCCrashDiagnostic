using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace BF6CrashDiagnostic.Core.Models;

public enum IncidentKind
{
    Unknown,
    Bugcheck,
    UnexpectedRestart,
    HardwareError,
    GpuTimeout,
    ResourceExhaustion,
    ApplicationCrash,
    ApplicationHang
}

public enum IncidentSelectionMethod
{
    UserSelected,
    Automatic,
    ManualTime,
    RecoveredSession
}

public enum IncidentEvidenceOrigin
{
    Unknown,
    WindowsEventLog,
    ReliabilityMonitor,
    MonitorObservation,
    ManualTime
}

public enum BootSessionBoundaryKind
{
    StartMarker,
    CleanEndMarker,
    UnexpectedEndMarker
}

public enum BootSessionReconstructionConfidence
{
    Unavailable,
    Partial,
    Corroborated
}

public enum BugcheckEvidenceSource
{
    Unknown,
    WindowsErrorReporting,
    KernelPower
}

public enum CrashDumpMode
{
    Unknown = -1,
    None = 0,
    CompleteMemory = 1,
    KernelMemory = 2,
    SmallMemory = 3,
    AutomaticMemory = 7,
    ActiveMemory = 10
}

public enum CrashReadinessState
{
    Ready,
    Configured = Ready,
    Limited,
    AtRisk,
    Off,
    PendingRestart,
    Unavailable
}

public enum DumpKind
{
    Unknown,
    WindowsMinidump,
    WindowsMemoryDump,
    LiveKernelDump,
    ApplicationDump
}

public enum DumpFormat
{
    Unknown,
    MiniDump,
    PageDump32,
    PageDump64
}

public enum DumpInspectionState
{
    Recognized,
    Unrecognized,
    Unavailable,
    Denied,
    Error
}

public enum CrashCorrelationBasis
{
    None,
    ExactRecordedPath,
    ExactFileName,
    TimestampProximity,
    UserSelected
}

public sealed record TargetProfile(
    string Id,
    string DisplayName,
    IReadOnlyList<string> ProcessNames,
    IReadOnlyList<string> RelatedProcessNames,
    IReadOnlyList<string> ApplicationEventSignals,
    IReadOnlyList<string> ArtifactSignals,
    IReadOnlyList<string> ReliabilitySignals,
    string OutputLabel,
    bool BlockSensitiveOperationsWhileRunning = true,
    TargetPrivacyRules? PrivacyRules = null)
{
    public static TargetProfile Battlefield6 { get; } = new(
        "battlefield-6",
        "Battlefield 6",
        ["BF6"],
        ["EADesktop", "EALauncher", "EAAntiCheat", "Javelin"],
        ["BF6", "Battlefield 6", "Battlefield6", "Javelin", "EAAntiCheat", "EA AntiCheat"],
        ["BF6", "Battlefield", "Javelin", "EAAntiCheat", "EADesktop", "EALauncher"],
        ["BF6", "Battlefield 6", "Battlefield6", "Javelin", "EAAntiCheat", "EA AntiCheat"],
        "BF6",
        BlockSensitiveOperationsWhileRunning: true,
        TargetPrivacyRules.Strict);

    public TargetPrivacyRules EffectivePrivacyRules => PrivacyRules ?? TargetPrivacyRules.Strict;

    public static TargetProfile FromExecutable(string executablePath, string? displayName = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        string fileName = Path.GetFileName(executablePath.Trim());
        if (!Path.GetExtension(fileName).Equals(".exe", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("The selected target must be a Windows executable.", nameof(executablePath));
        }

        string processName = Path.GetFileNameWithoutExtension(fileName);
        string label = string.IsNullOrWhiteSpace(displayName) ? processName : displayName.Trim();
        string idMaterial = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(fileName.ToUpperInvariant())))[..16].ToLowerInvariant();
        return new TargetProfile(
            "executable-" + idMaterial,
            label,
            [processName],
            [],
            [processName, fileName],
            [processName, fileName],
            [processName, fileName],
            processName,
            BlockSensitiveOperationsWhileRunning: true,
            TargetPrivacyRules.Strict);
    }

    public bool MatchesProcessName(string? processName) =>
        MatchesName(ProcessNames, processName) || MatchesName(RelatedProcessNames, processName);

    public bool MatchesApplicationEvidence(string? text) => MatchesText(ApplicationEventSignals, text);

    public bool MatchesArtifactName(string? text) => MatchesText(ArtifactSignals, text);

    public bool MatchesReliabilityEvidence(string? text) => MatchesText(ReliabilitySignals, text);

    private static bool MatchesName(IReadOnlyList<string> names, string? candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate))
        {
            return false;
        }

        string normalized = Path.GetFileNameWithoutExtension(candidate.Trim());
        return names.Any(name => string.Equals(
            Path.GetFileNameWithoutExtension(name),
            normalized,
            StringComparison.OrdinalIgnoreCase));
    }

    private static bool MatchesText(IReadOnlyList<string> signals, string? text) =>
        !string.IsNullOrWhiteSpace(text) &&
        signals.Any(signal => !string.IsNullOrWhiteSpace(signal) &&
                              ContainsBoundedSignal(text, signal));

    private static bool ContainsBoundedSignal(string text, string signal)
    {
        int searchStart = 0;
        while (searchStart < text.Length)
        {
            int index = text.IndexOf(signal, searchStart, StringComparison.OrdinalIgnoreCase);
            if (index < 0)
            {
                return false;
            }

            int end = index + signal.Length;
            bool leftBoundary = index == 0 || !char.IsLetterOrDigit(text[index - 1]);
            bool rightBoundary = end == text.Length || !char.IsLetterOrDigit(text[end]);
            if (leftBoundary && rightBoundary)
            {
                return true;
            }

            searchStart = index + 1;
        }

        return false;
    }
}

public sealed record TargetPrivacyRules(
    bool ReadProcessMemory,
    bool ReadModules,
    bool ReadCommandLines,
    bool ReadInputs,
    bool ReadAntiCheatData,
    bool ExportProcessIds)
{
    public static TargetPrivacyRules Strict { get; } = new(
        ReadProcessMemory: false,
        ReadModules: false,
        ReadCommandLines: false,
        ReadInputs: false,
        ReadAntiCheatData: false,
        ExportProcessIds: false);
}

public sealed record IncidentFingerprint
{
    public IncidentFingerprint(string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(value);
        if (value.Length != 64 || value.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new ArgumentException("An incident fingerprint must be a 64-character hexadecimal SHA-256 value.", nameof(value));
        }

        Value = value.ToLowerInvariant();
    }

    public string Value { get; }

    public static IncidentFingerprint Create(
        IncidentKind kind,
        DateTimeOffset timeUtc,
        string source,
        int eventId,
        string? targetProfileId = null,
        string? discriminator = null)
    {
        string identity = string.Join(
            '|',
            kind.ToString().ToUpperInvariant(),
            timeUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
            Normalize(source),
            eventId.ToString(CultureInfo.InvariantCulture),
            Normalize(targetProfileId),
            Normalize(discriminator));
        return new IncidentFingerprint(
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity))).ToLowerInvariant());
    }

    public override string ToString() => Value;

    private static string Normalize(string? value) =>
        string.IsNullOrWhiteSpace(value) ? string.Empty : value.Trim().ToUpperInvariant();
}

public sealed record IncidentCandidate(
    IncidentFingerprint Fingerprint,
    DateTimeOffset TimeUtc,
    IncidentKind Kind,
    string Title,
    string Source,
    int EventId,
    string? TargetProfileId,
    string? BugcheckCode,
    string? DumpFileName,
    int EvidencePriority,
    int SupportingRecordCount,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    IncidentEvidenceOrigin EvidenceOrigin = IncidentEvidenceOrigin.Unknown);

public sealed record IncidentSelection(
    IncidentCandidate Candidate,
    DateTimeOffset WindowStartUtc,
    DateTimeOffset WindowEndUtc,
    IncidentSelectionMethod Method);

public sealed record BugcheckRecord(
    DateTimeOffset TimeUtc,
    BugcheckEvidenceSource EvidenceSource,
    string ProviderName,
    int EventId,
    string RawCode,
    uint? Code,
    string NormalizedCode,
    IReadOnlyList<ulong?> Parameters,
    string? DumpFileName,
    string? RedactedDumpPath,
    [property: JsonIgnore]
    string? OriginalDumpPath = null,
    string? BugcheckName = null);

public sealed record BootSessionRecord(
    DateTimeOffset TimeUtc,
    string ProviderName,
    int EventId,
    BootSessionBoundaryKind BoundaryKind);

public sealed record BootSessionContext(
    DateTimeOffset IncidentTimeUtc,
    DateTimeOffset? StartUtc,
    DateTimeOffset? EndUtc,
    bool? IncidentOccurredInSession,
    string StartEvidence,
    string EndEvidence,
    BootSessionReconstructionConfidence Confidence,
    IReadOnlyList<BootSessionRecord> Records,
    string Limitation);

public sealed record CrashReadiness(
    DateTimeOffset CapturedUtc,
    CrashDumpMode DumpMode,
    int? RawDumpMode,
    bool? EventLoggingEnabled,
    bool? AutoRebootEnabled,
    bool? OverwriteEnabled,
    bool? AlwaysKeepMemoryDump,
    bool DedicatedDumpFileConfigured,
    string DumpFileLocation,
    string MinidumpDirectory,
    int PageFileEntryCount,
    bool? SystemManagedPageFile,
    long? SystemDriveFreeBytes,
    long? SystemDriveTotalBytes,
    CrashReadinessState Assessment = CrashReadinessState.Unavailable,
    string AssessmentDetail = "Crash-dump readiness could not be determined.",
    bool? ActiveDumpFilterEnabled = null,
    int RuntimePageFileCount = 0,
    long? RuntimePageFileAllocatedBytes = null,
    bool? DumpDestinationAccessible = null,
    long? DumpDestinationFreeBytes = null,
    long? DumpDestinationTotalBytes = null,
    bool? MinidumpDestinationAccessible = null,
    long? MinidumpDestinationFreeBytes = null,
    long? MinidumpDestinationTotalBytes = null,
    CrashCaptureActivationState ActivationState = CrashCaptureActivationState.Unknown,
    long? PhysicalMemoryBytes = null,
    long? RequiredDumpBackingBytes = null,
    long? RecommendedDestinationFreeBytes = null,
    DateTimeOffset? CurrentBootUtc = null,
    DateTimeOffset? ConfigurationAppliedUtc = null,
    bool RuntimePageFileStateAvailable = false,
    long? ConfiguredPageFileMinimumBytes = null,
    long? ConfiguredPageFileMaximumBytes = null,
    long? DedicatedDumpConfiguredBytes = null,
    long? DedicatedDumpActualBytes = null,
    long? DedicatedDumpDestinationFreeBytes = null,
    bool? AutomaticPageFileManagementEnabled = null,
    long? RecommendedDumpBackingBytes = null,
    int BootVolumePageFileEntryCount = 0,
    int BootVolumeRuntimePageFileCount = 0,
    long? BootVolumeConfiguredPageFileMinimumBytes = null,
    long? BootVolumeConfiguredPageFileMaximumBytes = null,
    long? BootVolumeRuntimePageFileAllocatedBytes = null,
    bool? DedicatedDumpDestinationAccessible = null,
    bool? ExistingDumpMayBeOverwritten = null,
    long? ExistingDumpFileBytes = null);

public sealed record CrashReadinessCollection(
    CrashReadiness Readiness,
    IReadOnlyList<CollectionStatus> Statuses);

public sealed record DumpCandidate(
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
    [property: JsonIgnore]
    string? OriginalPath = null,
    MiniDumpMetadata? Metadata = null);

public sealed record DumpInventory(
    IReadOnlyList<DumpCandidate> Candidates,
    IReadOnlyList<CollectionStatus> Statuses);

public sealed record CrashCorrelation(
    IncidentFingerprint Incident,
    BugcheckRecord? Bugcheck,
    DumpCandidate? SelectedDump,
    CrashCorrelationBasis Basis,
    TimeSpan? TimeDelta,
    IReadOnlyList<DumpCandidate> RelatedDumps,
    string Limitation);

public sealed record DriverDeviceRecord(
    string DeviceClass,
    string DeviceName,
    string Manufacturer,
    string DriverProvider,
    string DriverVersion,
    DateTimeOffset? DriverDateUtc,
    string InfName,
    bool? IsSigned,
    string Signer,
    int? DeviceManagerProblemCode = null,
    string DeviceManagerProblemState = "Unknown");

public sealed record DriverInventory(
    DateTimeOffset CapturedUtc,
    IReadOnlyList<DriverDeviceRecord> Drivers,
    IReadOnlyList<CollectionStatus> Statuses);
