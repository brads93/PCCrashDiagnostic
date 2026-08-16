using System.Globalization;
using System.Security;
using System.Text.RegularExpressions;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;
using Microsoft.Win32;

namespace BF6CrashDiagnostic.Core.Collectors;

/// <summary>
/// Reads configured and active Windows crash-capture prerequisites. This
/// collector is read-only; UAC configuration is performed only by the fixed
/// one-shot helper after an explicit preview.
/// </summary>
public sealed partial class CrashReadinessCollector
{
    private const string CrashControlPath = @"SYSTEM\CurrentControlSet\Control\CrashControl";
    private const string MemoryManagementPath = @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";
    private const long CompleteDumpOverheadBytes = 257L * 1024 * 1024;
    private const long ConservativeSmallDumpBackingBytes = 2L * 1024 * 1024;
    private const long AutomaticDumpRamCapBytes = 32L * 1024 * 1024 * 1024;

    private readonly TimeProvider _timeProvider;
    private readonly ICrashCaptureConfigurationStore _configurationStore;
    private readonly CrashCaptureReceiptStore _receiptStore;

    public CrashReadinessCollector(TimeProvider? timeProvider = null)
        : this(
            timeProvider ?? TimeProvider.System,
            new WindowsCrashCaptureConfigurationStore(),
            new CrashCaptureReceiptStore())
    {
    }

    internal CrashReadinessCollector(
        TimeProvider timeProvider,
        ICrashCaptureConfigurationStore configurationStore,
        CrashCaptureReceiptStore receiptStore)
    {
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _configurationStore = configurationStore ?? throw new ArgumentNullException(nameof(configurationStore));
        _receiptStore = receiptStore ?? throw new ArgumentNullException(nameof(receiptStore));
    }

    public Task<CrashReadinessCollection> CollectAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => Collect(cancellationToken), cancellationToken);

    private CrashReadinessCollection Collect(CancellationToken cancellationToken)
    {
        var statuses = new List<CollectionStatus>();
        var crashValues = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        var malformedRegistryValues = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        object? pagingFiles = null;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using RegistryKey? crashControl = Registry.LocalMachine.OpenSubKey(CrashControlPath, writable: false);
            if (crashControl is null)
            {
                statuses.Add(new CollectionStatus(
                    "Crash readiness/CrashControl",
                    CollectionState.Unavailable,
                    "The Windows crash-control registry key was unavailable."));
            }
            else
            {
                var presentNames = crashControl.GetValueNames().ToHashSet(StringComparer.OrdinalIgnoreCase);
                foreach (string name in CrashValueNames)
                {
                    crashValues[name] = crashControl.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                    if (presentNames.Contains(name) && !IsExpectedCrashValueKind(name, crashControl.GetValueKind(name)))
                    {
                        malformedRegistryValues.Add(name);
                    }
                }

                statuses.Add(new CollectionStatus(
                    "Crash readiness/CrashControl",
                    CollectionState.Available,
                    "Read the configured Windows crash-dump type, destinations, and retention settings."));
            }

            cancellationToken.ThrowIfCancellationRequested();
            using RegistryKey? memoryManagement = Registry.LocalMachine.OpenSubKey(MemoryManagementPath, writable: false);
            if (memoryManagement is null)
            {
                statuses.Add(new CollectionStatus(
                    "Crash readiness/Page file configuration",
                    CollectionState.Unavailable,
                    "The configured Windows page-file list was unavailable."));
            }
            else
            {
                pagingFiles = memoryManagement.GetValue(
                    "PagingFiles",
                    null,
                    RegistryValueOptions.DoNotExpandEnvironmentNames);
                if (memoryManagement.GetValueNames().Contains("PagingFiles", StringComparer.OrdinalIgnoreCase) &&
                    memoryManagement.GetValueKind("PagingFiles") != RegistryValueKind.MultiString)
                {
                    malformedRegistryValues.Add("PagingFiles");
                }
                statuses.Add(new CollectionStatus(
                    "Crash readiness/Page file configuration",
                    CollectionState.Available,
                    "Read configured page-file presence and sizing mode; page-file paths were not retained."));
            }
        }

        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            statuses.Add(Denied("Crash readiness/Registry"));
        }
        catch (SecurityException)
        {
            statuses.Add(Denied("Crash readiness/Registry"));
        }
        catch (IOException exception)
        {
            statuses.Add(Error("Crash readiness/Registry", exception));
        }
        catch (PlatformNotSupportedException)
        {
            statuses.Add(new CollectionStatus(
                "Crash readiness/Registry",
                CollectionState.Unavailable,
                "Windows registry data is unavailable on this platform."));
        }

        if (malformedRegistryValues.Count != 0)
        {
            statuses.Add(new CollectionStatus(
                "Crash readiness/Registry value types",
                CollectionState.Unavailable,
                "One or more crash-capture registry values used an unexpected Windows registry type."));
        }

        PageFileRuntimeSnapshot? runtime = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            runtime = _configurationStore.ReadPageFileRuntime();
            statuses.Add(new CollectionStatus(
                "Crash readiness/Active page files",
                CollectionState.Available,
                $"Windows reports {runtime.RuntimePageFileCount} active page file{(runtime.RuntimePageFileCount == 1 ? string.Empty : "s")}; paths were not retained."));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (IsReadFailure(exception))
        {
            statuses.Add(new CollectionStatus(
                "Crash readiness/Active page files",
                CollectionState.Unavailable,
                "Windows did not expose active page-file allocation or boot state."));
        }

        (long? systemFree, long? systemTotal) = ProbeSystemDrive(statuses, cancellationToken);
        DestinationCapacity? dumpDestination = ProbeDestination(
            Text(crashValues, "DumpFile"),
            pathIsFile: true,
            "Crash readiness/Dump destination",
            statuses,
            cancellationToken);
        DestinationCapacity? minidumpDestination = ProbeDestination(
            Text(crashValues, "MinidumpDir"),
            pathIsFile: false,
            "Crash readiness/Minidump destination",
            statuses,
            cancellationToken);
        string? dedicatedDumpPath = Text(crashValues, "DedicatedDumpFile");
        DestinationCapacity? dedicatedDumpDestination = dedicatedDumpPath is null
            ? null
            : ProbeDestination(
                dedicatedDumpPath,
                pathIsFile: true,
                "Crash readiness/Dedicated dump file",
                statuses,
                cancellationToken);

        CrashCaptureReceipt? latestReceipt = null;
        bool? latestReceiptMatchesConfiguration = null;
        try
        {
            latestReceipt = _receiptStore.TryReadLatestCrash();
            if (latestReceipt is not null)
            {
                latestReceiptMatchesConfiguration = IsUsableReceiptShape(latestReceipt) &&
                                                    ReceiptConfigurationMatches(latestReceipt);
                if (latestReceiptMatchesConfiguration == false)
                {
                    statuses.Add(new CollectionStatus(
                        "Crash readiness/Activation receipt",
                        CollectionState.Unavailable,
                        "The saved preparation receipt no longer matches the current Windows crash-capture settings."));
                }
            }
        }
        catch (Exception exception) when (IsReadFailure(exception))
        {
            if (latestReceipt is not null)
            {
                latestReceiptMatchesConfiguration = false;
            }

            statuses.Add(new CollectionStatus(
                "Crash readiness/Activation receipt",
                CollectionState.Unavailable,
                "The private local activation receipt could not be read."));
        }

        CrashReadiness readiness = CreateReadiness(
            _timeProvider.GetUtcNow(),
            crashValues,
            pagingFiles,
            systemFree,
            systemTotal,
            runtime,
            dumpDestination,
            minidumpDestination,
            latestReceipt,
            dedicatedDumpDestination,
            malformedRegistryValues,
            latestReceiptMatchesConfiguration);
        return new CrashReadinessCollection(readiness, statuses.ToArray());
    }

    internal static CrashReadiness CreateReadiness(
        DateTimeOffset capturedUtc,
        IReadOnlyDictionary<string, object?> crashValues,
        object? pagingFiles,
        long? systemDriveFreeBytes,
        long? systemDriveTotalBytes,
        PageFileRuntimeSnapshot? runtime = null,
        DestinationCapacity? dumpDestination = null,
        DestinationCapacity? minidumpDestination = null,
        CrashCaptureReceipt? latestReceipt = null,
        DestinationCapacity? dedicatedDumpDestination = null,
        IReadOnlyCollection<string>? malformedRegistryValues = null,
        bool? latestReceiptMatchesConfiguration = null)
    {
        ArgumentNullException.ThrowIfNull(crashValues);
        int? rawMode = Integer(crashValues, "CrashDumpEnabled");
        bool? filterPages = Boolean(crashValues, "FilterPages");
        CrashDumpMode mode = NormalizeDumpMode(rawMode, filterPages);
        string[] pageFileEntries = PageFileEntries(pagingFiles);
        string[] bootVolumePageFileEntries = pageFileEntries.Where(IsBootVolumePageFile).ToArray();
        PageFileCapacity configuredPageFileCapacity = ParsePageFileCapacity(bootVolumePageFileEntries);
        bool? configuredSystemManaged = pageFileEntries.Length == 0
            ? pagingFiles is null ? null : false
            : bootVolumePageFileEntries.Any(IsSystemManagedPageFile);
        string? rawDumpFile = Text(crashValues, "DumpFile");
        string? rawMinidumpDirectory = Text(crashValues, "MinidumpDir");
        string dumpFile = EvidencePathRedactor.Redact(rawDumpFile) ?? "Unavailable";
        string minidumpDirectory = EvidencePathRedactor.Redact(rawMinidumpDirectory) ?? "Unavailable";
        bool dedicatedDump = !string.IsNullOrWhiteSpace(Text(crashValues, "DedicatedDumpFile"));
        long? dedicatedConfiguredBytes = MegabytesToBytes(Integer(crashValues, "DumpFileSize"));
        long? dedicatedActualBytes = NonNegative(dedicatedDumpDestination?.ActualFileBytes);
        long? physicalMemory = NonNegative(runtime?.PhysicalMemoryBytes);
        long? requiredBacking = RequiredBacking(mode, physicalMemory);
        long? recommendedBacking = RecommendedBacking(
            mode,
            physicalMemory,
            requiredBacking,
            runtime?.RuntimeAllocatedBytes);
        long? recommendedFree = recommendedBacking;
        bool receiptConflict = latestReceipt is not null && latestReceiptMatchesConfiguration == false;
        (CrashCaptureActivationState activation, DateTimeOffset? changedUtc) = DetermineActivation(
            latestReceipt,
            runtime?.BootUtc,
            receiptConflict);
        (CrashReadinessState assessment, string assessmentDetail) = Assess(
            mode,
            Boolean(crashValues, "LogEvent"),
            Boolean(crashValues, "Overwrite"),
            dedicatedDump,
            bootVolumePageFileEntries.Length,
            configuredSystemManaged == true || runtime?.AutomaticManagementEnabled == true,
            runtime,
            dumpFile,
            minidumpDirectory,
            dumpDestination,
            minidumpDestination,
            requiredBacking,
            recommendedBacking,
            recommendedFree,
            configuredPageFileCapacity.MaximumBytes,
            dedicatedConfiguredBytes,
            dedicatedActualBytes,
            dedicatedDumpDestination?.Accessible,
            NonNegative(dedicatedDumpDestination?.FreeBytes),
            activation,
            malformedRegistryValues is null || malformedRegistryValues.Count == 0,
            receiptConflict);

        return new CrashReadiness(
            capturedUtc.ToUniversalTime(),
            mode,
            rawMode,
            Boolean(crashValues, "LogEvent"),
            Boolean(crashValues, "AutoReboot"),
            Boolean(crashValues, "Overwrite"),
            Boolean(crashValues, "AlwaysKeepMemoryDump"),
            dedicatedDump,
            dumpFile,
            minidumpDirectory,
            pageFileEntries.Length,
            configuredSystemManaged,
            NonNegative(systemDriveFreeBytes),
            NonNegative(systemDriveTotalBytes),
            assessment,
            assessmentDetail,
            filterPages,
            Math.Max(0, runtime?.RuntimePageFileCount ?? 0),
            NonNegative(runtime?.RuntimeAllocatedBytes),
            dumpDestination?.Accessible,
            NonNegative(dumpDestination?.FreeBytes),
            NonNegative(dumpDestination?.TotalBytes),
            minidumpDestination?.Accessible,
            NonNegative(minidumpDestination?.FreeBytes),
            NonNegative(minidumpDestination?.TotalBytes),
            activation,
            physicalMemory,
            requiredBacking,
            recommendedFree,
            runtime?.BootUtc,
            changedUtc,
            runtime is not null,
            configuredPageFileCapacity.MinimumBytes,
            configuredPageFileCapacity.MaximumBytes,
            dedicatedConfiguredBytes,
            dedicatedActualBytes,
            NonNegative(dedicatedDumpDestination?.FreeBytes),
            runtime?.AutomaticManagementEnabled,
            recommendedBacking,
            bootVolumePageFileEntries.Length,
            runtime?.BootVolumeRuntimePageFileCount ?? 0,
            configuredPageFileCapacity.MinimumBytes,
            configuredPageFileCapacity.MaximumBytes,
            NonNegative(runtime?.BootVolumeRuntimeAllocatedBytes),
            dedicatedDumpDestination?.Accessible,
            dumpDestination?.ActualFileBytes is > 0 ? Boolean(crashValues, "Overwrite") : false,
            NonNegative(dumpDestination?.ActualFileBytes));
    }

    private static CrashDumpMode NormalizeDumpMode(int? rawMode, bool? filterPages) => rawMode switch
    {
        0 => CrashDumpMode.None,
        1 when filterPages == true => CrashDumpMode.ActiveMemory,
        1 => CrashDumpMode.CompleteMemory,
        2 => CrashDumpMode.KernelMemory,
        3 => CrashDumpMode.SmallMemory,
        7 => CrashDumpMode.AutomaticMemory,
        // Some Windows APIs expose Active Memory Dump as the synthetic value
        // 10 even though CrashControl represents it as 1 + FilterPages=1.
        10 => CrashDumpMode.ActiveMemory,
        _ => CrashDumpMode.Unknown
    };

    private static (CrashReadinessState State, string Detail) Assess(
        CrashDumpMode mode,
        bool? eventLogging,
        bool? overwriteEnabled,
        bool dedicatedDump,
        int configuredPageFileCount,
        bool? systemManagedPageFile,
        PageFileRuntimeSnapshot? runtime,
        string dumpFile,
        string minidumpDirectory,
        DestinationCapacity? dumpDestination,
        DestinationCapacity? minidumpDestination,
        long? requiredBacking,
        long? recommendedBacking,
        long? recommendedFree,
        long? configuredPageFileMaximumBytes,
        long? dedicatedConfiguredBytes,
        long? dedicatedActualBytes,
        bool? dedicatedDumpDestinationAccessible,
        long? dedicatedDumpDestinationFreeBytes,
        CrashCaptureActivationState activation,
        bool registryValuesWellFormed,
        bool receiptConflict)
    {
        if (!registryValuesWellFormed)
        {
            return (CrashReadinessState.Unavailable, "One or more crash-capture registry values use an unexpected Windows registry type.");
        }

        if (mode == CrashDumpMode.None)
        {
            return (CrashReadinessState.Off, "Windows crash-dump writing is turned off.");
        }

        if (mode == CrashDumpMode.Unknown)
        {
            return (CrashReadinessState.Unavailable, "Windows did not expose a recognized crash-dump type.");
        }

        if (receiptConflict)
        {
            return (CrashReadinessState.Limited, "The saved crash-capture preparation no longer matches the current Windows settings.");
        }

        if (activation == CrashCaptureActivationState.PendingRestart)
        {
            return (CrashReadinessState.PendingRestart, "Crash-capture settings changed after the current Windows boot; restart is required.");
        }

        DestinationCapacity? selectedDestination = mode == CrashDumpMode.SmallMemory
            ? minidumpDestination
            : dumpDestination;
        string selectedLocation = mode == CrashDumpMode.SmallMemory ? minidumpDirectory : dumpFile;
        if (selectedLocation == "Unavailable")
        {
            return (CrashReadinessState.Limited, "The configured dump destination could not be confirmed.");
        }

        if (selectedDestination?.Accessible == false)
        {
            return (CrashReadinessState.AtRisk, "The configured dump destination directory is not currently accessible.");
        }

        if (dedicatedDump && dedicatedDumpDestinationAccessible == false)
        {
            return (CrashReadinessState.AtRisk, "The dedicated dump-file destination is not currently accessible.");
        }

        if (mode != CrashDumpMode.SmallMemory && overwriteEnabled == false &&
            selectedDestination?.ActualFileBytes is > 0)
        {
            return (CrashReadinessState.AtRisk, "A dump already exists at the configured destination and overwrite is disabled.");
        }

        bool backingPresent = dedicatedDump || configuredPageFileCount > 0 ||
                              runtime?.BootVolumeRuntimePageFileCount > 0;
        if (!backingPresent)
        {
            return (CrashReadinessState.AtRisk, "No configured or active page file and no dedicated dump file was reported.");
        }

        if (!dedicatedDump && configuredPageFileCount > 0 &&
            runtime?.BootVolumeRuntimeStateKnown == true &&
            runtime.BootVolumeRuntimePageFileCount == 0)
        {
            return (CrashReadinessState.AtRisk, "A boot-volume page file is configured but is not active in the current Windows boot; restart or verify the page-file configuration.");
        }

        long? backingCapacity = dedicatedDump
            ? MaxKnown(dedicatedActualBytes, dedicatedConfiguredBytes)
            : MaxKnown(runtime?.BootVolumeRuntimeAllocatedBytes, configuredPageFileMaximumBytes);
        long? backingTarget = requiredBacking ?? recommendedBacking;
        bool backingCanGrow = !dedicatedDump && systemManagedPageFile == true && backingPresent;
        if (backingTarget is > 0 && backingCapacity is null && !backingCanGrow)
        {
            return (CrashReadinessState.AtRisk, "The crash-dump backing capacity could not be confirmed against the conservative estimate.");
        }

        if (backingTarget is > 0 && backingCapacity is { } capacity &&
            capacity < backingTarget && !backingCanGrow)
        {
            return (CrashReadinessState.AtRisk, "The configured crash-dump backing capacity is below the conservative estimate for this dump type.");
        }

        if (dedicatedDump && backingTarget is > 0 &&
            dedicatedDumpDestinationFreeBytes is { } dedicatedFree && dedicatedFree < backingTarget)
        {
            return (CrashReadinessState.AtRisk, "The dedicated dump-file volume has less free space than the conservative crash-capture estimate.");
        }

        if (recommendedFree is > 0 && selectedDestination?.FreeBytes is { } free && free < recommendedFree)
        {
            return (CrashReadinessState.AtRisk, "The dump destination has less free space than the conservative crash-capture estimate.");
        }

        if (eventLogging == false)
        {
            return (CrashReadinessState.Limited, "Crash-event logging is disabled even though dump writing is configured.");
        }

        if (overwriteEnabled is null && mode != CrashDumpMode.SmallMemory)
        {
            return (CrashReadinessState.Limited, "Windows did not expose whether an existing dump may be overwritten.");
        }

        if (mode == CrashDumpMode.SmallMemory)
        {
            return (CrashReadinessState.Limited, "Small memory dumps are enabled; they contain the least crash context.");
        }

        if (mode is CrashDumpMode.KernelMemory or CrashDumpMode.AutomaticMemory &&
            systemManagedPageFile != true && !dedicatedDump && configuredPageFileMaximumBytes is > 0)
        {
            return (CrashReadinessState.Limited, "A fixed-size page file is present, but Windows documents kernel-dump capacity as workload-dependent.");
        }

        if (runtime is null || selectedDestination?.Accessible is null)
        {
            return (CrashReadinessState.Limited, "The configured dump type is usable, but an active page-file or destination check was unavailable.");
        }

        return (CrashReadinessState.Ready, "The configured dump type, active backing, and destination checks are ready.");
    }

    private static long? RequiredBacking(CrashDumpMode mode, long? physicalMemoryBytes)
    {
        if (mode == CrashDumpMode.SmallMemory)
        {
            return ConservativeSmallDumpBackingBytes;
        }

        if ((mode is CrashDumpMode.CompleteMemory or CrashDumpMode.ActiveMemory) && physicalMemoryBytes is { } memory)
        {
            try
            {
                return checked(memory + CompleteDumpOverheadBytes);
            }
            catch (OverflowException)
            {
                return null;
            }
        }

        // Microsoft documents kernel and automatic requirements as dependent on
        // actual kernel virtual-memory use, so the collector does not invent a
        // fixed minimum for those modes.
        return null;
    }

    private static long? RecommendedBacking(
        CrashDumpMode mode,
        long? physicalMemoryBytes,
        long? requiredBacking,
        long? runtimeAllocatedBytes)
    {
        if (requiredBacking is > 0)
        {
            return requiredBacking;
        }

        if (mode == CrashDumpMode.AutomaticMemory)
        {
            return RecommendedAutomaticBackingBytes(physicalMemoryBytes);
        }

        return mode == CrashDumpMode.KernelMemory && runtimeAllocatedBytes is > 0
            ? runtimeAllocatedBytes
            : null;
    }

    internal static long? RecommendedAutomaticBackingBytes(long? physicalMemoryBytes)
    {
        if (physicalMemoryBytes is not > 0)
        {
            return null;
        }

        return Math.Min(physicalMemoryBytes.Value, AutomaticDumpRamCapBytes);
    }

    internal static bool NeedsSystemManagedPageFileForAutomatic(CrashCaptureEnvironmentSnapshot environment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        if (environment.RuntimePageFiles.AutomaticManagementEnabled == true)
        {
            return false;
        }

        long? recommendation = RecommendedAutomaticBackingBytes(environment.RuntimePageFiles.PhysicalMemoryBytes);
        bool bootVolumeDetailAvailable = environment.BootVolumeConfiguredPageFilePresent.HasValue ||
                                         environment.RuntimePageFiles.BootVolumeRuntimePageFileCount > 0 ||
                                         environment.RuntimePageFiles.BootVolumeRuntimeAllocatedBytes.HasValue;
        long? pageFileCapacity = MaxKnown(
            bootVolumeDetailAvailable
                ? environment.RuntimePageFiles.BootVolumeRuntimeAllocatedBytes
                : environment.RuntimePageFiles.RuntimeAllocatedBytes,
            bootVolumeDetailAvailable
                ? environment.BootVolumeConfiguredPageFileMaximumBytes
                : environment.ConfiguredPageFileMaximumBytes);
        bool pageFileSufficient = recommendation is > 0 &&
                                  pageFileCapacity is { } pageCapacity &&
                                  pageCapacity >= recommendation.Value;
        bool dedicatedSufficient = HasUsableDedicatedBacking(environment, recommendation);

        // A fixed/dedicated backing source is only accepted when both the
        // RAM-aware recommendation and the available capacity are known and
        // the latter meets the recommendation. Otherwise the fixed helper can
        // offer Windows-managed page-file sizing without guessing a custom size.
        return !pageFileSufficient && !dedicatedSufficient;
    }

    internal static bool AutomaticManagementEnabledWithoutBootBacking(
        CrashCaptureEnvironmentSnapshot environment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        long? recommendation = RecommendedAutomaticBackingBytes(
            environment.RuntimePageFiles.PhysicalMemoryBytes);
        return environment.RuntimePageFiles.AutomaticManagementEnabled == true &&
               environment.RuntimePageFiles.BootVolumeRuntimeStateKnown &&
               environment.RuntimePageFiles.BootVolumeRuntimePageFileCount == 0 &&
               environment.BootVolumeConfiguredPageFilePresent == false &&
               !HasUsableDedicatedBacking(environment, recommendation);
    }

    private static bool HasUsableDedicatedBacking(
        CrashCaptureEnvironmentSnapshot environment,
        long? recommendation)
    {
        if (!environment.DedicatedDumpFileConfigured ||
            environment.DedicatedDumpDestinationAccessible != true ||
            recommendation is not > 0)
        {
            return false;
        }

        if (environment.DedicatedDumpActualBytes is { } allocated &&
            allocated >= recommendation.Value)
        {
            return true;
        }

        return environment.DedicatedDumpConfiguredBytes is { } configured &&
               configured >= recommendation.Value &&
               environment.DedicatedDumpDestinationFreeBytes is { } freeBytes &&
               freeBytes >= recommendation.Value;
    }

    private static (CrashCaptureActivationState State, DateTimeOffset? ChangedUtc) DetermineActivation(
        CrashCaptureReceipt? receipt,
        DateTimeOffset? bootUtc,
        bool receiptConflict)
    {
        if (receipt is null)
        {
            return (CrashCaptureActivationState.Active, null);
        }

        DateTimeOffset changedUtc = receipt.Restored
            ? receipt.RestoredUtc ?? receipt.AppliedUtc
            : receipt.AppliedUtc;
        if (receiptConflict)
        {
            return (CrashCaptureActivationState.Unknown, changedUtc);
        }

        bool pending = bootUtc is null
            ? receipt.ActivationState == CrashCaptureActivationState.PendingRestart
            : changedUtc >= bootUtc.Value;
        return (pending ? CrashCaptureActivationState.PendingRestart : CrashCaptureActivationState.Active, changedUtc);
    }

    private bool ReceiptConfigurationMatches(CrashCaptureReceipt receipt)
    {
        foreach (CrashCaptureChange change in receipt.AppliedChanges)
        {
            StoredConfigurationValue expected = receipt.Restored
                ? new StoredConfigurationValue(
                    change.PreviousValueExists,
                    change.PreviousValue,
                    change.PreviousRegistryValueKind)
                : new StoredConfigurationValue(
                    change.DesiredValueExists,
                    change.DesiredValue,
                    change.DesiredRegistryValueKind);
            if (_configurationStore.ReadCrashSetting(change.Setting) != expected)
            {
                return false;
            }

            if (change.Setting == CrashCaptureSetting.AutomaticManagedPagefile)
            {
                PageFileConfigurationSnapshot? expectedPageFile = receipt.Restored
                    ? change.PreviousPageFileConfiguration
                    : change.AppliedPageFileConfiguration;
                if (expectedPageFile is null ||
                    !PageFileConfigurationsEqual(
                        expectedPageFile,
                        _configurationStore.ReadPageFileConfiguration()))
                {
                    return false;
                }
            }
        }

        if (receipt.WerLocalDumpReceipt is not { } wer)
        {
            return true;
        }

        WerConfigurationSnapshot expectedWer = receipt.Restored
            ? new WerConfigurationSnapshot(
                wer.PreviousKeyExists,
                new StoredConfigurationValue(wer.PreviousDumpTypeExists, OptionalNumber(wer.PreviousDumpType), wer.PreviousDumpTypeRegistryValueKind),
                new StoredConfigurationValue(wer.PreviousDumpCountExists, OptionalNumber(wer.PreviousDumpCount), wer.PreviousDumpCountRegistryValueKind),
                new StoredConfigurationValue(wer.PreviousDumpFolderExists, wer.PreviousDumpFolder, wer.PreviousDumpFolderRegistryValueKind))
            : new WerConfigurationSnapshot(
                true,
                new StoredConfigurationValue(true, wer.AppliedDumpType.ToString(CultureInfo.InvariantCulture), (int)RegistryValueKind.DWord),
                new StoredConfigurationValue(true, wer.AppliedDumpCount.ToString(CultureInfo.InvariantCulture), (int)RegistryValueKind.DWord),
                new StoredConfigurationValue(true, wer.AppliedDumpFolder, (int)RegistryValueKind.ExpandString));
        return WerConfigurationComparison.Matches(
            _configurationStore.ReadWerSettings(wer.ExecutableName),
            expectedWer);
    }

    private static bool IsUsableReceiptShape(CrashCaptureReceipt receipt)
    {
        if (receipt.SchemaVersion != 1 || receipt.AppliedChanges is null ||
            receipt.AppliedChanges.Count > Enum.GetValues<CrashCaptureSetting>().Length ||
            receipt.AppliedChanges.Select(change => change.Setting).Distinct().Count() != receipt.AppliedChanges.Count)
        {
            return false;
        }

        foreach (CrashCaptureChange change in receipt.AppliedChanges)
        {
            if (!Enum.IsDefined(change.Setting))
            {
                return false;
            }

            if (change.Setting == CrashCaptureSetting.AutomaticManagedPagefile)
            {
                PageFileConfigurationSnapshot? prior = change.PreviousPageFileConfiguration;
                PageFileConfigurationSnapshot? applied = change.AppliedPageFileConfiguration;
                if (prior?.PagingFiles is null || applied?.PagingFiles is null)
                {
                    return false;
                }
            }
        }

        return true;
    }

    private static bool PageFileConfigurationsEqual(
        PageFileConfigurationSnapshot left,
        PageFileConfigurationSnapshot right) =>
        left.AutomaticManagementStateKnown == right.AutomaticManagementStateKnown &&
        left.AutomaticManagementEnabled == right.AutomaticManagementEnabled &&
        left.PagingFilesValueExists == right.PagingFilesValueExists &&
        left.PagingFiles.SequenceEqual(right.PagingFiles, StringComparer.Ordinal);

    private static string? OptionalNumber(int? value) => value?.ToString(CultureInfo.InvariantCulture);

    private static DestinationCapacity? ProbeDestination(
        string? configuredPath,
        bool pathIsFile,
        string source,
        ICollection<CollectionStatus> statuses,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            statuses.Add(new CollectionStatus(source, CollectionState.Unavailable, "No destination path was configured."));
            return null;
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!WindowsCrashCaptureConfigurationStore.TryNormalizeLocalFixedDrivePath(
                    configuredPath,
                    out string fullPath,
                    out DriveInfo? drive))
            {
                throw new ArgumentException("Only a local fixed-drive destination can be probed.");
            }

            PathSafety.EnsureNoReparseComponents(fullPath);
            string? directory = pathIsFile ? Path.GetDirectoryName(fullPath) : fullPath;
            string? root = Path.GetPathRoot(fullPath);
            if (string.IsNullOrWhiteSpace(directory) || string.IsNullOrWhiteSpace(root))
            {
                throw new ArgumentException("The configured path had no local filesystem root.");
            }

            var result = new DestinationCapacity(
                Directory.Exists(directory),
                drive!.AvailableFreeSpace,
                drive.TotalSize,
                pathIsFile && File.Exists(fullPath) ? new FileInfo(fullPath).Length : null);
            statuses.Add(new CollectionStatus(
                source,
                result.Accessible == true ? CollectionState.Available : CollectionState.Unavailable,
                result.Accessible == true
                    ? "The configured local destination and its free space were checked."
                    : "The configured destination directory is not currently accessible."));
            return result;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SecurityException or ArgumentException or NotSupportedException)
        {
            statuses.Add(new CollectionStatus(source, CollectionState.Unavailable, "The configured local destination could not be checked."));
            return new DestinationCapacity(false, null, null, null);
        }
    }

    private static (long? FreeBytes, long? TotalBytes) ProbeSystemDrive(
        ICollection<CollectionStatus> statuses,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            string? root = Path.GetPathRoot(Environment.SystemDirectory);
            if (string.IsNullOrWhiteSpace(root))
            {
                throw new ArgumentException("The Windows system-drive root was unavailable.");
            }

            var drive = new DriveInfo(root);
            statuses.Add(new CollectionStatus(
                "Crash readiness/System drive",
                CollectionState.Available,
                "Read system-drive capacity; volume labels and identifiers were not requested."));
            return (drive.AvailableFreeSpace, drive.TotalSize);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SecurityException or ArgumentException)
        {
            statuses.Add(new CollectionStatus(
                "Crash readiness/System drive",
                CollectionState.Unavailable,
                "The Windows system-drive capacity could not be read."));
            return (null, null);
        }
    }

    private static readonly string[] CrashValueNames =
    [
        "CrashDumpEnabled",
        "FilterPages",
        "LogEvent",
        "AutoReboot",
        "Overwrite",
        "AlwaysKeepMemoryDump",
        "DedicatedDumpFile",
        "DumpFileSize",
        "DumpFile",
        "MinidumpDir"
    ];

    private static bool IsExpectedCrashValueKind(string name, RegistryValueKind kind) => name switch
    {
        "CrashDumpEnabled" or "FilterPages" or "LogEvent" or "AutoReboot" or
            "Overwrite" or "AlwaysKeepMemoryDump" or "DumpFileSize" => kind == RegistryValueKind.DWord,
        "DumpFile" or "MinidumpDir" => kind == RegistryValueKind.ExpandString,
        // DedicatedDumpFile has appeared as either a literal or expandable path
        // across supported Windows configurations; both remain unambiguous.
        "DedicatedDumpFile" => kind is RegistryValueKind.String or RegistryValueKind.ExpandString,
        _ => false
    };

    private static int? Integer(IReadOnlyDictionary<string, object?> values, string name)
    {
        object? value = Value(values, name);
        if (value is null)
        {
            return null;
        }

        try
        {
            return Convert.ToInt32(value, CultureInfo.InvariantCulture);
        }
        catch (Exception exception) when (exception is FormatException or InvalidCastException or OverflowException)
        {
            return null;
        }
    }

    private static bool? Boolean(IReadOnlyDictionary<string, object?> values, string name)
    {
        int? value = Integer(values, name);
        return value is null ? null : value.Value != 0;
    }

    private static string? Text(IReadOnlyDictionary<string, object?> values, string name)
    {
        string? text = Convert.ToString(Value(values, name), CultureInfo.InvariantCulture)?.Trim();
        return string.IsNullOrWhiteSpace(text) ? null : text;
    }

    private static object? Value(IReadOnlyDictionary<string, object?> values, string name) =>
        values.FirstOrDefault(pair => pair.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;

    private static string[] PageFileEntries(object? value) => value switch
    {
        string[] entries => entries.Where(entry => !string.IsNullOrWhiteSpace(entry)).Select(entry => entry.Trim()).ToArray(),
        string entry when !string.IsNullOrWhiteSpace(entry) => [entry.Trim()],
        _ => []
    };

    private static bool IsSystemManagedPageFile(string entry)
    {
        if (entry.StartsWith(@"?:\pagefile.sys", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        Match match = PageFileSizeRegex().Match(entry);
        return match.Success && match.Groups["minimum"].Value == "0" && match.Groups["maximum"].Value == "0";
    }

    private static bool IsBootVolumePageFile(string entry)
    {
        string trimmed = entry.Trim();
        if (trimmed.StartsWith(@"?:\pagefile.sys", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        Match match = PageFileSizeRegex().Match(trimmed);
        string candidate = match.Success
            ? trimmed[..match.Index].Trim().Trim('"')
            : trimmed.Trim('"');
        string? systemRoot = Path.GetPathRoot(Environment.SystemDirectory);
        string? candidateRoot;
        try
        {
            candidateRoot = Path.GetPathRoot(Environment.ExpandEnvironmentVariables(candidate));
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            return false;
        }

        return !string.IsNullOrWhiteSpace(systemRoot) &&
               string.Equals(candidateRoot, systemRoot, StringComparison.OrdinalIgnoreCase);
    }

    private static PageFileCapacity ParsePageFileCapacity(IEnumerable<string> entries)
    {
        long minimumBytes = 0;
        long maximumBytes = 0;
        bool foundSizedEntry = false;
        bool dynamic = false;
        foreach (string entry in entries)
        {
            if (entry.StartsWith(@"?:\pagefile.sys", StringComparison.OrdinalIgnoreCase))
            {
                dynamic = true;
                continue;
            }

            Match match = PageFileSizeRegex().Match(entry);
            if (!match.Success ||
                !long.TryParse(match.Groups["minimum"].Value, out long minimumMb) ||
                !long.TryParse(match.Groups["maximum"].Value, out long maximumMb))
            {
                continue;
            }

            if (minimumMb == 0 && maximumMb == 0)
            {
                dynamic = true;
                continue;
            }

            try
            {
                minimumBytes = checked(minimumBytes + minimumMb * 1024L * 1024L);
                maximumBytes = checked(maximumBytes + maximumMb * 1024L * 1024L);
                foundSizedEntry = true;
            }
            catch (OverflowException)
            {
                return new PageFileCapacity(null, null);
            }
        }

        return foundSizedEntry && !dynamic
            ? new PageFileCapacity(minimumBytes, maximumBytes)
            : new PageFileCapacity(null, null);
    }

    private static long? MegabytesToBytes(int? megabytes)
    {
        if (megabytes is not > 0)
        {
            return null;
        }

        try
        {
            return checked((long)megabytes.Value * 1024L * 1024L);
        }
        catch (OverflowException)
        {
            return null;
        }
    }

    private static long? MaxKnown(long? first, long? second) => first is null
        ? second
        : second is null ? first : Math.Max(first.Value, second.Value);

    private static long? NonNegative(long? value) => value is >= 0 ? value : null;

    private static bool IsReadFailure(Exception exception) => exception is
        IOException or UnauthorizedAccessException or SecurityException or PlatformNotSupportedException or
        System.Management.ManagementException or InvalidOperationException or InvalidDataException or ArgumentException;

    private static CollectionStatus Denied(string source) => new(
        source,
        CollectionState.Denied,
        "Windows denied access. The collector did not request elevation.");

    private static CollectionStatus Error(string source, Exception exception) => new(
        source,
        CollectionState.Error,
        $"Windows crash-readiness settings could not be read (0x{exception.HResult:X8}).");

    [GeneratedRegex(@"\s+(?<minimum>\d+)\s+(?<maximum>\d+)\s*$", RegexOptions.CultureInvariant)]
    private static partial Regex PageFileSizeRegex();
}

internal sealed record DestinationCapacity(
    bool? Accessible,
    long? FreeBytes,
    long? TotalBytes,
    long? ActualFileBytes = null);

internal sealed record PageFileCapacity(long? MinimumBytes, long? MaximumBytes);
