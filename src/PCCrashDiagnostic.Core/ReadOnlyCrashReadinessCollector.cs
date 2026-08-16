using System.Management;
using System.Security;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;
using Microsoft.Win32;

namespace PCCrashDiagnostic.Core;

/// <summary>
/// Reads Windows crash-capture configuration without consulting receipts or
/// exposing any registry mutation surface.
/// </summary>
public sealed class ReadOnlyCrashReadinessCollector
{
    private const string CrashControlPath = @"SYSTEM\CurrentControlSet\Control\CrashControl";
    private const string MemoryManagementPath = @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management";
    private const long MiB = 1024L * 1024L;
    private const long GiB = 1024L * MiB;

    public Task<CrashReadinessCollection> CollectAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => Collect(cancellationToken), cancellationToken);

    private static CrashReadinessCollection Collect(CancellationToken cancellationToken)
    {
        var statuses = new List<CollectionStatus>();
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using RegistryKey? crash = Registry.LocalMachine.OpenSubKey(CrashControlPath, writable: false);
            using RegistryKey? memory = Registry.LocalMachine.OpenSubKey(MemoryManagementPath, writable: false);
            if (crash is null)
            {
                return Unavailable(statuses, "Windows crash-control settings were unavailable.");
            }

            int? rawMode = ReadInt32(crash, "CrashDumpEnabled");
            bool activeFilter = ReadBoolean(crash, "FilterPages") == true;
            CrashDumpMode mode = DecodeMode(rawMode, activeFilter);
            string rawDumpPath = ReadText(crash, "DumpFile") ?? @"%SystemRoot%\MEMORY.DMP";
            string rawMiniPath = ReadText(crash, "MinidumpDir") ?? @"%SystemRoot%\Minidump";
            string dumpPath = EvidencePathRedactor.Redact(rawDumpPath) ?? "[configured dump path]";
            string miniPath = EvidencePathRedactor.Redact(rawMiniPath) ?? "[configured minidump path]";
            string[] pagingFiles = memory?.GetValue(
                    "PagingFiles",
                    Array.Empty<string>(),
                    RegistryValueOptions.DoNotExpandEnvironmentNames) as string[] ?? [];

            RuntimePageFileFacts runtime = ReadRuntimePageFileFacts(cancellationToken, statuses);
            DestinationFacts dumpDestination = ProbeDestination(rawDumpPath, pathIsFile: true, cancellationToken);
            DestinationFacts miniDestination = ProbeDestination(rawMiniPath, pathIsFile: false, cancellationToken);
            long? required = EstimateRequiredBacking(mode, runtime.PhysicalMemoryBytes);
            long? recommendedFree = required is null ? null : checked(required.Value + Math.Max(GiB, required.Value / 10));

            CrashReadinessState state;
            string detail;
            if (mode == CrashDumpMode.None)
            {
                state = CrashReadinessState.Off;
                detail = "Windows crash-dump capture is turned off.";
            }
            else if (rawMode is null || mode == CrashDumpMode.Unknown)
            {
                state = CrashReadinessState.Unavailable;
                detail = "The configured crash-dump type could not be interpreted.";
            }
            else if (dumpDestination.Accessible == false ||
                     (recommendedFree is not null && dumpDestination.FreeBytes is not null &&
                      dumpDestination.FreeBytes < recommendedFree))
            {
                state = CrashReadinessState.AtRisk;
                detail = "The configured dump destination may be inaccessible or short on free space.";
            }
            else if (!HasPlausibleBacking(pagingFiles, runtime, required))
            {
                state = CrashReadinessState.Limited;
                detail = "The active page-file backing may be too limited for the configured dump type.";
            }
            else
            {
                state = CrashReadinessState.Ready;
                detail = "Windows crash capture appears configured for the selected dump type.";
            }

            statuses.Add(new CollectionStatus(
                "Crash readiness",
                CollectionState.Available,
                "Read crash-dump, destination, and page-file facts without changing Windows settings."));

            return new CrashReadinessCollection(
                new CrashReadiness(
                    DateTimeOffset.UtcNow,
                    mode,
                    rawMode,
                    ReadBoolean(crash, "LogEvent"),
                    ReadBoolean(crash, "AutoReboot"),
                    ReadBoolean(crash, "Overwrite"),
                    ReadBoolean(crash, "AlwaysKeepMemoryDump"),
                    DedicatedDumpFileConfigured: !string.IsNullOrWhiteSpace(ReadText(crash, "DedicatedDumpFile")),
                    DumpFileLocation: dumpPath,
                    MinidumpDirectory: miniPath,
                    PageFileEntryCount: pagingFiles.Length,
                    SystemManagedPageFile: runtime.AutomaticManagement,
                    SystemDriveFreeBytes: dumpDestination.FreeBytes,
                    SystemDriveTotalBytes: dumpDestination.TotalBytes,
                    Assessment: state,
                    AssessmentDetail: detail,
                    ActiveDumpFilterEnabled: activeFilter,
                    RuntimePageFileCount: runtime.Count,
                    RuntimePageFileAllocatedBytes: runtime.AllocatedBytes,
                    DumpDestinationAccessible: dumpDestination.Accessible,
                    DumpDestinationFreeBytes: dumpDestination.FreeBytes,
                    DumpDestinationTotalBytes: dumpDestination.TotalBytes,
                    MinidumpDestinationAccessible: miniDestination.Accessible,
                    MinidumpDestinationFreeBytes: miniDestination.FreeBytes,
                    MinidumpDestinationTotalBytes: miniDestination.TotalBytes,
                    ActivationState: CrashCaptureActivationState.Unknown,
                    PhysicalMemoryBytes: runtime.PhysicalMemoryBytes,
                    RequiredDumpBackingBytes: required,
                    RecommendedDestinationFreeBytes: recommendedFree,
                    CurrentBootUtc: EstimateBootUtc(),
                    RuntimePageFileStateAvailable: runtime.Available,
                    AutomaticPageFileManagementEnabled: runtime.AutomaticManagement,
                    RecommendedDumpBackingBytes: required,
                    BootVolumeRuntimePageFileCount: runtime.Count,
                    BootVolumeRuntimePageFileAllocatedBytes: runtime.AllocatedBytes,
                    ExistingDumpMayBeOverwritten: ReadBoolean(crash, "Overwrite")),
                statuses);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or SecurityException)
        {
            statuses.Add(new CollectionStatus("Crash readiness", CollectionState.Denied, "Windows denied read-only access to crash-capture settings."));
            return Unavailable(statuses, "Crash readiness could not be read as the current user.");
        }
        catch (Exception exception) when (exception is IOException or ManagementException or InvalidOperationException or PlatformNotSupportedException)
        {
            statuses.Add(new CollectionStatus("Crash readiness", CollectionState.Error, $"Read-only collection failed ({exception.GetType().Name})."));
            return Unavailable(statuses, "Crash readiness could not be determined from the available Windows records.");
        }
    }

    private static CrashReadinessCollection Unavailable(List<CollectionStatus> statuses, string detail)
    {
        if (statuses.Count == 0)
        {
            statuses.Add(new CollectionStatus("Crash readiness", CollectionState.Unavailable, detail));
        }

        return new CrashReadinessCollection(
            new CrashReadiness(
                DateTimeOffset.UtcNow,
                CrashDumpMode.Unknown,
                null,
                null,
                null,
                null,
                null,
                false,
                "Not available",
                "Not available",
                0,
                null,
                null,
                null,
                CrashReadinessState.Unavailable,
                detail),
            statuses);
    }

    private static CrashDumpMode DecodeMode(int? raw, bool filterPages) => raw switch
    {
        0 => CrashDumpMode.None,
        1 when filterPages => CrashDumpMode.ActiveMemory,
        1 => CrashDumpMode.CompleteMemory,
        2 => CrashDumpMode.KernelMemory,
        3 => CrashDumpMode.SmallMemory,
        7 => CrashDumpMode.AutomaticMemory,
        10 => CrashDumpMode.ActiveMemory,
        _ => CrashDumpMode.Unknown
    };

    private static long? EstimateRequiredBacking(CrashDumpMode mode, long? ram) => mode switch
    {
        CrashDumpMode.None => 0,
        CrashDumpMode.SmallMemory => 64 * MiB,
        CrashDumpMode.KernelMemory => ram is null ? 8 * GiB : Math.Min(ram.Value, 8 * GiB) + 257 * MiB,
        CrashDumpMode.AutomaticMemory => ram is null ? 8 * GiB : Math.Min(ram.Value, 32 * GiB) + 257 * MiB,
        CrashDumpMode.ActiveMemory => ram is null ? 8 * GiB : Math.Min(ram.Value, 32 * GiB) + 257 * MiB,
        CrashDumpMode.CompleteMemory => ram is null ? null : ram.Value + 257 * MiB,
        _ => null
    };

    private static bool HasPlausibleBacking(
        IReadOnlyCollection<string> configured,
        RuntimePageFileFacts runtime,
        long? required)
    {
        if (required is 0)
        {
            return true;
        }

        if (runtime.AutomaticManagement == true && (runtime.Count > 0 || configured.Count > 0))
        {
            return true;
        }

        if (runtime.AllocatedBytes is not null && required is not null)
        {
            return runtime.AllocatedBytes >= required;
        }

        return configured.Count > 0 || runtime.Count > 0;
    }

    private static RuntimePageFileFacts ReadRuntimePageFileFacts(
        CancellationToken cancellationToken,
        ICollection<CollectionStatus> statuses)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            bool? automatic = null;
            long? physical = null;
            using (var searcher = new ManagementObjectSearcher(
                       "root\\CIMV2",
                       "SELECT AutomaticManagedPagefile, TotalPhysicalMemory FROM Win32_ComputerSystem"))
            using (ManagementObjectCollection systems = searcher.Get())
            {
                using ManagementObject? system = systems.Cast<ManagementObject>().FirstOrDefault();
                if (system is not null)
                {
                    automatic = ConvertNullableBoolean(system["AutomaticManagedPagefile"]);
                    physical = ConvertNullableInt64(system["TotalPhysicalMemory"]);
                }
            }

            int count = 0;
            long allocated = 0;
            using (var searcher = new ManagementObjectSearcher(
                       "root\\CIMV2",
                       "SELECT AllocatedBaseSize FROM Win32_PageFileUsage"))
            using (ManagementObjectCollection pageFiles = searcher.Get())
            {
                foreach (ManagementObject pageFile in pageFiles)
                {
                    using (pageFile)
                    {
                        count++;
                        long? megabytes = ConvertNullableInt64(pageFile["AllocatedBaseSize"]);
                        if (megabytes is not null && megabytes >= 0)
                        {
                            allocated = checked(allocated + megabytes.Value * MiB);
                        }
                    }
                }
            }

            statuses.Add(new CollectionStatus(
                "Crash readiness/Active page files",
                CollectionState.Available,
                $"Windows reports {count} active page file{(count == 1 ? string.Empty : "s")}; paths were not retained."));
            return new RuntimePageFileFacts(true, automatic, count, allocated, physical);
        }
        catch (Exception exception) when (exception is ManagementException or UnauthorizedAccessException or InvalidOperationException or PlatformNotSupportedException)
        {
            statuses.Add(new CollectionStatus(
                "Crash readiness/Active page files",
                CollectionState.Unavailable,
                "Windows did not expose active page-file sizing to the current user."));
            return new RuntimePageFileFacts(false, null, 0, null, null);
        }
    }

    private static DestinationFacts ProbeDestination(string configured, bool pathIsFile, CancellationToken token)
    {
        try
        {
            token.ThrowIfCancellationRequested();
            string expanded = Environment.ExpandEnvironmentVariables(configured);
            string full = Path.GetFullPath(expanded);
            string? directory = pathIsFile ? Path.GetDirectoryName(full) : full;
            string? root = Path.GetPathRoot(full);
            if (string.IsNullOrWhiteSpace(directory) || string.IsNullOrWhiteSpace(root))
            {
                return new DestinationFacts(false, null, null);
            }

            var drive = new DriveInfo(root);
            bool accessible = Directory.Exists(directory) || Directory.Exists(Path.GetDirectoryName(directory));
            return new DestinationFacts(accessible, drive.AvailableFreeSpace, drive.TotalSize);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException or SecurityException)
        {
            return new DestinationFacts(false, null, null);
        }
    }

    private static int? ReadInt32(RegistryKey key, string name)
    {
        object? value = key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        return value is null ? null : Convert.ToInt32(value, System.Globalization.CultureInfo.InvariantCulture);
    }

    private static bool? ReadBoolean(RegistryKey key, string name) => ReadInt32(key, name) switch
    {
        0 => false,
        1 => true,
        _ => null
    };

    private static string? ReadText(RegistryKey key, string name) =>
        key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames)?.ToString();

    private static bool? ConvertNullableBoolean(object? value) => value is null ? null : Convert.ToBoolean(value, System.Globalization.CultureInfo.InvariantCulture);

    private static long? ConvertNullableInt64(object? value) => value is null ? null : Convert.ToInt64(value, System.Globalization.CultureInfo.InvariantCulture);

    private static DateTimeOffset EstimateBootUtc() =>
        DateTimeOffset.UtcNow - TimeSpan.FromMilliseconds(Math.Max(0, Environment.TickCount64));

    private sealed record RuntimePageFileFacts(
        bool Available,
        bool? AutomaticManagement,
        int Count,
        long? AllocatedBytes,
        long? PhysicalMemoryBytes);

    private sealed record DestinationFacts(bool? Accessible, long? FreeBytes, long? TotalBytes);
}
