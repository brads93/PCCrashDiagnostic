using System.Globalization;
using System.Management;
using System.Security;
using BF6CrashDiagnostic.Core.Models;
using Microsoft.Win32;

namespace BF6CrashDiagnostic.Core.Collectors;

/// <summary>
/// Captures non-secret hardware and Windows facts. WMI projections intentionally omit all
/// serial-number, UUID, product-key, user, domain, network, and storage-identifying fields.
/// </summary>
public sealed class SystemSnapshotCollector
{
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(8);

    private readonly TimeProvider _timeProvider;

    public SystemSnapshotCollector(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public Task<SystemSnapshotCollection> CollectAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => Collect(cancellationToken), cancellationToken);

    private SystemSnapshotCollection Collect(CancellationToken cancellationToken)
    {
        var statuses = new List<CollectionStatus>();

        IReadOnlyList<ComputerFact> computers = Query(
            "System snapshot/Computer system",
            "SELECT Manufacturer, Model, TotalPhysicalMemory FROM Win32_ComputerSystem",
            item => new ComputerFact(
                Text(item, "Manufacturer"),
                Text(item, "Model"),
                UInt64(item, "TotalPhysicalMemory")),
            statuses,
            cancellationToken);

        IReadOnlyList<BaseboardFact> baseboards = Query(
            "System snapshot/Baseboard",
            "SELECT Manufacturer, Product FROM Win32_BaseBoard",
            item => new BaseboardFact(Text(item, "Manufacturer"), Text(item, "Product")),
            statuses,
            cancellationToken);

        IReadOnlyList<BiosFact> biosRecords = Query(
            "System snapshot/BIOS",
            "SELECT SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS",
            item => new BiosFact(
                Text(item, "SMBIOSBIOSVersion"),
                FormatWmiDate(TextOrNull(item, "ReleaseDate"))),
            statuses,
            cancellationToken);

        IReadOnlyList<string> cpus = Query(
            "System snapshot/Processor",
            "SELECT Name FROM Win32_Processor",
            item => Text(item, "Name"),
            statuses,
            cancellationToken);

        IReadOnlyList<MemoryModuleInfo> memoryModules = Query(
            "System snapshot/Physical memory",
            "SELECT Capacity, Speed, ConfiguredClockSpeed, Manufacturer, PartNumber FROM Win32_PhysicalMemory",
            item => new MemoryModuleInfo(
                UInt64(item, "Capacity"),
                NullableUInt32(item, "Speed"),
                NullableUInt32(item, "ConfiguredClockSpeed"),
                Text(item, "Manufacturer"),
                Text(item, "PartNumber")),
            statuses,
            cancellationToken);

        IReadOnlyList<GpuInfo> gpus = Query(
            "System snapshot/Display adapters",
            "SELECT Name, DriverVersion, AdapterRAM FROM Win32_VideoController",
            item => new GpuInfo(
                Text(item, "Name"),
                Text(item, "DriverVersion"),
                NullableUInt64(item, "AdapterRAM")),
            statuses,
            cancellationToken);

        IReadOnlyList<OperatingSystemFact> operatingSystems = Query(
            "System snapshot/Operating system",
            "SELECT Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime FROM Win32_OperatingSystem",
            item => new OperatingSystemFact(
                Text(item, "Caption"),
                Text(item, "Version"),
                Text(item, "BuildNumber"),
                Text(item, "OSArchitecture"),
                ParseWmiDate(TextOrNull(item, "LastBootUpTime"))),
            statuses,
            cancellationToken);

        WindowsRegistryFact registry = ReadWindowsRegistry(statuses, cancellationToken);
        ComputerFact computer = computers.FirstOrDefault() ?? ComputerFact.Unknown;
        BaseboardFact baseboard = baseboards.FirstOrDefault() ?? BaseboardFact.Unknown;
        BiosFact bios = biosRecords.FirstOrDefault() ?? BiosFact.Unknown;
        OperatingSystemFact operatingSystem = operatingSystems.FirstOrDefault() ?? OperatingSystemFact.Unknown;

        string build = operatingSystem.Build;
        if (!string.IsNullOrWhiteSpace(registry.UpdateBuildRevision) &&
            !build.EndsWith('.' + registry.UpdateBuildRevision, StringComparison.Ordinal))
        {
            build = string.IsNullOrWhiteSpace(build)
                ? registry.UpdateBuildRevision
                : build + '.' + registry.UpdateBuildRevision;
        }

        var snapshot = new SystemSnapshot(
            _timeProvider.GetUtcNow(),
            computer.Manufacturer,
            computer.Model,
            baseboard.Manufacturer,
            baseboard.Product,
            bios.Version,
            bios.ReleaseDate,
            cpus.FirstOrDefault() ?? "Unknown",
            computer.TotalPhysicalMemory,
            memoryModules,
            gpus,
            operatingSystem.Caption,
            operatingSystem.Version,
            build,
            operatingSystem.Architecture,
            registry.Channel,
            registry.PreviewBuildDetected,
            operatingSystem.LastBootUtc);

        return new SystemSnapshotCollection(snapshot, statuses.ToArray());
    }

    private static IReadOnlyList<T> Query<T>(
        string source,
        string wql,
        Func<ManagementBaseObject, T> projector,
        ICollection<CollectionStatus> statuses,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var searcher = new ManagementObjectSearcher("root\\cimv2", wql);
            searcher.Options.Timeout = QueryTimeout;
            using ManagementObjectCollection results = searcher.Get();
            var values = new List<T>();
            foreach (ManagementBaseObject item in results)
            {
                using (item)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    values.Add(projector(item));
                }
            }

            statuses.Add(new CollectionStatus(
                source,
                values.Count == 0 ? CollectionState.Unavailable : CollectionState.Available,
                values.Count == 0
                    ? "Windows returned no records for this source."
                    : $"Collected {values.Count} non-identifying {(values.Count == 1 ? "record" : "records")}."));
            return values;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            statuses.Add(Denied(source));
            return [];
        }
        catch (SecurityException)
        {
            statuses.Add(Denied(source));
            return [];
        }
        catch (ManagementException exception)
        {
            CollectionState state = exception.ErrorCode switch
            {
                ManagementStatus.InvalidClass or ManagementStatus.NotFound => CollectionState.Unavailable,
                ManagementStatus.Timedout => CollectionState.TimedOut,
                _ => CollectionState.Error
            };
            statuses.Add(new CollectionStatus(
                source,
                state,
                $"Windows Management Instrumentation returned {exception.ErrorCode}."));
            return [];
        }
        catch (PlatformNotSupportedException)
        {
            statuses.Add(new CollectionStatus(
                source,
                CollectionState.Unavailable,
                "Windows Management Instrumentation is unavailable on this platform."));
            return [];
        }
        catch (InvalidOperationException exception)
        {
            statuses.Add(new CollectionStatus(
                source,
                CollectionState.Error,
                $"The WMI source could not be read (0x{exception.HResult:X8})."));
            return [];
        }
    }

    private static WindowsRegistryFact ReadWindowsRegistry(
        ICollection<CollectionStatus> statuses,
        CancellationToken cancellationToken)
    {
        const string source = "System snapshot/Windows release channel";
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using RegistryKey? currentVersion = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                writable: false);
            using RegistryKey? applicability = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\WindowsSelfHost\Applicability",
                writable: false);

            string displayVersion = RegistryText(currentVersion, "DisplayVersion");
            string updateBuildRevision = RegistryText(currentVersion, "UBR");
            string buildBranch = RegistryText(currentVersion, "BuildBranch");
            string buildLab = RegistryText(currentVersion, "BuildLabEx");
            string ring = RegistryText(applicability, "Ring");
            string contentType = RegistryText(applicability, "ContentType");
            string branchName = RegistryText(applicability, "BranchName");

            string[] insiderParts = [contentType, ring, branchName];
            bool hasChannelMetadata = insiderParts.Any(value => !string.IsNullOrWhiteSpace(value));
            bool preview = IsPreviewChannel(contentType, ring, branchName) ||
                ContainsPreviewMarker(buildBranch) ||
                ContainsPreviewMarker(buildLab);
            string channel = preview && hasChannelMetadata
                ? "Insider " + string.Join(
                    '/',
                    insiderParts.Where(value => !string.IsNullOrWhiteSpace(value)))
                : string.IsNullOrWhiteSpace(displayVersion)
                    ? "Channel unavailable"
                    : displayVersion;

            statuses.Add(new CollectionStatus(
                source,
                currentVersion is null ? CollectionState.Unavailable : CollectionState.Available,
                currentVersion is null
                    ? "The Windows release registry key was unavailable."
                    : "Read release and flight-channel fields; product identifiers were not requested."));
            return new WindowsRegistryFact(channel, preview, updateBuildRevision);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            statuses.Add(Denied(source));
        }
        catch (SecurityException)
        {
            statuses.Add(Denied(source));
        }
        catch (IOException exception)
        {
            statuses.Add(new CollectionStatus(
                source,
                CollectionState.Error,
                $"The Windows release registry key could not be read (0x{exception.HResult:X8})."));
        }

        return WindowsRegistryFact.Unknown;
    }

    private static bool ContainsPreviewMarker(string value) =>
        value.Contains("prerelease", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("insider", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("flight", StringComparison.OrdinalIgnoreCase) ||
        value.Contains("canary", StringComparison.OrdinalIgnoreCase);

    private static bool IsPreviewChannel(string contentType, string ring, string branchName) =>
        (!string.IsNullOrWhiteSpace(contentType) &&
         !contentType.Equals("Mainline", StringComparison.OrdinalIgnoreCase)) ||
        ContainsAny(ring, "Canary", "Dev", "Beta", "ReleasePreview", "WIF") ||
        ContainsPreviewMarker(branchName);

    private static bool ContainsAny(string value, params string[] markers) =>
        markers.Any(marker => value.Contains(marker, StringComparison.OrdinalIgnoreCase));

    private static string RegistryText(RegistryKey? key, string valueName)
    {
        object? value = key?.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        return Convert.ToString(value, CultureInfo.InvariantCulture)?.Trim() ?? string.Empty;
    }

    private static CollectionStatus Denied(string source) => new(
        source,
        CollectionState.Denied,
        "Windows denied access. The collector did not request elevation.");

    private static string Text(ManagementBaseObject item, string propertyName) =>
        TextOrNull(item, propertyName) ?? "Unknown";

    private static string? TextOrNull(ManagementBaseObject item, string propertyName)
    {
        string? value = Convert.ToString(item[propertyName], CultureInfo.InvariantCulture)?.Trim();
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private static ulong UInt64(ManagementBaseObject item, string propertyName) =>
        NullableUInt64(item, propertyName) ?? 0;

    private static ulong? NullableUInt64(ManagementBaseObject item, string propertyName)
    {
        object? value = item[propertyName];
        if (value is null)
        {
            return null;
        }

        try
        {
            return Convert.ToUInt64(value, CultureInfo.InvariantCulture);
        }
        catch (FormatException)
        {
            return null;
        }
        catch (InvalidCastException)
        {
            return null;
        }
        catch (OverflowException)
        {
            return null;
        }
    }

    private static uint? NullableUInt32(ManagementBaseObject item, string propertyName)
    {
        ulong? value = NullableUInt64(item, propertyName);
        return value <= uint.MaxValue ? (uint?)value : null;
    }

    private static DateTimeOffset? ParseWmiDate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        try
        {
            return new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(value).ToUniversalTime());
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static string FormatWmiDate(string? value)
    {
        DateTimeOffset? parsed = ParseWmiDate(value);
        return parsed?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "Unknown";
    }

    private sealed record ComputerFact(string Manufacturer, string Model, ulong TotalPhysicalMemory)
    {
        public static ComputerFact Unknown { get; } = new("Unknown", "Unknown", 0);
    }

    private sealed record BaseboardFact(string Manufacturer, string Product)
    {
        public static BaseboardFact Unknown { get; } = new("Unknown", "Unknown");
    }

    private sealed record BiosFact(string Version, string ReleaseDate)
    {
        public static BiosFact Unknown { get; } = new("Unknown", "Unknown");
    }

    private sealed record OperatingSystemFact(
        string Caption,
        string Version,
        string Build,
        string Architecture,
        DateTimeOffset? LastBootUtc)
    {
        public static OperatingSystemFact Unknown { get; } =
            new("Unknown", "Unknown", "Unknown", "Unknown", null);
    }

    private sealed record WindowsRegistryFact(
        string Channel,
        bool PreviewBuildDetected,
        string UpdateBuildRevision)
    {
        public static WindowsRegistryFact Unknown { get; } = new("Unknown", false, string.Empty);
    }
}
