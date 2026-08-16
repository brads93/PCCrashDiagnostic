using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Collectors;

/// <summary>
/// Reads device-reported storage health and reliability counters. Serial numbers,
/// unique IDs, paths, physical locations, and persistent identifiers never enter
/// the public model. No storage command, test, or counter-reset method is invoked.
/// </summary>
public sealed class StorageHealthCollector
{
    private readonly IStorageHealthSource _source;
    private readonly TimeProvider _timeProvider;

    public StorageHealthCollector()
        : this(new WmiStorageHealthSource(), TimeProvider.System)
    {
    }

    internal StorageHealthCollector(IStorageHealthSource source, TimeProvider timeProvider)
    {
        _source = source;
        _timeProvider = timeProvider;
    }

    public Task<StorageHealthSnapshot> CollectAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => Collect(cancellationToken), cancellationToken);

    private StorageHealthSnapshot Collect(CancellationToken cancellationToken)
    {
        StorageHealthSourceResult source = _source.Read(cancellationToken);
        IReadOnlyDictionary<string, RawStorageReliability> counters = source.Reliability
            .GroupBy(item => item.DeviceId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.First(), StringComparer.OrdinalIgnoreCase);
        StorageHealthRecord[] records = source.Devices
            .OrderBy(item => item.DeviceId, StringComparer.OrdinalIgnoreCase)
            .Take(64)
            .Select((item, index) => CreateRecord(index + 1, item,
                counters.GetValueOrDefault(item.DeviceId)))
            .ToArray();
        return new StorageHealthSnapshot(
            _timeProvider.GetUtcNow().ToUniversalTime(),
            records,
            source.Status);
    }

    internal static StorageHealthRecord CreateRecord(
        int ordinal,
        RawStorageDevice device,
        RawStorageReliability? reliability)
    {
        return new StorageHealthRecord(
            ordinal,
            SafeText(device.Model, 128, "Unknown model"),
            MediaType(device.MediaType),
            BusType(device.BusType),
            SafeText(device.FirmwareVersion, 64, "Unavailable"),
            HealthStatus(device.HealthStatus),
            device.OperationalStatus.Select(OperationalStatus).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
            device.SizeBytes,
            reliability?.TemperatureCelsius,
            reliability?.MaximumTemperatureCelsius,
            reliability?.WearPercent,
            reliability?.ReadErrorsTotal,
            reliability?.ReadErrorsUncorrected,
            reliability?.WriteErrorsTotal,
            reliability?.WriteErrorsUncorrected,
            reliability?.ReadLatencyMaximumMilliseconds,
            reliability?.WriteLatencyMaximumMilliseconds,
            reliability?.FlushLatencyMaximumMilliseconds,
            reliability?.PowerOnHours);
    }

    private static string SafeText(string value, int maximumLength, string fallback)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return fallback;
        }

        string collapsed = string.Join(' ', value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        string safe = new(collapsed
            .Where(character => !char.IsControl(character) && character is not '\\' and not '/')
            .Take(maximumLength)
            .ToArray());
        return safe.Length == 0 ? fallback : safe;
    }

    private static string MediaType(ushort? value) => value switch
    {
        3 => "HDD",
        4 => "SSD",
        5 => "Storage class memory",
        0 => "Unspecified",
        null => "Unavailable",
        _ => $"Other ({value.Value})"
    };

    private static string BusType(ushort? value) => value switch
    {
        1 => "SCSI",
        2 => "ATAPI",
        3 => "ATA",
        7 => "USB",
        8 => "RAID",
        9 => "iSCSI",
        10 => "SAS",
        11 => "SATA",
        12 => "SD",
        13 => "MMC",
        14 => "Virtual",
        15 => "File-backed virtual",
        16 => "Storage Spaces",
        17 => "NVMe",
        0 => "Unknown",
        null => "Unavailable",
        _ => $"Other ({value.Value})"
    };

    private static string HealthStatus(ushort? value) => value switch
    {
        0 => "Healthy",
        1 => "Warning",
        2 => "Unhealthy",
        5 => "Unknown",
        null => "Unavailable",
        _ => $"Other ({value.Value})"
    };

    private static string OperationalStatus(ushort value) => value switch
    {
        0 => "Unknown",
        1 => "Other",
        2 => "OK",
        3 => "Degraded",
        4 => "Stressed",
        5 => "Predictive failure",
        6 => "Error",
        7 => "Non-recoverable error",
        8 => "Starting",
        9 => "Stopping",
        10 => "Stopped",
        11 => "In service",
        12 => "No contact",
        13 => "Lost communication",
        15 => "Dormant",
        16 => "Supporting entity in error",
        17 => "Completed",
        18 => "Power mode",
        19 => "Relocating",
        _ => $"Status {value}"
    };
}

internal sealed record RawStorageDevice(
    string DeviceId,
    string Model,
    ushort? MediaType,
    ushort? BusType,
    string FirmwareVersion,
    ushort? HealthStatus,
    IReadOnlyList<ushort> OperationalStatus,
    ulong? SizeBytes);

internal sealed record RawStorageReliability(
    string DeviceId,
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

internal sealed record StorageHealthSourceResult(
    IReadOnlyList<RawStorageDevice> Devices,
    IReadOnlyList<RawStorageReliability> Reliability,
    IReadOnlyList<CollectionStatus> Status);

internal interface IStorageHealthSource
{
    StorageHealthSourceResult Read(CancellationToken cancellationToken);
}

internal sealed class WmiStorageHealthSource : IStorageHealthSource
{
    private const string Namespace = @"root\Microsoft\Windows\Storage";
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(10);

    public StorageHealthSourceResult Read(CancellationToken cancellationToken)
    {
        var statuses = new List<CollectionStatus>();
        IReadOnlyList<RawStorageDevice> devices = Query(
            "Storage health/Physical disks",
            "SELECT DeviceId, Model, MediaType, BusType, FirmwareVersion, HealthStatus, OperationalStatus, Size FROM MSFT_PhysicalDisk",
            CreateDevice,
            statuses,
            cancellationToken);
        IReadOnlyList<RawStorageReliability> reliability = Query(
            "Storage health/Reliability counters",
            "SELECT DeviceId, Temperature, TemperatureMax, Wear, ReadErrorsTotal, ReadErrorsUncorrected, " +
            "WriteErrorsTotal, WriteErrorsUncorrected, ReadLatencyMax, WriteLatencyMax, FlushLatencyMax, PowerOnHours " +
            "FROM MSFT_StorageReliabilityCounter",
            CreateReliability,
            statuses,
            cancellationToken);
        return new StorageHealthSourceResult(devices, reliability, statuses);
    }

    private static IReadOnlyList<T> Query<T>(
        string source,
        string query,
        Func<ManagementBaseObject, T> projector,
        ICollection<CollectionStatus> statuses,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var searcher = new ManagementObjectSearcher(Namespace, query);
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
                CollectionState.Available,
                $"Read {values.Count} device-reported {(values.Count == 1 ? "record" : "records")} without persistent identifiers."));
            return values;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            statuses.Add(new CollectionStatus(source, CollectionState.Denied,
                "Windows denied read-only access to this storage source."));
            return [];
        }
        catch (SecurityException)
        {
            statuses.Add(new CollectionStatus(source, CollectionState.Denied,
                "Windows denied read-only access to this storage source."));
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
            statuses.Add(new CollectionStatus(source, state,
                $"The Windows storage provider returned {exception.ErrorCode}."));
            return [];
        }
        catch (Exception exception) when (exception is COMException or InvalidOperationException)
        {
            statuses.Add(new CollectionStatus(source, CollectionState.Error,
                $"The Windows storage provider failed (0x{exception.HResult:X8})."));
            return [];
        }
    }

    private static RawStorageDevice CreateDevice(ManagementBaseObject item) => new(
        Text(item, "DeviceId"),
        Text(item, "Model"),
        UInt16(item, "MediaType"),
        UInt16(item, "BusType"),
        Text(item, "FirmwareVersion"),
        UInt16(item, "HealthStatus"),
        UInt16Array(item, "OperationalStatus"),
        UInt64(item, "Size"));

    private static RawStorageReliability CreateReliability(ManagementBaseObject item) => new(
        Text(item, "DeviceId"),
        Byte(item, "Temperature"),
        Byte(item, "TemperatureMax"),
        Byte(item, "Wear"),
        UInt64(item, "ReadErrorsTotal"),
        UInt64(item, "ReadErrorsUncorrected"),
        UInt64(item, "WriteErrorsTotal"),
        UInt64(item, "WriteErrorsUncorrected"),
        UInt64(item, "ReadLatencyMax"),
        UInt64(item, "WriteLatencyMax"),
        UInt64(item, "FlushLatencyMax"),
        UInt16(item, "PowerOnHours"));

    private static object? Value(ManagementBaseObject item, string name)
    {
        try
        {
            return item[name];
        }
        catch (ManagementException)
        {
            return null;
        }
    }

    private static string Text(ManagementBaseObject item, string name) =>
        Convert.ToString(Value(item, name), CultureInfo.InvariantCulture)?.Trim() ?? string.Empty;

    private static byte? Byte(ManagementBaseObject item, string name) => ConvertValue<byte>(Value(item, name));

    private static ushort? UInt16(ManagementBaseObject item, string name) => ConvertValue<ushort>(Value(item, name));

    private static ulong? UInt64(ManagementBaseObject item, string name) => ConvertValue<ulong>(Value(item, name));

    private static IReadOnlyList<ushort> UInt16Array(ManagementBaseObject item, string name)
    {
        object? value = Value(item, name);
        if (value is ushort[] values)
        {
            return values;
        }

        if (value is Array array)
        {
            return array.Cast<object?>()
                .Select(ConvertValue<ushort>)
                .Where(item => item is not null)
                .Select(item => item!.Value)
                .ToArray();
        }

        return [];
    }

    private static T? ConvertValue<T>(object? value) where T : struct
    {
        if (value is null)
        {
            return null;
        }

        try
        {
            return (T)Convert.ChangeType(value, typeof(T), CultureInfo.InvariantCulture);
        }
        catch (Exception exception) when (exception is InvalidCastException or FormatException or OverflowException)
        {
            return null;
        }
    }
}
