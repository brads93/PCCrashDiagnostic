using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Collectors;

/// <summary>
/// Reads a bounded inventory of signed Plug and Play drivers for hardware classes useful
/// during crash diagnosis. Device IDs, instance paths, locations, serials, and hardware IDs
/// are deliberately not queried or retained.
/// </summary>
public sealed class DriverDeviceCollector
{
    private const int MaximumDrivers = 512;
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(10);
    private static readonly HashSet<string> AllowedDeviceClasses = new(StringComparer.OrdinalIgnoreCase)
    {
        "DISPLAY",
        "SYSTEM",
        "SCSIADAPTER",
        "HDC",
        "USB",
        "MEDIA",
        "NET",
        "PROCESSOR",
        "FIRMWARE"
    };

    private readonly TimeProvider _timeProvider;

    public DriverDeviceCollector(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public Task<DriverInventory> CollectAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => Collect(cancellationToken), cancellationToken);

    private DriverInventory Collect(CancellationToken cancellationToken)
    {
        const string source = "Driver inventory/Plug and Play signed drivers";
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            IReadOnlyDictionary<string, int> problemCodes = CollectProblemCodes(cancellationToken, out CollectionStatus problemStatus);
            const string query = "SELECT DeviceClass, DeviceName, Manufacturer, DriverProviderName, " +
                                 "DriverVersion, DriverDate, InfName, IsSigned, Signer " +
                                 "FROM Win32_PnPSignedDriver";
            using var searcher = new ManagementObjectSearcher("root\\cimv2", query);
            searcher.Options.Timeout = QueryTimeout;
            using ManagementObjectCollection results = searcher.Get();
            var drivers = new List<DriverDeviceRecord>();
            bool truncated = false;
            foreach (ManagementBaseObject item in results)
            {
                using (item)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var values = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
                    foreach (string name in QueriedProperties)
                    {
                        values[name] = item[name];
                    }

                    DriverDeviceRecord? record = CreateRecord(values);
                    if (record is null)
                    {
                        continue;
                    }

                    if (problemCodes.TryGetValue(DeviceKey(record.DeviceClass, record.DeviceName), out int problemCode))
                    {
                        record = record with
                        {
                            DeviceManagerProblemCode = problemCode,
                            DeviceManagerProblemState = problemCode == 0 ? "Working" : $"Problem code {problemCode}"
                        };
                    }

                    if (drivers.Count >= MaximumDrivers)
                    {
                        truncated = true;
                        break;
                    }

                    drivers.Add(record);
                }
            }

            DriverDeviceRecord[] ordered = drivers
                .DistinctBy(
                    record => string.Join('|', record.DeviceClass, record.DeviceName, record.DriverProvider, record.DriverVersion, record.InfName),
                    StringComparer.OrdinalIgnoreCase)
                .OrderBy(record => record.DeviceClass, StringComparer.OrdinalIgnoreCase)
                .ThenBy(record => record.DeviceName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(record => record.DriverVersion, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            string detail = truncated
                ? $"Collected {drivers.Count} privacy-filtered driver records; additional records were not read."
                : $"Collected {ordered.Length} privacy-filtered driver {(ordered.Length == 1 ? "record" : "records")}.";
            return new DriverInventory(
                _timeProvider.GetUtcNow().ToUniversalTime(),
                ordered,
                [new CollectionStatus(source, CollectionState.Available, detail), problemStatus]);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            return Failed(source, CollectionState.Denied, "Windows denied access. The collector did not request elevation.");
        }
        catch (SecurityException)
        {
            return Failed(source, CollectionState.Denied, "Windows denied access. The collector did not request elevation.");
        }
        catch (ManagementException exception)
        {
            CollectionState state = exception.ErrorCode switch
            {
                ManagementStatus.InvalidClass or ManagementStatus.NotFound => CollectionState.Unavailable,
                ManagementStatus.Timedout => CollectionState.TimedOut,
                _ => CollectionState.Error
            };
            return Failed(source, state, $"Windows Management Instrumentation returned {exception.ErrorCode}.");
        }
        catch (PlatformNotSupportedException)
        {
            return Failed(source, CollectionState.Unavailable, "Driver inventory is unavailable on this platform.");
        }
        catch (InvalidOperationException exception)
        {
            return Failed(source, CollectionState.Error, $"Driver inventory could not be read (0x{exception.HResult:X8}).");
        }
        catch (COMException exception)
        {
            return Failed(source, CollectionState.Error, $"Driver inventory could not be read (0x{exception.HResult:X8}).");
        }
    }

    internal static DriverDeviceRecord? CreateRecord(IReadOnlyDictionary<string, object?> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        string deviceClass = Text(values, "DeviceClass", 64, string.Empty).ToUpperInvariant();
        if (!AllowedDeviceClasses.Contains(deviceClass))
        {
            return null;
        }

        return new DriverDeviceRecord(
            deviceClass,
            Text(values, "DeviceName", 256),
            Text(values, "Manufacturer", 128),
            Text(values, "DriverProviderName", 128),
            Text(values, "DriverVersion", 64),
            ParseWmiDate(RawText(values, "DriverDate")),
            Text(values, "InfName", 96),
            NullableBoolean(Value(values, "IsSigned")),
            Text(values, "Signer", 192));
    }

    private static readonly string[] QueriedProperties =
    [
        "DeviceClass",
        "DeviceName",
        "Manufacturer",
        "DriverProviderName",
        "DriverVersion",
        "DriverDate",
        "InfName",
        "IsSigned",
        "Signer"
    ];

    private static IReadOnlyDictionary<string, int> CollectProblemCodes(
        CancellationToken cancellationToken,
        out CollectionStatus status)
    {
        const string source = "Driver inventory/Device Manager problem state";
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "root\\cimv2",
                "SELECT Name, PNPClass, ConfigManagerErrorCode FROM Win32_PnPEntity");
            searcher.Options.Timeout = QueryTimeout;
            using ManagementObjectCollection results = searcher.Get();
            var codes = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (ManagementBaseObject item in results)
            {
                using (item)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    string deviceClass = Convert.ToString(item["PNPClass"], CultureInfo.InvariantCulture)?.Trim() ?? string.Empty;
                    string name = Convert.ToString(item["Name"], CultureInfo.InvariantCulture)?.Trim() ?? string.Empty;
                    if (!AllowedDeviceClasses.Contains(deviceClass) || string.IsNullOrWhiteSpace(name))
                    {
                        continue;
                    }

                    if (int.TryParse(
                            Convert.ToString(item["ConfigManagerErrorCode"], CultureInfo.InvariantCulture),
                            NumberStyles.Integer,
                            CultureInfo.InvariantCulture,
                            out int code))
                    {
                        codes.TryAdd(DeviceKey(deviceClass, name), code);
                    }
                }
            }

            status = new CollectionStatus(source, CollectionState.Available, "Read privacy-filtered Device Manager problem codes.");
            return codes;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            status = new CollectionStatus(source, CollectionState.Denied, "Windows denied access. The collector did not request elevation.");
            return new Dictionary<string, int>();
        }
        catch (SecurityException)
        {
            status = new CollectionStatus(source, CollectionState.Denied, "Windows denied access. The collector did not request elevation.");
            return new Dictionary<string, int>();
        }
        catch (ManagementException exception)
        {
            status = new CollectionStatus(source, CollectionState.Error, $"Device Manager state returned {exception.ErrorCode}.");
            return new Dictionary<string, int>();
        }
        catch (InvalidOperationException exception)
        {
            status = new CollectionStatus(source, CollectionState.Error, $"Device Manager state could not be read (0x{exception.HResult:X8}).");
            return new Dictionary<string, int>();
        }
    }

    private static string DeviceKey(string deviceClass, string name) =>
        deviceClass.Trim().ToUpperInvariant() + "|" + name.Trim().ToUpperInvariant();

    private DriverInventory Failed(string source, CollectionState state, string detail) => new(
        _timeProvider.GetUtcNow().ToUniversalTime(),
        [],
        [new CollectionStatus(source, state, detail)]);

    private static object? Value(IReadOnlyDictionary<string, object?> values, string name) =>
        values.FirstOrDefault(pair => pair.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;

    private static string? RawText(IReadOnlyDictionary<string, object?> values, string name)
    {
        string? value = Convert.ToString(Value(values, name), CultureInfo.InvariantCulture)?.Trim();
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private static string Text(
        IReadOnlyDictionary<string, object?> values,
        string name,
        int maximumLength,
        string fallback = "Unknown")
    {
        string? raw = RawText(values, name);
        if (raw is null)
        {
            return fallback;
        }

        string collapsed = string.Join(' ', raw.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return collapsed.Length <= maximumLength ? collapsed : collapsed[..maximumLength];
    }

    private static bool? NullableBoolean(object? value)
    {
        if (value is null)
        {
            return null;
        }

        if (value is bool boolean)
        {
            return boolean;
        }

        string? text = Convert.ToString(value, CultureInfo.InvariantCulture);
        if (bool.TryParse(text, out bool parsedBoolean))
        {
            return parsedBoolean;
        }

        return int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsedInteger)
            ? parsedInteger != 0
            : null;
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
}
