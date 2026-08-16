using System.Globalization;

namespace BF6CrashDiagnostic.Core.Analysis;

/// <summary>
/// Offline canonical names for a bounded set of common Windows bugcheck codes.
/// Names come from Microsoft's Bug Check Code Reference. A name classifies the
/// stop code; it does not identify the component that caused the stop.
/// </summary>
public static class BugcheckCatalog
{
    private static readonly IReadOnlyDictionary<uint, string> Names = new Dictionary<uint, string>
    {
        [0x0000000A] = "IRQL_NOT_LESS_OR_EQUAL",
        [0x0000001A] = "MEMORY_MANAGEMENT",
        [0x0000001E] = "KMODE_EXCEPTION_NOT_HANDLED",
        [0x00000024] = "NTFS_FILE_SYSTEM",
        [0x0000003B] = "SYSTEM_SERVICE_EXCEPTION",
        [0x0000004E] = "PFN_LIST_CORRUPT",
        [0x00000050] = "PAGE_FAULT_IN_NONPAGED_AREA",
        [0x0000007A] = "KERNEL_DATA_INPAGE_ERROR",
        [0x0000007B] = "INACCESSIBLE_BOOT_DEVICE",
        [0x0000007E] = "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        [0x0000007F] = "UNEXPECTED_KERNEL_MODE_TRAP",
        [0x0000009C] = "MACHINE_CHECK_EXCEPTION",
        [0x0000009F] = "DRIVER_POWER_STATE_FAILURE",
        [0x000000A5] = "ACPI_BIOS_ERROR",
        [0x000000C2] = "BAD_POOL_CALLER",
        [0x000000C4] = "DRIVER_VERIFIER_DETECTED_VIOLATION",
        [0x000000D1] = "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        [0x000000E6] = "DRIVER_VERIFIER_DMA_VIOLATION",
        [0x000000EA] = "THREAD_STUCK_IN_DEVICE_DRIVER",
        [0x000000ED] = "UNMOUNTABLE_BOOT_VOLUME",
        [0x000000EF] = "CRITICAL_PROCESS_DIED",
        [0x00000101] = "CLOCK_WATCHDOG_TIMEOUT",
        [0x00000109] = "CRITICAL_STRUCTURE_CORRUPTION",
        [0x0000010E] = "VIDEO_MEMORY_MANAGEMENT_INTERNAL",
        [0x00000113] = "VIDEO_DXGKRNL_FATAL_ERROR",
        [0x00000116] = "VIDEO_TDR_FAILURE",
        [0x00000117] = "VIDEO_TDR_TIMEOUT_DETECTED",
        [0x00000119] = "VIDEO_SCHEDULER_INTERNAL_ERROR",
        [0x00000124] = "WHEA_UNCORRECTABLE_ERROR",
        [0x0000012B] = "FAULTY_HARDWARE_CORRUPTED_PAGE",
        [0x00000133] = "DPC_WATCHDOG_VIOLATION",
        [0x00000139] = "KERNEL_SECURITY_CHECK_FAILURE",
        [0x0000013A] = "KERNEL_MODE_HEAP_CORRUPTION",
        [0x00000154] = "UNEXPECTED_STORE_EXCEPTION"
    };

    public static IReadOnlyDictionary<uint, string> KnownCodes => Names;

    public static string? GetName(uint code) => Names.GetValueOrDefault(code);

    public static bool TryGetName(uint code, out string name) => Names.TryGetValue(code, out name!);

    public static bool TryGetName(string? normalizedHexCode, out string name)
    {
        name = string.Empty;
        if (!TryParseNormalizedHex(normalizedHexCode, out uint code))
        {
            return false;
        }

        return TryGetName(code, out name);
    }

    public static string Format(string? normalizedHexCode)
    {
        if (string.IsNullOrWhiteSpace(normalizedHexCode))
        {
            return string.Empty;
        }

        return TryGetName(normalizedHexCode, out string name)
            ? $"{normalizedHexCode} ({name})"
            : normalizedHexCode;
    }

    private static bool TryParseNormalizedHex(string? value, out uint code)
    {
        code = 0;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        string candidate = value.Trim();
        if (!candidate.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        candidate = candidate[2..];
        return candidate.Length is > 0 and <= 8 &&
               uint.TryParse(candidate, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out code);
    }
}
