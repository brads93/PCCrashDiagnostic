using System.Globalization;
using System.Management;
using System.Text.Json;
using System.Text.RegularExpressions;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;
using Microsoft.Win32;

namespace BF6CrashDiagnostic.Core.Collectors;

internal sealed record StoredConfigurationValue(
    bool Exists,
    string? Value,
    int? RegistryValueKind = null);

internal sealed record WerConfigurationSnapshot(
    bool KeyExists,
    StoredConfigurationValue DumpType,
    StoredConfigurationValue DumpCount,
    StoredConfigurationValue DumpFolder);

internal static class WerConfigurationComparison
{
    public static bool Matches(
        WerConfigurationSnapshot current,
        WerConfigurationSnapshot expected) =>
        current.DumpType == expected.DumpType &&
        current.DumpCount == expected.DumpCount &&
        current.DumpFolder == expected.DumpFolder &&
        (!expected.KeyExists || current.KeyExists);
}

internal sealed record PageFileRuntimeSnapshot(
    bool? AutomaticManagementEnabled,
    int RuntimePageFileCount,
    long? RuntimeAllocatedBytes,
    DateTimeOffset? BootUtc,
    long? PhysicalMemoryBytes,
    int BootVolumeRuntimePageFileCount = 0,
    long? BootVolumeRuntimeAllocatedBytes = null,
    bool BootVolumeRuntimeStateKnown = false);

internal sealed record CrashCaptureEnvironmentSnapshot(
    bool DedicatedDumpFileConfigured,
    bool ConfiguredPageFilePresent,
    long? ConfiguredPageFileMinimumBytes,
    long? ConfiguredPageFileMaximumBytes,
    long? DedicatedDumpConfiguredBytes,
    long? DedicatedDumpActualBytes,
    long? DedicatedDumpDestinationFreeBytes,
    PageFileRuntimeSnapshot RuntimePageFiles,
    bool? DedicatedDumpDestinationAccessible = null,
    bool? BootVolumeConfiguredPageFilePresent = null,
    long? BootVolumeConfiguredPageFileMinimumBytes = null,
    long? BootVolumeConfiguredPageFileMaximumBytes = null);

internal interface ICrashCaptureConfigurationStore
{
    StoredConfigurationValue ReadCrashSetting(CrashCaptureSetting setting);

    void WriteCrashSetting(CrashCaptureSetting setting, StoredConfigurationValue value);

    WerConfigurationSnapshot ReadWerSettings(string executableName);

    void WriteWerSettings(string executableName, WerConfigurationSnapshot value);

    PageFileRuntimeSnapshot ReadPageFileRuntime();

    PageFileConfigurationSnapshot ReadPageFileConfiguration();

    void RestorePageFileConfiguration(PageFileConfigurationSnapshot snapshot);

    CrashCaptureEnvironmentSnapshot ReadEnvironment();
}

internal sealed class WindowsCrashCaptureConfigurationStore : ICrashCaptureConfigurationStore
{
    private const string CrashControlPath = @"SYSTEM\CurrentControlSet\Control\CrashControl";
    private const string WerLocalDumpsPath = @"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps";

    public StoredConfigurationValue ReadCrashSetting(CrashCaptureSetting setting)
    {
        if (setting == CrashCaptureSetting.AutomaticManagedPagefile)
        {
            bool? automaticValue = ReadPageFileRuntime().AutomaticManagementEnabled;
            return automaticValue is null
                ? new StoredConfigurationValue(false, null)
                : new StoredConfigurationValue(true, automaticValue.Value ? "true" : "false");
        }

        (string valueName, RegistryValueKind _) = RegistrySetting(setting);
        using RegistryKey? key = Registry.LocalMachine.OpenSubKey(CrashControlPath, writable: false);
        if (key is null || !key.GetValueNames().Contains(valueName, StringComparer.OrdinalIgnoreCase))
        {
            return new StoredConfigurationValue(false, null);
        }

        object? value = key.GetValue(valueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        return new StoredConfigurationValue(
            true,
            CanonicalRegistryValue(value),
            (int)key.GetValueKind(valueName));
    }

    public void WriteCrashSetting(CrashCaptureSetting setting, StoredConfigurationValue value)
    {
        if (setting == CrashCaptureSetting.AutomaticManagedPagefile)
        {
            if (!value.Exists || !bool.TryParse(value.Value, out bool enabled))
            {
                throw new InvalidDataException("Automatic page-file management requires a Boolean value.");
            }

            using var searcher = new ManagementObjectSearcher(
                "root\\CIMV2",
                "SELECT AutomaticManagedPagefile FROM Win32_ComputerSystem");
            using ManagementObjectCollection results = searcher.Get();
            ManagementObject? system = results.Cast<ManagementObject>().FirstOrDefault();
            if (system is null)
            {
                throw new IOException("Windows did not expose automatic page-file management.");
            }

            using (system)
            {
                system["AutomaticManagedPagefile"] = enabled;
                system.Put();
            }

            return;
        }

        (string valueName, RegistryValueKind _) = RegistrySetting(setting);
        using RegistryKey key = Registry.LocalMachine.CreateSubKey(CrashControlPath, writable: true)
            ?? throw new IOException("The Windows crash-control registry key could not be opened.");
        WriteRegistryValue(key, valueName, value);
    }

    public WerConfigurationSnapshot ReadWerSettings(string executableName)
    {
        string safeName = NormalizeExecutableName(executableName);
        using RegistryKey? parent = Registry.LocalMachine.OpenSubKey(WerLocalDumpsPath, writable: false);
        using RegistryKey? key = parent?.OpenSubKey(safeName, writable: false);
        if (key is null)
        {
            return new WerConfigurationSnapshot(
                false,
                new StoredConfigurationValue(false, null),
                new StoredConfigurationValue(false, null),
                new StoredConfigurationValue(false, null));
        }

        return new WerConfigurationSnapshot(
            true,
            ReadDword(key, "DumpType"),
            ReadDword(key, "DumpCount"),
            ReadString(key, "DumpFolder"));
    }

    public void WriteWerSettings(string executableName, WerConfigurationSnapshot value)
    {
        string safeName = NormalizeExecutableName(executableName);
        if (!value.KeyExists && !value.DumpType.Exists && !value.DumpCount.Exists && !value.DumpFolder.Exists)
        {
            using RegistryKey? parent = Registry.LocalMachine.OpenSubKey(WerLocalDumpsPath, writable: true);
            if (parent is null)
            {
                return;
            }

            using RegistryKey? existing = parent.OpenSubKey(safeName, writable: true);
            if (existing is null)
            {
                return;
            }

            // Restore only the three values this tool owns. A different writer may
            // have added unrelated values or subkeys after setup; those must survive.
            existing.DeleteValue("DumpType", throwOnMissingValue: false);
            existing.DeleteValue("DumpCount", throwOnMissingValue: false);
            existing.DeleteValue("DumpFolder", throwOnMissingValue: false);
            bool deleteKey = ShouldDeleteWerKeyAfterRestore(
                previousKeyExisted: false,
                existing.GetValueNames(),
                existing.GetSubKeyNames());
            existing.Dispose();
            if (deleteKey)
            {
                parent.DeleteSubKey(safeName, throwOnMissingSubKey: false);
            }

            return;
        }

        using RegistryKey parentKey = Registry.LocalMachine.CreateSubKey(WerLocalDumpsPath, writable: true)
            ?? throw new IOException("The Windows Error Reporting registry key could not be opened.");
        using RegistryKey key = parentKey.CreateSubKey(safeName, writable: true)
            ?? throw new IOException("The per-application Windows Error Reporting key could not be opened.");
        WriteRegistryValue(key, "DumpType", value.DumpType);
        WriteRegistryValue(key, "DumpCount", value.DumpCount);
        WriteRegistryValue(key, "DumpFolder", value.DumpFolder);
    }

    public PageFileRuntimeSnapshot ReadPageFileRuntime()
    {
        bool? automatic = null;
        int count = 0;
        long allocatedBytes = 0;
        bool allocationKnown = false;
        int bootVolumeCount = 0;
        long bootVolumeAllocatedBytes = 0;
        bool bootVolumeAllocationKnown = false;
        DateTimeOffset? bootUtc = null;
        long? physicalMemoryBytes = null;

        using (var searcher = new ManagementObjectSearcher(
                   "root\\CIMV2",
                   "SELECT AutomaticManagedPagefile, TotalPhysicalMemory FROM Win32_ComputerSystem"))
        using (ManagementObjectCollection results = searcher.Get())
        {
            using ManagementObject? system = results.Cast<ManagementObject>().FirstOrDefault();
            if (system?["AutomaticManagedPagefile"] is not null)
            {
                automatic = Convert.ToBoolean(system["AutomaticManagedPagefile"], CultureInfo.InvariantCulture);
            }

            if (system?["TotalPhysicalMemory"] is not null)
            {
                physicalMemoryBytes = Convert.ToInt64(system["TotalPhysicalMemory"], CultureInfo.InvariantCulture);
            }
        }

        using (var searcher = new ManagementObjectSearcher(
                   "root\\CIMV2",
                   "SELECT Name, AllocatedBaseSize FROM Win32_PageFileUsage"))
        using (ManagementObjectCollection results = searcher.Get())
        {
            foreach (ManagementObject pageFile in results.Cast<ManagementObject>())
            {
                using (pageFile)
                {
                    count++;
                    string? name = Convert.ToString(pageFile["Name"], CultureInfo.InvariantCulture);
                    bool bootVolume = IsBootVolumePath(name);
                    if (bootVolume)
                    {
                        bootVolumeCount++;
                    }

                    if (pageFile["AllocatedBaseSize"] is not null)
                    {
                        long megabytes = Convert.ToInt64(pageFile["AllocatedBaseSize"], CultureInfo.InvariantCulture);
                        allocatedBytes = checked(allocatedBytes + megabytes * 1024L * 1024L);
                        allocationKnown = true;
                        if (bootVolume)
                        {
                            bootVolumeAllocatedBytes = checked(
                                bootVolumeAllocatedBytes + megabytes * 1024L * 1024L);
                            bootVolumeAllocationKnown = true;
                        }
                    }
                }
            }
        }

        using (var searcher = new ManagementObjectSearcher(
                   "root\\CIMV2",
                   "SELECT LastBootUpTime FROM Win32_OperatingSystem"))
        using (ManagementObjectCollection results = searcher.Get())
        {
            using ManagementObject? operatingSystem = results.Cast<ManagementObject>().FirstOrDefault();
            if (operatingSystem?["LastBootUpTime"] is string value && !string.IsNullOrWhiteSpace(value))
            {
                bootUtc = new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(value)).ToUniversalTime();
            }
        }

        return new PageFileRuntimeSnapshot(
            automatic,
            count,
            allocationKnown ? allocatedBytes : null,
            bootUtc,
            physicalMemoryBytes,
            bootVolumeCount,
            bootVolumeAllocationKnown ? bootVolumeAllocatedBytes : null,
            BootVolumeRuntimeStateKnown: true);
    }

    public PageFileConfigurationSnapshot ReadPageFileConfiguration()
    {
        bool? automatic = ReadPageFileRuntime().AutomaticManagementEnabled;
        using RegistryKey? memoryManagement = Registry.LocalMachine.OpenSubKey(
            @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
            writable: false);
        bool exists = memoryManagement?.GetValueNames().Contains("PagingFiles", StringComparer.OrdinalIgnoreCase) == true;
        string[] entries = [];
        if (exists)
        {
            if (memoryManagement!.GetValueKind("PagingFiles") != RegistryValueKind.MultiString ||
                memoryManagement.GetValue(
                    "PagingFiles",
                    null,
                    RegistryValueOptions.DoNotExpandEnvironmentNames) is not string[] configuredEntries)
            {
                throw new InvalidDataException("Windows exposed PagingFiles in an unexpected registry format.");
            }

            entries = configuredEntries.ToArray();
        }

        return new PageFileConfigurationSnapshot(
            automatic.HasValue,
            automatic == true,
            exists,
            entries);
    }

    public void RestorePageFileConfiguration(PageFileConfigurationSnapshot snapshot)
    {
        ValidatePageFileConfigurationSnapshot(snapshot);
        PageFileConfigurationSnapshot current = ReadPageFileConfiguration();
        bool automaticWritten = false;
        try
        {
            WriteAutomaticPageFileManagement(snapshot.AutomaticManagementEnabled);
            automaticWritten = true;
            WritePagingFilesValue(snapshot);
        }
        catch
        {
            if (automaticWritten)
            {
                try
                {
                    WriteAutomaticPageFileManagement(current.AutomaticManagementEnabled);
                    WritePagingFilesValue(current);
                }
                catch (Exception rollbackException) when (rollbackException is IOException or UnauthorizedAccessException or
                                                          InvalidDataException or System.Management.ManagementException or
                                                          System.ComponentModel.Win32Exception)
                {
                }
            }

            throw;
        }
    }

    private void WriteAutomaticPageFileManagement(bool enabled) => WriteCrashSetting(
        CrashCaptureSetting.AutomaticManagedPagefile,
        new StoredConfigurationValue(true, enabled ? "true" : "false"));

    private static void WritePagingFilesValue(PageFileConfigurationSnapshot snapshot)
    {
        using RegistryKey memoryManagement = Registry.LocalMachine.CreateSubKey(
            @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
            writable: true)
            ?? throw new IOException("The Windows page-file configuration key could not be opened.");
        if (snapshot.PagingFilesValueExists)
        {
            memoryManagement.SetValue("PagingFiles", snapshot.PagingFiles.ToArray(), RegistryValueKind.MultiString);
        }
        else
        {
            memoryManagement.DeleteValue("PagingFiles", throwOnMissingValue: false);
        }
    }

    public CrashCaptureEnvironmentSnapshot ReadEnvironment()
    {
        bool dedicated = false;
        long? dedicatedConfiguredBytes = null;
        long? dedicatedActualBytes = null;
        long? dedicatedFreeBytes = null;
        bool? dedicatedAccessible = null;
        using (RegistryKey? crashControl = Registry.LocalMachine.OpenSubKey(CrashControlPath, writable: false))
        {
            string? dedicatedPath = Convert.ToString(
                crashControl?.GetValue(
                    "DedicatedDumpFile",
                    null,
                    RegistryValueOptions.DoNotExpandEnvironmentNames),
                CultureInfo.InvariantCulture);
            dedicated = !string.IsNullOrWhiteSpace(dedicatedPath);
            if (crashControl?.GetValue("DumpFileSize") is { } configuredSize)
            {
                long megabytes = Convert.ToInt64(configuredSize, CultureInfo.InvariantCulture);
                if (megabytes > 0)
                {
                    dedicatedConfiguredBytes = checked(megabytes * 1024L * 1024L);
                }
            }

            if (dedicated && dedicatedPath is not null)
            {
                try
                {
                    if (!TryNormalizeLocalFixedDrivePath(dedicatedPath, out string expanded, out DriveInfo? drive))
                    {
                        dedicatedAccessible = false;
                    }
                    else
                    {
                        PathSafety.EnsureNoReparseComponents(expanded);
                        string? directory = Path.GetDirectoryName(expanded);
                        dedicatedAccessible = !string.IsNullOrWhiteSpace(directory) && Directory.Exists(directory);
                        if (File.Exists(expanded))
                        {
                            dedicatedActualBytes = new FileInfo(expanded).Length;
                        }

                        dedicatedFreeBytes = drive!.AvailableFreeSpace;
                    }
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
                {
                    dedicatedAccessible = false;
                }
            }
        }

        bool configured = false;
        long configuredMinimumBytes = 0;
        long configuredMaximumBytes = 0;
        bool hasSizedEntry = false;
        bool dynamicSizing = false;
        bool bootConfigured = false;
        long bootMinimumBytes = 0;
        long bootMaximumBytes = 0;
        bool bootHasSizedEntry = false;
        bool bootDynamicSizing = false;
        using (RegistryKey? memoryManagement = Registry.LocalMachine.OpenSubKey(
                   @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
                   writable: false))
        {
            object? pagingFiles = memoryManagement?.GetValue(
                "PagingFiles",
                null,
                RegistryValueOptions.DoNotExpandEnvironmentNames);
            configured = pagingFiles switch
            {
                string entry => !string.IsNullOrWhiteSpace(entry),
                string[] configuredEntries => configuredEntries.Any(entry => !string.IsNullOrWhiteSpace(entry)),
                _ => false
            };

            IEnumerable<string> entries = pagingFiles switch
            {
                string entry when !string.IsNullOrWhiteSpace(entry) => [entry],
                string[] values => values.Where(value => !string.IsNullOrWhiteSpace(value)),
                _ => []
            };
            foreach (string entry in entries)
            {
                bool bootEntry = IsBootVolumePageFileEntry(entry);
                bootConfigured |= bootEntry;
                Match match = Regex.Match(
                    entry,
                    @"\s+(?<minimum>\d+)\s+(?<maximum>\d+)\s*$",
                    RegexOptions.CultureInvariant);
                if (!match.Success)
                {
                    dynamicSizing |= entry.TrimStart().StartsWith(@"?:\pagefile.sys", StringComparison.OrdinalIgnoreCase);
                    bootDynamicSizing |= bootEntry;
                    continue;
                }

                long minimumMb = long.Parse(match.Groups["minimum"].Value, CultureInfo.InvariantCulture);
                long maximumMb = long.Parse(match.Groups["maximum"].Value, CultureInfo.InvariantCulture);
                if (minimumMb == 0 && maximumMb == 0)
                {
                    dynamicSizing = true;
                    bootDynamicSizing |= bootEntry;
                    continue;
                }

                configuredMinimumBytes = checked(configuredMinimumBytes + minimumMb * 1024L * 1024L);
                configuredMaximumBytes = checked(configuredMaximumBytes + maximumMb * 1024L * 1024L);
                hasSizedEntry = true;
                if (bootEntry)
                {
                    bootMinimumBytes = checked(bootMinimumBytes + minimumMb * 1024L * 1024L);
                    bootMaximumBytes = checked(bootMaximumBytes + maximumMb * 1024L * 1024L);
                    bootHasSizedEntry = true;
                }
            }
        }

        return new CrashCaptureEnvironmentSnapshot(
            dedicated,
            configured,
            hasSizedEntry && !dynamicSizing ? configuredMinimumBytes : null,
            hasSizedEntry && !dynamicSizing ? configuredMaximumBytes : null,
            dedicatedConfiguredBytes,
            dedicatedActualBytes,
            dedicatedFreeBytes,
            ReadPageFileRuntime(),
            dedicatedAccessible,
            bootConfigured,
            bootHasSizedEntry && !bootDynamicSizing ? bootMinimumBytes : null,
            bootHasSizedEntry && !bootDynamicSizing ? bootMaximumBytes : null);
    }

    private static bool IsBootVolumePageFileEntry(string entry)
    {
        string trimmed = entry.Trim();
        if (trimmed.StartsWith(@"?:\pagefile.sys", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        Match match = Regex.Match(trimmed, @"^(?<path>.+?)\s+\d+\s+\d+\s*$", RegexOptions.CultureInvariant);
        return IsBootVolumePath(match.Success ? match.Groups["path"].Value.Trim('"') : trimmed);
    }

    private static bool IsBootVolumePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        string? systemRoot = Path.GetPathRoot(Environment.SystemDirectory);
        string? pathRoot;
        try
        {
            pathRoot = Path.GetPathRoot(Environment.ExpandEnvironmentVariables(path));
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            return false;
        }

        return !string.IsNullOrWhiteSpace(systemRoot) &&
               string.Equals(pathRoot, systemRoot, StringComparison.OrdinalIgnoreCase);
    }

    internal static bool TryNormalizeLocalFixedDrivePath(
        string configuredPath,
        out string fullPath,
        out DriveInfo? drive)
    {
        fullPath = string.Empty;
        drive = null;
        if (string.IsNullOrWhiteSpace(configuredPath))
        {
            return false;
        }

        string expanded = Environment.ExpandEnvironmentVariables(configuredPath.Trim());
        if (!Regex.IsMatch(expanded, @"^[A-Za-z]:[\\/]", RegexOptions.CultureInvariant) ||
            expanded.StartsWith(@"\\", StringComparison.Ordinal) ||
            expanded.StartsWith(@"//", StringComparison.Ordinal) ||
            expanded.StartsWith(@"\\?\", StringComparison.Ordinal) ||
            expanded.StartsWith(@"\\.\", StringComparison.Ordinal) ||
            expanded.StartsWith(@"\??\", StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            fullPath = Path.GetFullPath(expanded);
            string? root = Path.GetPathRoot(fullPath);
            if (root is null || !Regex.IsMatch(root, @"^[A-Za-z]:\\$", RegexOptions.CultureInvariant))
            {
                fullPath = string.Empty;
                return false;
            }

            var candidateDrive = new DriveInfo(root);
            if (candidateDrive.DriveType != DriveType.Fixed)
            {
                fullPath = string.Empty;
                return false;
            }

            drive = candidateDrive;
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                          ArgumentException or NotSupportedException)
        {
            fullPath = string.Empty;
            drive = null;
            return false;
        }
    }

    internal static string NormalizeExecutableName(string executableName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executableName);
        string name = executableName.Trim();
        if (name.Length > 128 ||
            !name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(Path.GetFileName(name), name, StringComparison.Ordinal) ||
            name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            throw new ArgumentException("The WER target must be one executable basename.", nameof(executableName));
        }

        return name;
    }

    internal static bool ShouldDeleteWerKeyAfterRestore(
        bool previousKeyExisted,
        IEnumerable<string> remainingValueNames,
        IEnumerable<string> remainingSubKeyNames)
    {
        ArgumentNullException.ThrowIfNull(remainingValueNames);
        ArgumentNullException.ThrowIfNull(remainingSubKeyNames);
        if (previousKeyExisted)
        {
            return false;
        }

        bool hasUnknownValue = remainingValueNames.Any(name =>
            !name.Equals("DumpType", StringComparison.OrdinalIgnoreCase) &&
            !name.Equals("DumpCount", StringComparison.OrdinalIgnoreCase) &&
            !name.Equals("DumpFolder", StringComparison.OrdinalIgnoreCase));
        return !hasUnknownValue && !remainingSubKeyNames.Any();
    }

    private static (string Name, RegistryValueKind Kind) RegistrySetting(CrashCaptureSetting setting) => setting switch
    {
        CrashCaptureSetting.CrashDumpEnabled => ("CrashDumpEnabled", RegistryValueKind.DWord),
        CrashCaptureSetting.FilterPages => ("FilterPages", RegistryValueKind.DWord),
        CrashCaptureSetting.DumpFile => ("DumpFile", RegistryValueKind.ExpandString),
        CrashCaptureSetting.MinidumpDirectory => ("MinidumpDir", RegistryValueKind.ExpandString),
        CrashCaptureSetting.EventLogging => ("LogEvent", RegistryValueKind.DWord),
        CrashCaptureSetting.OverwriteExistingDump => ("Overwrite", RegistryValueKind.DWord),
        _ => throw new ArgumentOutOfRangeException(nameof(setting), "The crash-capture setting is not registry-backed.")
    };

    private static StoredConfigurationValue ReadDword(RegistryKey key, string name)
    {
        if (!key.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            return new StoredConfigurationValue(false, null);
        }

        return new StoredConfigurationValue(
            true,
            Convert.ToInt32(key.GetValue(name), CultureInfo.InvariantCulture)
                .ToString(CultureInfo.InvariantCulture),
            (int)key.GetValueKind(name));
    }

    private static StoredConfigurationValue ReadString(RegistryKey key, string name)
    {
        if (!key.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            return new StoredConfigurationValue(false, null);
        }

        return new StoredConfigurationValue(
            true,
            Convert.ToString(
                key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames),
                CultureInfo.InvariantCulture),
            (int)key.GetValueKind(name));
    }

    private static void WriteRegistryValue(RegistryKey key, string name, StoredConfigurationValue value)
    {
        if (!value.Exists)
        {
            key.DeleteValue(name, throwOnMissingValue: false);
            return;
        }

        if (value.RegistryValueKind is not { } rawKind ||
            !Enum.IsDefined(typeof(RegistryValueKind), rawKind))
        {
            throw new InvalidDataException("A registry value kind was missing or invalid.");
        }

        RegistryValueKind kind = (RegistryValueKind)rawKind;
        switch (kind)
        {
            case RegistryValueKind.DWord:
                if (!int.TryParse(value.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int dword))
                {
                    throw new InvalidDataException("A registry DWORD value was invalid.");
                }

                key.SetValue(name, dword, kind);
                break;
            case RegistryValueKind.QWord:
                if (!long.TryParse(value.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long qword))
                {
                    throw new InvalidDataException("A registry QWORD value was invalid.");
                }

                key.SetValue(name, qword, kind);
                break;
            case RegistryValueKind.String:
            case RegistryValueKind.ExpandString:
                key.SetValue(name, value.Value ?? string.Empty, kind);
                break;
            default:
                throw new InvalidDataException("The registry value kind could not be restored exactly and safely.");
        }
    }

    private static string? CanonicalRegistryValue(object? value) => value switch
    {
        null => null,
        string text => text,
        int number => number.ToString(CultureInfo.InvariantCulture),
        uint number => number.ToString(CultureInfo.InvariantCulture),
        long number => number.ToString(CultureInfo.InvariantCulture),
        _ => Convert.ToString(value, CultureInfo.InvariantCulture)
    };

    internal static void ValidatePageFileConfigurationSnapshot(PageFileConfigurationSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        if (!snapshot.AutomaticManagementStateKnown ||
            snapshot.PagingFiles is null || snapshot.PagingFiles.Count > 32 ||
            snapshot.PagingFiles.Any(entry => string.IsNullOrWhiteSpace(entry) || entry.Length > 1_024) ||
            !snapshot.PagingFilesValueExists && snapshot.PagingFiles.Count != 0)
        {
            throw new InvalidDataException("The saved page-file configuration was invalid.");
        }
    }
}

internal sealed class CrashCaptureReceiptStore
{
    private const int MaximumReceiptBytes = 64 * 1024;
    private const int MaximumReceiptsToInspect = 256;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        MaxDepth = 16
    };

    private readonly string _root;
    private readonly bool _hardenedAcl;
    private readonly System.Security.Principal.SecurityIdentifier? _originatingUserSid;

    public CrashCaptureReceiptStore()
        : this(
            DefaultRoot,
            hardenedAcl: true,
            System.Security.Principal.WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException("The current Windows user SID was unavailable."))
    {
    }

    internal CrashCaptureReceiptStore(string root)
        : this(root, hardenedAcl: false, originatingUserSid: null)
    {
    }

    private CrashCaptureReceiptStore(
        string root,
        bool hardenedAcl,
        System.Security.Principal.SecurityIdentifier? originatingUserSid)
    {
        _root = Path.GetFullPath(root);
        _hardenedAcl = hardenedAcl;
        _originatingUserSid = originatingUserSid;
    }

    internal static CrashCaptureReceiptStore CreateForElevatedOrigin(
        string dataRoot,
        System.Security.Principal.SecurityIdentifier originatingUserSid) => new(
        Path.Combine(Path.GetFullPath(dataRoot), "ConfigurationReceipts"),
        hardenedAcl: true,
        originatingUserSid);

    internal static string DefaultRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "PCCrashDiagnostic",
        (System.Security.Principal.WindowsIdentity.GetCurrent().User ??
         throw new InvalidOperationException("The current Windows user SID was unavailable.")).Value,
        "ConfigurationReceipts");

    public void Save(CrashCaptureReceipt receipt) => Save(receipt.ReceiptId, "crash", receipt, overwrite: false);

    public void Save(WerLocalDumpReceipt receipt) => Save(receipt.ReceiptId, "wer", receipt, overwrite: false);

    public void Replace(CrashCaptureReceipt receipt) => Save(receipt.ReceiptId, "crash", receipt, overwrite: true);

    public void Replace(WerLocalDumpReceipt receipt) => Save(receipt.ReceiptId, "wer", receipt, overwrite: true);

    public CrashCaptureReceipt ReadCrash(string receiptId) => Read<CrashCaptureReceipt>(receiptId, "crash");

    public WerLocalDumpReceipt ReadWer(string receiptId) => Read<WerLocalDumpReceipt>(receiptId, "wer");

    public ReceiptStoreDiscovery DiscoverCandidates()
    {
        var crashReceipts = new List<CrashCaptureReceipt>();
        var werReceipts = new List<WerLocalDumpReceipt>();
        var warnings = new List<string>();
        int skipped = 0;
        try
        {
            PathSafety.EnsureNoReparseComponents(_root);
            if (!Directory.Exists(_root))
            {
                return new ReceiptStoreDiscovery([], [], []);
            }

            EnsureRootForRead();
            string[] paths = Directory.EnumerateFiles(_root, "*.json", SearchOption.TopDirectoryOnly)
                .Take(MaximumReceiptsToInspect + 1)
                .ToArray();
            if (paths.Length > MaximumReceiptsToInspect)
            {
                warnings.Add($"Only {MaximumReceiptsToInspect} saved configuration receipts were inspected in this pass.");
            }

            foreach (string path in paths.Take(MaximumReceiptsToInspect))
            {
                if (TryReadCandidate(path, ".crash.json", out CrashCaptureReceipt? crash))
                {
                    if (crash is { Restored: false })
                    {
                        crashReceipts.Add(crash);
                    }

                    continue;
                }

                if (TryReadCandidate(path, ".wer.json", out WerLocalDumpReceipt? wer))
                {
                    if (wer is { Restored: false })
                    {
                        werReceipts.Add(wer);
                    }

                    continue;
                }

                skipped++;
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                          System.Security.SecurityException or ArgumentException or JsonException or
                                          InvalidOperationException)
        {
            warnings.Add("Saved configuration receipts could not be inspected safely.");
            return new ReceiptStoreDiscovery([], [], warnings);
        }

        if (skipped > 0)
        {
            warnings.Add($"{skipped} malformed or unsafe saved configuration receipt(s) were ignored.");
        }

        return new ReceiptStoreDiscovery(
            crashReceipts.OrderByDescending(receipt => receipt.AppliedUtc).ToArray(),
            werReceipts.OrderByDescending(receipt => receipt.AppliedUtc).ToArray(),
            warnings);
    }

    public CrashCaptureReceipt? TryReadLatestCrash()
    {
        try
        {
            PathSafety.EnsureNoReparseComponents(_root);
            if (!Directory.Exists(_root))
            {
                return null;
            }

            EnsureRootForRead();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                          System.Security.SecurityException or InvalidOperationException)
        {
            return null;
        }

        foreach (string path in Directory.EnumerateFiles(_root, "*.crash.json", SearchOption.TopDirectoryOnly)
                     .Take(MaximumReceiptsToInspect)
                     .OrderByDescending(File.GetLastWriteTimeUtc))
        {
            if (TryReadCandidate(path, ".crash.json", out CrashCaptureReceipt? receipt))
            {
                return receipt;
            }
        }

        return null;
    }

    private bool TryReadCandidate<T>(string path, string suffix, out T? receipt)
        where T : class
    {
        receipt = null;
        string fileName = Path.GetFileName(path);
        if (!fileName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        string id = fileName[..^suffix.Length];
        try
        {
            string normalizedId = NormalizeReceiptId(id);
            string fullPath = PathSafety.EnsureContained(_root, path);
            EnsureSafeReceiptFile(fullPath);
            var info = new FileInfo(fullPath);
            if (info.Length is <= 0 or > MaximumReceiptBytes)
            {
                return false;
            }

            using var input = new FileStream(
                fullPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                4096,
                FileOptions.SequentialScan);
            receipt = JsonSerializer.Deserialize<T>(input, JsonOptions);
            string? receiptId = receipt switch
            {
                CrashCaptureReceipt crash => crash.ReceiptId,
                WerLocalDumpReceipt wer => wer.ReceiptId,
                _ => null
            };
            if (!string.Equals(receiptId, normalizedId, StringComparison.OrdinalIgnoreCase))
            {
                receipt = null;
                return false;
            }

            return receipt is not null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                          System.Security.SecurityException or ArgumentException or JsonException or
                                          InvalidOperationException)
        {
            receipt = null;
            return false;
        }
    }

    private void Save<T>(string receiptId, string kind, T receipt, bool overwrite)
    {
        EnsureRootForWrite();
        string path = ReceiptPath(receiptId, kind);
        PathSafety.EnsureNoReparseComponents(_root, path);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(receipt, JsonOptions);
        if (bytes.Length is <= 0 or > MaximumReceiptBytes)
        {
            throw new InvalidDataException("The configuration receipt exceeded its fixed size limit.");
        }

        if (!overwrite && (File.Exists(path) || Directory.Exists(path)))
        {
            throw new IOException("The configuration receipt already exists.");
        }

        if (overwrite)
        {
            EnsureSafeReceiptFile(path);
            long existingLength = new FileInfo(path).Length;
            if (existingLength is <= 0 or > MaximumReceiptBytes)
            {
                throw new InvalidDataException("The existing configuration receipt was malformed.");
            }
        }

        byte[]? previousBytes = overwrite ? File.ReadAllBytes(path) : null;

        string temporary = PathSafety.CreateRandomTemporaryPath(_root, _root, "receipt");
        bool movedIntoPlace = false;
        try
        {
            using (var output = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                output.Write(bytes);
                output.Flush(flushToDisk: true);
            }

            if (_hardenedAcl)
            {
                ConfigurationReceiptAcl.ProtectFile(
                    temporary,
                    _originatingUserSid ?? throw new InvalidOperationException("The receipt origin SID was missing."));
            }

            PathSafety.EnsureSafeExistingFile(_root, temporary);
            PathSafety.EnsureNoReparseComponents(_root, path);
            File.Move(temporary, path, overwrite);
            movedIntoPlace = true;
            if (_hardenedAcl)
            {
                ConfigurationReceiptAcl.VerifyFile(
                    path,
                    _originatingUserSid ?? throw new InvalidOperationException("The receipt origin SID was missing."));
            }
        }
        catch
        {
            // A move can succeed before a later ACL verification fails. Repair
            // the persistent state before the caller compensates registry writes.
            bool committed = movedIntoPlace || ReceiptBytesEqual(path, bytes);
            if (committed)
            {
                if (previousBytes is null)
                {
                    PathSafety.TryDeleteFile(_root, path);
                }
                else
                {
                    _ = TryRestoreReceiptBytes(path, previousBytes);
                }
            }

            throw;
        }
        finally
        {
            PathSafety.TryDeleteFile(_root, temporary);
        }
    }

    private bool TryRestoreReceiptBytes(string path, byte[] bytes)
    {
        string repair = PathSafety.CreateRandomTemporaryPath(_root, _root, "receipt-repair");
        try
        {
            using (var output = new FileStream(
                       repair,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            {
                output.Write(bytes);
                output.Flush(flushToDisk: true);
            }

            if (_hardenedAcl)
            {
                ConfigurationReceiptAcl.ProtectFile(
                    repair,
                    _originatingUserSid ?? throw new InvalidOperationException("The receipt origin SID was missing."));
            }

            PathSafety.EnsureSafeExistingFile(_root, repair);
            File.Move(repair, path, overwrite: true);
            if (_hardenedAcl)
            {
                ConfigurationReceiptAcl.VerifyFile(
                    path,
                    _originatingUserSid ?? throw new InvalidOperationException("The receipt origin SID was missing."));
            }

            return ReceiptBytesEqual(path, bytes);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                          System.Security.SecurityException or InvalidOperationException)
        {
            return false;
        }
        finally
        {
            PathSafety.TryDeleteFile(_root, repair);
        }
    }

    private static bool ReceiptBytesEqual(string path, byte[] expected)
    {
        try
        {
            if (!File.Exists(path))
            {
                return false;
            }

            var info = new FileInfo(path);
            return info.Length == expected.Length &&
                   File.ReadAllBytes(path).AsSpan().SequenceEqual(expected);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                          System.Security.SecurityException or ArgumentException)
        {
            return false;
        }
    }

    private T Read<T>(string receiptId, string kind)
    {
        EnsureRootForRead();
        string path = ReceiptPath(receiptId, kind);
        EnsureSafeReceiptFile(path);
        var info = new FileInfo(path);
        if (info.Length is <= 0 or > MaximumReceiptBytes)
        {
            throw new InvalidDataException("The configuration receipt was malformed.");
        }

        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 4096, FileOptions.SequentialScan);
        return JsonSerializer.Deserialize<T>(input, JsonOptions)
            ?? throw new InvalidDataException("The configuration receipt was empty.");
    }

    private void EnsureRootForWrite()
    {
        PathSafety.EnsureNoReparseComponents(_root);
        Directory.CreateDirectory(_root);
        PathSafety.EnsureNoReparseComponents(_root);
        if (_hardenedAcl)
        {
            ConfigurationReceiptAcl.ProtectDirectory(
                _root,
                _originatingUserSid ?? throw new InvalidOperationException("The receipt origin SID was missing."));
        }
        else
        {
            PrivateDirectoryAcl.EnsureRestrictedToCurrentUserAndSystem(_root);
        }
    }

    private void EnsureRootForRead()
    {
        PathSafety.EnsureNoReparseComponents(_root);
        if (!Directory.Exists(_root))
        {
            throw new DirectoryNotFoundException("The configuration receipt folder does not exist.");
        }

        if (_hardenedAcl)
        {
            ConfigurationReceiptAcl.VerifyDirectory(
                _root,
                _originatingUserSid ?? throw new InvalidOperationException("The receipt origin SID was missing."));
        }
        else
        {
            PrivateDirectoryAcl.EnsureRestrictedToCurrentUserAndSystem(_root);
        }
    }

    private void EnsureSafeReceiptFile(string path)
    {
        PathSafety.EnsureSafeExistingFile(_root, path);
        if (_hardenedAcl)
        {
            ConfigurationReceiptAcl.VerifyFile(
                path,
                _originatingUserSid ?? throw new InvalidOperationException("The receipt origin SID was missing."));
        }
    }

    private string ReceiptPath(string receiptId, string kind)
    {
        string normalized = NormalizeReceiptId(receiptId);
        return PathSafety.EnsureContained(_root, Path.Combine(_root, normalized + "." + kind + ".json"));
    }

    internal static string NormalizeReceiptId(string receiptId)
    {
        if (receiptId.Length != 32 || receiptId.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new ArgumentException("The configuration receipt id was invalid.", nameof(receiptId));
        }

        return receiptId.ToLowerInvariant();
    }
}

internal sealed record ReceiptStoreDiscovery(
    IReadOnlyList<CrashCaptureReceipt> CrashReceipts,
    IReadOnlyList<WerLocalDumpReceipt> WerReceipts,
    IReadOnlyList<string> Warnings);

internal static class ConfigurationReceiptAcl
{
    private const System.Security.AccessControl.FileSystemRights UserReadRights =
        System.Security.AccessControl.FileSystemRights.ReadAndExecute |
        System.Security.AccessControl.FileSystemRights.Synchronize;

    public static void ProtectDirectory(
        string path,
        System.Security.Principal.SecurityIdentifier originatingUserSid)
    {
        try
        {
            var directory = new DirectoryInfo(path);
            var security = new System.Security.AccessControl.DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            AddRules(security, directoryInheritance: true, originatingUserSid);
            directory.SetAccessControl(security);
            VerifyDirectory(path, originatingUserSid);
        }
        catch (Exception exception) when (IsAclFailure(exception))
        {
            throw new IOException("The elevated configuration receipt folder could not be protected.", exception);
        }
    }

    public static void ProtectFile(
        string path,
        System.Security.Principal.SecurityIdentifier originatingUserSid)
    {
        try
        {
            var file = new FileInfo(path);
            var security = new System.Security.AccessControl.FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            AddRules(security, directoryInheritance: false, originatingUserSid);
            file.SetAccessControl(security);
            VerifyFile(path, originatingUserSid);
        }
        catch (Exception exception) when (IsAclFailure(exception))
        {
            throw new IOException("The elevated configuration receipt could not be protected.", exception);
        }
    }

    public static void VerifyDirectory(
        string path,
        System.Security.Principal.SecurityIdentifier originatingUserSid) =>
        Verify(new DirectoryInfo(path).GetAccessControl(), originatingUserSid);

    public static void VerifyFile(
        string path,
        System.Security.Principal.SecurityIdentifier originatingUserSid) =>
        Verify(new FileInfo(path).GetAccessControl(), originatingUserSid);

    private static void AddRules(
        System.Security.AccessControl.FileSystemSecurity security,
        bool directoryInheritance,
        System.Security.Principal.SecurityIdentifier originatingUserSid)
    {
        (System.Security.Principal.SecurityIdentifier administrators,
            System.Security.Principal.SecurityIdentifier system) = Principals();
        security.SetOwner(administrators);
        System.Security.AccessControl.InheritanceFlags inheritance = directoryInheritance
            ? System.Security.AccessControl.InheritanceFlags.ContainerInherit |
              System.Security.AccessControl.InheritanceFlags.ObjectInherit
            : System.Security.AccessControl.InheritanceFlags.None;
        foreach (System.Security.Principal.SecurityIdentifier principal in new[] { administrators, system })
        {
            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                principal,
                System.Security.AccessControl.FileSystemRights.FullControl,
                inheritance,
                System.Security.AccessControl.PropagationFlags.None,
                System.Security.AccessControl.AccessControlType.Allow));
        }

        security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
            originatingUserSid,
            UserReadRights,
            inheritance,
            System.Security.AccessControl.PropagationFlags.None,
            System.Security.AccessControl.AccessControlType.Allow));
    }

    private static void Verify(
        System.Security.AccessControl.FileSystemSecurity security,
        System.Security.Principal.SecurityIdentifier originatingUserSid)
    {
        (System.Security.Principal.SecurityIdentifier administrators,
            System.Security.Principal.SecurityIdentifier system) = Principals();
        System.Security.Principal.IdentityReference? owner = security.GetOwner(
            typeof(System.Security.Principal.SecurityIdentifier));
        if (!security.AreAccessRulesProtected ||
            owner is null || !owner.Equals(administrators) && !owner.Equals(system))
        {
            throw new UnauthorizedAccessException("The configuration receipt owner or inheritance was unsafe.");
        }

        const System.Security.AccessControl.FileSystemRights writeRights =
            System.Security.AccessControl.FileSystemRights.Write |
            System.Security.AccessControl.FileSystemRights.Modify |
            System.Security.AccessControl.FileSystemRights.FullControl |
            System.Security.AccessControl.FileSystemRights.ChangePermissions |
            System.Security.AccessControl.FileSystemRights.TakeOwnership |
            System.Security.AccessControl.FileSystemRights.Delete;
        foreach (System.Security.AccessControl.FileSystemAccessRule rule in security.GetAccessRules(
                     includeExplicit: true,
                     includeInherited: true,
                     typeof(System.Security.Principal.SecurityIdentifier)))
        {
            if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow ||
                rule.IdentityReference is not System.Security.Principal.SecurityIdentifier sid)
            {
                continue;
            }

            bool trustedWriter = sid.Equals(administrators) || sid.Equals(system);
            if ((!trustedWriter && (rule.FileSystemRights & writeRights) != 0) ||
                (sid.Equals(originatingUserSid) && (rule.FileSystemRights & writeRights) != 0))
            {
                throw new UnauthorizedAccessException("The configuration receipt ACL allowed an unelevated writer.");
            }
        }
    }

    private static (
        System.Security.Principal.SecurityIdentifier Administrators,
        System.Security.Principal.SecurityIdentifier System) Principals()
    {
        var administrators = new System.Security.Principal.SecurityIdentifier(
            System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid,
            null);
        var system = new System.Security.Principal.SecurityIdentifier(
            System.Security.Principal.WellKnownSidType.LocalSystemSid,
            null);
        return (administrators, system);
    }

    private static bool IsAclFailure(Exception exception) => exception is
        PlatformNotSupportedException or UnauthorizedAccessException or
        System.Security.SecurityException or InvalidOperationException or
        System.ComponentModel.Win32Exception;
}

internal static class MachineDataRootAcl
{
    public static void EnsureAdminOwned(string path)
    {
        string fullPath = Path.GetFullPath(path);
        PathSafety.EnsureNoReparseComponents(fullPath);
        bool existed = Directory.Exists(fullPath);
        if (!existed)
        {
            Directory.CreateDirectory(fullPath);
            PathSafety.EnsureNoReparseComponents(fullPath);
            Protect(fullPath);
        }

        Verify(fullPath);
    }

    private static void Protect(string path)
    {
        var administrators = new System.Security.Principal.SecurityIdentifier(
            System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid,
            null);
        var system = new System.Security.Principal.SecurityIdentifier(
            System.Security.Principal.WellKnownSidType.LocalSystemSid,
            null);
        var security = new System.Security.AccessControl.DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(administrators);
        foreach (System.Security.Principal.SecurityIdentifier sid in new[] { administrators, system })
        {
            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                sid,
                System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                System.Security.AccessControl.PropagationFlags.None,
                System.Security.AccessControl.AccessControlType.Allow));
        }

        new DirectoryInfo(path).SetAccessControl(security);
    }

    private static void Verify(string path)
    {
        var administrators = new System.Security.Principal.SecurityIdentifier(
            System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid,
            null);
        var system = new System.Security.Principal.SecurityIdentifier(
            System.Security.Principal.WellKnownSidType.LocalSystemSid,
            null);
        System.Security.AccessControl.DirectorySecurity security = new DirectoryInfo(path).GetAccessControl();
        System.Security.Principal.IdentityReference? owner = security.GetOwner(
            typeof(System.Security.Principal.SecurityIdentifier));
        if (!security.AreAccessRulesProtected || owner is null ||
            !owner.Equals(administrators) && !owner.Equals(system))
        {
            throw new UnauthorizedAccessException("The global diagnostic data root owner or inheritance was unsafe.");
        }

        const System.Security.AccessControl.FileSystemRights writeRights =
            System.Security.AccessControl.FileSystemRights.Write |
            System.Security.AccessControl.FileSystemRights.Modify |
            System.Security.AccessControl.FileSystemRights.FullControl |
            System.Security.AccessControl.FileSystemRights.DeleteSubdirectoriesAndFiles |
            System.Security.AccessControl.FileSystemRights.ChangePermissions |
            System.Security.AccessControl.FileSystemRights.TakeOwnership;
        foreach (System.Security.AccessControl.FileSystemAccessRule rule in security.GetAccessRules(
                     includeExplicit: true,
                     includeInherited: true,
                     typeof(System.Security.Principal.SecurityIdentifier)))
        {
            if (rule.AccessControlType == System.Security.AccessControl.AccessControlType.Allow &&
                rule.IdentityReference is System.Security.Principal.SecurityIdentifier sid &&
                (rule.FileSystemRights & writeRights) != 0 &&
                !sid.Equals(administrators) && !sid.Equals(system))
            {
                throw new UnauthorizedAccessException("An unelevated principal could replace the global diagnostic data root.");
            }
        }
    }
}
