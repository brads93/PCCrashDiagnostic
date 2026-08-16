using System.Text.Json;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class CrashEvidenceCollectorTests
{
    [Fact]
    public void CrashReadiness_MapsKnownSettingsWithoutRetainingPageFilePaths()
    {
        DateTimeOffset capturedUtc = new(2026, 8, 2, 4, 42, 18, TimeSpan.Zero);
        var values = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["CrashDumpEnabled"] = 7,
            ["LogEvent"] = 1,
            ["AutoReboot"] = 0,
            ["Overwrite"] = 1,
            ["AlwaysKeepMemoryDump"] = 0,
            ["DedicatedDumpFile"] = @"D:\Dumps\dedicated.dmp",
            ["DumpFile"] = @"D:\Dumps\MEMORY.DMP",
            ["MinidumpDir"] = @"C:\Windows\Minidump"
        };

        CrashReadiness actual = CrashReadinessCollector.CreateReadiness(
            capturedUtc,
            values,
            new[] { @"C:\pagefile.sys 0 0" },
            50,
            100);

        Assert.Equal(CrashDumpMode.AutomaticMemory, actual.DumpMode);
        Assert.Equal(7, actual.RawDumpMode);
        Assert.True(actual.EventLoggingEnabled);
        Assert.False(actual.AutoRebootEnabled);
        Assert.True(actual.OverwriteEnabled);
        Assert.False(actual.AlwaysKeepMemoryDump);
        Assert.True(actual.DedicatedDumpFileConfigured);
        Assert.Equal(1, actual.PageFileEntryCount);
        Assert.True(actual.SystemManagedPageFile);
        Assert.Equal(50, actual.SystemDriveFreeBytes);
        Assert.Equal(100, actual.SystemDriveTotalBytes);
        Assert.DoesNotContain("D:\\Dumps", actual.DumpFileLocation, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("pagefile.sys", JsonSerializer.Serialize(actual), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CrashReadiness_PreservesUnknownRawModeWithoutInventingMeaning()
    {
        CrashReadiness actual = CrashReadinessCollector.CreateReadiness(
            DateTimeOffset.UnixEpoch,
            new Dictionary<string, object?> { ["CrashDumpEnabled"] = 99 },
            pagingFiles: null,
            systemDriveFreeBytes: -1,
            systemDriveTotalBytes: -1);

        Assert.Equal(CrashDumpMode.Unknown, actual.DumpMode);
        Assert.Equal(99, actual.RawDumpMode);
        Assert.Null(actual.SystemManagedPageFile);
        Assert.Null(actual.SystemDriveFreeBytes);
        Assert.Null(actual.SystemDriveTotalBytes);
    }

    [Fact]
    public void DriverDeviceCollector_EmitsOnlyAllowlistedPrivacyFilteredFields()
    {
        const string privateDeviceId = @"PCI\VEN_1234&DEV_5678\PRIVATE-SERIAL";
        var values = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase)
        {
            ["DeviceClass"] = "DISPLAY",
            ["DeviceName"] = "Example GPU",
            ["Manufacturer"] = "Example",
            ["DriverProviderName"] = "Example Provider",
            ["DriverVersion"] = "1.2.3.4",
            ["InfName"] = "oem42.inf",
            ["IsSigned"] = true,
            ["Signer"] = "Microsoft Windows Hardware Compatibility Publisher",
            ["DeviceID"] = privateDeviceId,
            ["PNPDeviceID"] = privateDeviceId,
            ["LocationInformation"] = "PCI bus 1, device 0",
            ["HardwareID"] = privateDeviceId,
            ["UserName"] = "private-user"
        };

        DriverDeviceRecord actual = Assert.IsType<DriverDeviceRecord>(
            DriverDeviceCollector.CreateRecord(values));
        string json = JsonSerializer.Serialize(actual);

        Assert.Equal("DISPLAY", actual.DeviceClass);
        Assert.Equal("Example GPU", actual.DeviceName);
        Assert.DoesNotContain(privateDeviceId, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("DeviceID", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("LocationInformation", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("private-user", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DriverDeviceCollector_RejectsClassesOutsideDiagnosticAllowlist()
    {
        var values = new Dictionary<string, object?>
        {
            ["DeviceClass"] = "BLUETOOTH",
            ["DeviceName"] = "Personal device"
        };

        Assert.Null(DriverDeviceCollector.CreateRecord(values));
    }

    [Theory]
    [InlineData("MDMP", 32, DumpFormat.MiniDump, true)]
    [InlineData("PAGEDUMP", 4096, DumpFormat.PageDump32, true)]
    [InlineData("PAGEDU64", 4096, DumpFormat.PageDump64, true)]
    [InlineData("MDMP", 4, DumpFormat.MiniDump, false)]
    public void SafeDumpInspector_UsesBoundedHeaderIdentification(
        string signature,
        int length,
        DumpFormat expectedFormat,
        bool expectedPlausible)
    {
        using var directory = new TestDirectory();
        string path = System.IO.Path.Combine(directory.Path, "candidate.dmp");
        byte[] bytes = new byte[length];
        System.Text.Encoding.ASCII.GetBytes(signature).CopyTo(bytes, 0);
        File.WriteAllBytes(path, bytes);

        DumpCandidate actual = new SafeDumpInspector().Inspect(path, DumpKind.WindowsMinidump, "Test");

        Assert.Equal(DumpInspectionState.Recognized, actual.InspectionState);
        Assert.Equal(expectedFormat, actual.Format);
        Assert.Equal(expectedPlausible, actual.SizePlausible);
        Assert.InRange(actual.HeaderBytesRead, 1, SafeDumpInspector.MaximumHeaderBytesRead);
        Assert.DoesNotContain(path, JsonSerializer.Serialize(actual), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(path, actual.OriginalPath);
    }

    [Fact]
    public void SafeDumpInspector_DoesNotParseUnknownOrNonDumpFiles()
    {
        using var directory = new TestDirectory();
        string unknownDump = System.IO.Path.Combine(directory.Path, "unknown.dmp");
        string textFile = System.IO.Path.Combine(directory.Path, "unknown.txt");
        File.WriteAllBytes(unknownDump, new byte[64]);
        File.WriteAllBytes(textFile, "MDMP"u8.ToArray());
        var inspector = new SafeDumpInspector();

        DumpCandidate unknown = inspector.Inspect(unknownDump, DumpKind.Unknown, "Test");
        DumpCandidate text = inspector.Inspect(textFile, DumpKind.Unknown, "Test");

        Assert.Equal(DumpInspectionState.Unrecognized, unknown.InspectionState);
        Assert.Equal(DumpFormat.Unknown, unknown.Format);
        Assert.Equal(DumpInspectionState.Unrecognized, text.InspectionState);
        Assert.Equal(0, text.HeaderBytesRead);
    }

    [Fact]
    public async Task DumpInventory_RespectsWindowDepthTargetFilterAndPerSourceLimit()
    {
        using var directory = new TestDirectory();
        string nested = Directory.CreateDirectory(System.IO.Path.Combine(directory.Path, "nested")).FullName;
        DateTimeOffset center = DateTimeOffset.UtcNow;
        string first = CreateMiniDump(directory.Path, "BF6-first.dmp", center.AddMinutes(-1));
        _ = CreateMiniDump(nested, "BF6-nested.dmp", center);
        _ = CreateMiniDump(directory.Path, "OtherGame.dmp", center);
        _ = CreateMiniDump(directory.Path, "BF6-old.dmp", center.AddHours(-2));
        var root = new DumpSearchRoot(
            "Synthetic application dumps",
            directory.Path,
            DumpKind.ApplicationDump,
            MaximumDepth: 1,
            RequireTargetMatch: true);
        var collector = new DumpInventoryCollector(new SafeDumpInspector(), [root], maximumCandidatesPerSource: 1);

        DumpInventory actual = await collector.CollectAsync(
            center.AddMinutes(-10),
            center.AddMinutes(10),
            TargetProfile.Battlefield6);

        DumpCandidate candidate = Assert.Single(actual.Candidates);
        Assert.Equal(System.IO.Path.GetFileName(first), candidate.Name);
        Assert.Equal(DumpInspectionState.Recognized, candidate.InspectionState);
        Assert.Contains(actual.Statuses, status =>
            status.Source == "Synthetic application dumps" &&
            status.Detail.Contains("additional", StringComparison.OrdinalIgnoreCase));
    }

    private static string CreateMiniDump(string directory, string name, DateTimeOffset lastWriteUtc)
    {
        string path = System.IO.Path.Combine(directory, name);
        byte[] bytes = new byte[32];
        "MDMP"u8.CopyTo(bytes);
        File.WriteAllBytes(path, bytes);
        File.SetLastWriteTimeUtc(path, lastWriteUtc.UtcDateTime);
        return path;
    }
}
