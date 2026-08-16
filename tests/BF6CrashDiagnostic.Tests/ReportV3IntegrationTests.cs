using System.IO.Compression;
using System.Text;
using System.Text.Json;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Tests;

public sealed class ReportV3IntegrationTests
{
    private static readonly DateTimeOffset BaseTime =
        new(2026, 8, 3, 4, 30, 0, TimeSpan.Zero);

    [Beta2Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task WriteV3Async_WritesContractMembersButExcludesDumpBytesAndRawDebuggerLog()
    {
        using var directory = new TestDirectory();
        string dumpPath = Path.Combine(directory.Path, "private-memory.dmp");
        string rawLogPath = Path.Combine(directory.Path, "private-debugger.log");
        await File.WriteAllBytesAsync(dumpPath, "MDMP-private"u8.ToArray());
        await File.WriteAllTextAsync(rawLogPath, "raw private debugger output");
        var writer = new ReportWriter(directory.Path);
        DiagnosticReportV3 report = CreateReport("v3-standard-members", BaseTime, dumpPath, rawLogPath) with
        {
            DumpQuality = new DumpQuality(
                BaseTime,
                DumpQualityClassification.Valid,
                DumpFormat.MiniDump,
                DumpInternalQualityState.Valid,
                true,
                true,
                true,
                DumpChkState.NotFound,
                string.Empty,
                "The bounded minidump structure was valid."),
            RecentChanges = new RecentChangeTimeline(
                BaseTime,
                BaseTime.AddDays(-7),
                BaseTime,
                [new RecentSystemChange(BaseTime.AddHours(-4), RecentChangeKind.WindowsUpdate, "Security update", "Installation", "Succeeded", string.Empty)],
                [new CollectionStatus("Recent changes/Windows Update", CollectionState.Available, "Read local update history.")]),
            StorageHealth = new StorageHealthSnapshot(
                BaseTime,
                [new StorageHealthRecord(1, "Redacted model", "SSD", "NVMe", "1.0", "Healthy", ["OK"], 1_000_000, 35, 60, 2, 0, 0, 0, 0, 1, 1, 1, 100)],
                [new CollectionStatus("Storage health", CollectionState.Available, "Read Windows storage health.")]),
            DriverVerifier = new DriverVerifierState(
                BaseTime,
                DriverVerifierStatusKind.Disabled,
                string.Empty,
                [],
                "Driver Verifier was not enabled.")
        };

        ReportPackageV3 package = await writer.WriteV3Async(report, CancellationToken.None);
        ValidatedReportArchive validated = await IncidentLibrary.ReadValidatedArchiveAsync(
            package.ZipPath,
            CancellationToken.None);
        Assert.Equal(3, validated.ReportSchemaVersion);

        using ZipArchive archive = ZipFile.OpenRead(package.ZipPath);
        string[] names = archive.Entries.Select(entry => entry.FullName).ToArray();
        string[] required =
        [
            "SUMMARY.txt",
            "Report.json",
            "Performance-Samples.csv",
            "Windows-Events.json",
            "Windows-Event-Groups.json",
            "Reliability.json",
            "Artifacts.json",
            "Collection-Status.json",
            "Source-Coverage.json",
            "Incident.json",
            "Bugchecks.json",
            "Crash-Readiness.json",
            "Dump-Inventory.json",
            "Driver-Inventory.json",
            "Debugger-Analysis.json",
            "Dump-Quality.json",
            "Recent-Changes.json",
            "Storage-Health.json",
            "Driver-Verifier.json",
            "Manifest.json"
        ];
        Assert.Equal(required.Order(), names.Order());
        Assert.DoesNotContain(names, name => Path.GetExtension(name).Equals(".dmp", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(names, name => name.Contains("raw", StringComparison.OrdinalIgnoreCase));

        var text = new StringBuilder();
        foreach (ZipArchiveEntry entry in archive.Entries.Where(entry =>
                     Path.GetExtension(entry.FullName) is ".json" or ".txt" or ".csv"))
        {
            await using Stream stream = entry.Open();
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: false);
            text.Append(await reader.ReadToEndAsync(CancellationToken.None));
        }

        Assert.DoesNotContain(dumpPath, text.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(rawLogPath, text.ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("raw private debugger output", text.ToString(), StringComparison.OrdinalIgnoreCase);

        string csv = ReadEntry(archive, "Performance-Samples.csv");
        Assert.Contains("TargetRunning,TargetProcessCount", csv, StringComparison.Ordinal);
        Assert.DoesNotContain("BF6Running", csv, StringComparison.Ordinal);

        string dumpQualityJson = ReadEntry(archive, "Dump-Quality.json");
        Assert.Contains("\"Classification\": \"Valid\"", dumpQualityJson, StringComparison.Ordinal);
        string debuggerJson = ReadEntry(archive, "Debugger-Analysis.json");
        Assert.Contains("\"Blackbox\"", debuggerJson, StringComparison.Ordinal);
        Assert.Contains("\"AvailableSources\"", debuggerJson, StringComparison.Ordinal);
        string driverVerifierJson = ReadEntry(archive, "Driver-Verifier.json");
        Assert.Contains("\"Status\": \"Disabled\"", driverVerifierJson, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task IncidentLibrary_UsesOpenableArchivesAndGroupsRecurringV3Signals()
    {
        using var directory = new TestDirectory();
        var writer = new ReportWriter(directory.Path);
        await writer.WriteV3Async(
            CreateReport("history-report-one", BaseTime, null, null),
            CancellationToken.None);
        await writer.WriteV3Async(
            CreateReport("history-report-two", BaseTime.AddDays(1), null, null),
            CancellationToken.None);

        IncidentLibrarySnapshot snapshot = await new IncidentLibrary(directory.Path)
            .BuildAsync(CancellationToken.None);

        Assert.Equal(2, snapshot.Incidents.Count);
        Assert.All(snapshot.Incidents, incident =>
        {
            Assert.Equal(3, incident.ReportSchemaVersion);
            Assert.EndsWith(".zip", incident.ReportPath, StringComparison.OrdinalIgnoreCase);
            Assert.True(File.Exists(incident.ReportPath));
        });
        Assert.Contains(snapshot.RecurringGroups, group =>
            group.Category == "Stop code" && group.Value == "0x00000119" && group.Count == 2);
        Assert.Contains(snapshot.RecurringGroups, group =>
            group.Category == "WinDbg named module" && group.Value == "sampledriver.sys" && group.Count == 2);
        Assert.Contains(snapshot.RecurringGroups, group =>
            group.Category == "Selected target" && group.Value == "Battlefield 6" && group.Count == 2);
    }

    [Fact]
    public async Task IncidentLibrary_DoesNotFollowReparseBackedSessionFolders()
    {
        using var directory = new TestDirectory();
        string outsideRoot = Path.Combine(directory.Path, "outside-library");
        await new ReportWriter(outsideRoot).WriteV3Async(
            CreateReport("outside-reparse-report", BaseTime, null, null),
            CancellationToken.None);

        string sessionsRoot = Path.Combine(directory.Path, "Sessions");
        Directory.CreateDirectory(sessionsRoot);
        string outsideSession = Path.Combine(outsideRoot, "Sessions", "outside-reparse-report");
        string linkedSession = Path.Combine(sessionsRoot, "linked-outside-session");
        if (!TryCreateDirectorySymbolicLink(linkedSession, outsideSession))
        {
            return;
        }

        IncidentLibrarySnapshot snapshot = await new IncidentLibrary(directory.Path)
            .BuildAsync(CancellationToken.None);

        Assert.Empty(snapshot.Incidents);
    }

    [Fact]
    public async Task IncidentLibrary_PrefersNewestValidatedArchiveForUpdatedSession()
    {
        using var directory = new TestDirectory();
        var writer = new ReportWriter(directory.Path);
        DiagnosticReportV3 original = CreateReport("updated-history-session", BaseTime, null, null) with
        {
            DebuggerAnalysis = null
        };
        ReportPackageV3 first = await writer.WriteV3Async(original, CancellationToken.None);
        ReportPackageV3 second = await writer.WriteV3Async(
            CreateReport("updated-history-session", BaseTime, null, null),
            CancellationToken.None);
        File.SetLastWriteTimeUtc(first.ZipPath, BaseTime.UtcDateTime);
        File.SetLastWriteTimeUtc(second.ZipPath, BaseTime.AddMinutes(1).UtcDateTime);

        IncidentLibrarySnapshot snapshot = await new IncidentLibrary(directory.Path)
            .BuildAsync(CancellationToken.None);

        IncidentLibraryEntry incident = Assert.Single(snapshot.Incidents);
        Assert.Equal(second.ZipPath, incident.ReportPath, ignoreCase: true);
        Assert.Equal(2, Assert.IsAssignableFrom<IReadOnlyList<LocalReportCopy>>(incident.LocalCopies).Count);
        Assert.Contains(incident.LocalCopies!, copy =>
            string.Equals(copy.ReportPath, first.ZipPath, StringComparison.OrdinalIgnoreCase));
        Assert.Contains(incident.LocalCopies!, copy =>
            string.Equals(copy.ReportPath, second.ZipPath, StringComparison.OrdinalIgnoreCase));
        Assert.Contains("sampledriver.sys", incident.Modules);
    }

    [Fact]
    public async Task IncidentLibrary_PreservesEachDecodedCperCategory()
    {
        using var directory = new TestDirectory();
        DiagnosticEvent whea = new(
            BaseTime,
            "System",
            "Microsoft-Windows-WHEA-Logger",
            new Guid("C26C4F3C-3F66-4E99-8F8A-39405CFED220"),
            1,
            1,
            "Critical",
            "Windows hardware error record.",
            new Dictionary<string, string>
            {
                ["CperSectionCategories"] = "Processor, Memory, PCIe, Generic hardware"
            });
        DiagnosticReportV3 report = CreateReport("history-cper-categories", BaseTime, null, null) with
        {
            Events = [whea]
        };
        await new ReportWriter(directory.Path).WriteV3Async(report, CancellationToken.None);

        IncidentLibraryEntry incident = Assert.Single((await new IncidentLibrary(directory.Path)
            .BuildAsync(CancellationToken.None)).Incidents);

        Assert.Equal(
            new[]
            {
                "Generic hardware record",
                "Memory hardware record",
                "PCIe hardware record",
                "Processor hardware record"
            },
            incident.WheaCategories.Order(StringComparer.OrdinalIgnoreCase).ToArray());
    }

    [Fact]
    public async Task ValidatedArchiveLoader_AcceptsArchivesFromRealV2AndV3Writers()
    {
        using var directory = new TestDirectory();
        var writer = new ReportWriter(directory.Path);
        ReportPackage v2 = await writer.WriteAsync(CreateV2Report("manifest-real-v2", BaseTime), CancellationToken.None);
        ReportPackageV3 v3 = await writer.WriteV3Async(
            CreateReport("manifest-real-v3", BaseTime.AddMinutes(1), null, null),
            CancellationToken.None);

        ValidatedReportArchive validatedV2 = await IncidentLibrary.ReadValidatedArchiveAsync(
            v2.ZipPath,
            CancellationToken.None);
        ValidatedReportArchive validatedV3 = await IncidentLibrary.ReadValidatedArchiveAsync(
            v3.ZipPath,
            CancellationToken.None);

        Assert.Equal(2, validatedV2.ReportSchemaVersion);
        Assert.Equal("manifest-real-v2", validatedV2.SessionId);
        Assert.Equal(3, validatedV3.ReportSchemaVersion);
        Assert.Equal("manifest-real-v3", validatedV3.SessionId);
        using JsonDocument v2Json = JsonDocument.Parse(validatedV2.ReportJson);
        using JsonDocument v3Json = JsonDocument.Parse(validatedV3.ReportJson);
        Assert.Equal("manifest-real-v2", v2Json.RootElement.GetProperty("SessionId").GetString());
        Assert.Equal("manifest-real-v3", v3Json.RootElement.GetProperty("SessionId").GetString());
    }

    [Theory]
    [InlineData(false, "SHA-256")]
    [InlineData(true, "recorded size")]
    public async Task ValidatedArchiveLoader_RejectsChangedPayloadAgainstManifest(
        bool changeLength,
        string expectedMessage)
    {
        using var directory = new TestDirectory();
        ReportPackageV3 package = await new ReportWriter(directory.Path).WriteV3Async(
            CreateReport("manifest-payload-drift", BaseTime, null, null),
            CancellationToken.None);
        string tampered = CopyArchive(package.ZipPath, directory.Path, "payload-drift.zip");
        ReplaceArchiveEntry(tampered, "SUMMARY.txt", bytes =>
        {
            byte[] changed = changeLength ? [.. bytes, (byte)'!'] : [.. bytes];
            changed[0] ^= 0x01;
            return changed;
        });

        InvalidDataException exception = await Assert.ThrowsAsync<InvalidDataException>(() =>
            IncidentLibrary.ReadValidatedArchiveAsync(tampered, CancellationToken.None));

        Assert.Contains(expectedMessage, exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidatedArchiveLoader_RejectsMissingManifest()
    {
        using var directory = new TestDirectory();
        ReportPackageV3 package = await new ReportWriter(directory.Path).WriteV3Async(
            CreateReport("manifest-missing", BaseTime, null, null),
            CancellationToken.None);
        string tampered = CopyArchive(package.ZipPath, directory.Path, "missing-manifest.zip");
        using (ZipArchive archive = ZipFile.Open(tampered, ZipArchiveMode.Update))
        {
            Assert.Single(archive.Entries, entry => entry.FullName == "Manifest.json").Delete();
        }

        InvalidDataException exception = await Assert.ThrowsAsync<InvalidDataException>(() =>
            IncidentLibrary.ReadValidatedArchiveAsync(tampered, CancellationToken.None));

        Assert.Contains("Manifest.json", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidatedArchiveLoader_RejectsMissingRequiredPayloadMember()
    {
        using var directory = new TestDirectory();
        ReportPackageV3 package = await new ReportWriter(directory.Path).WriteV3Async(
            CreateReport("manifest-payload-missing", BaseTime, null, null),
            CancellationToken.None);
        string tampered = CopyArchive(package.ZipPath, directory.Path, "missing-payload.zip");
        using (ZipArchive archive = ZipFile.Open(tampered, ZipArchiveMode.Update))
        {
            Assert.Single(archive.Entries, entry => entry.FullName == "Artifacts.json").Delete();
        }

        InvalidDataException exception = await Assert.ThrowsAsync<InvalidDataException>(() =>
            IncidentLibrary.ReadValidatedArchiveAsync(tampered, CancellationToken.None));

        Assert.Contains("Artifacts.json", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidatedArchiveLoader_RejectsCaseInsensitiveDuplicateNames()
    {
        using var directory = new TestDirectory();
        ReportPackageV3 package = await new ReportWriter(directory.Path).WriteV3Async(
            CreateReport("manifest-duplicate", BaseTime, null, null),
            CancellationToken.None);
        string tampered = CopyArchive(package.ZipPath, directory.Path, "duplicate.zip");
        AddArchiveEntry(tampered, "report.JSON", "{}"u8.ToArray());

        InvalidDataException exception = await Assert.ThrowsAsync<InvalidDataException>(() =>
            IncidentLibrary.ReadValidatedArchiveAsync(tampered, CancellationToken.None));

        Assert.Contains("duplicate", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("private.dmp")]
    [InlineData("raw-debugger.log")]
    [InlineData("nested/Report.json")]
    public async Task ValidatedArchiveLoader_RejectsPrivateOrUnsafeExtraMembers(string memberName)
    {
        using var directory = new TestDirectory();
        ReportPackageV3 package = await new ReportWriter(directory.Path).WriteV3Async(
            CreateReport("manifest-private-member", BaseTime, null, null),
            CancellationToken.None);
        string tampered = CopyArchive(package.ZipPath, directory.Path, "private-member.zip");
        AddArchiveEntry(tampered, memberName, "private"u8.ToArray());

        await Assert.ThrowsAsync<InvalidDataException>(() =>
            IncidentLibrary.ReadValidatedArchiveAsync(tampered, CancellationToken.None));
    }

    private static DiagnosticReportV3 CreateReport(
        string sessionId,
        DateTimeOffset incidentTime,
        string? dumpPath,
        string? rawLogPath)
    {
        IncidentFingerprint fingerprint = IncidentFingerprint.Create(
            IncidentKind.Bugcheck,
            incidentTime,
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001,
            TargetProfile.Battlefield6.Id,
            "0x00000119");
        var candidate = new IncidentCandidate(
            fingerprint,
            incidentTime,
            IncidentKind.Bugcheck,
            "Windows blue screen",
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001,
            TargetProfile.Battlefield6.Id,
            "0x00000119",
            dumpPath is null ? null : Path.GetFileName(dumpPath),
            100,
            2,
            incidentTime,
            incidentTime);
        var selection = new IncidentSelection(
            candidate,
            incidentTime.AddMinutes(-15),
            incidentTime.AddMinutes(15),
            IncidentSelectionMethod.UserSelected);
        var bugcheck = new BugcheckRecord(
            incidentTime,
            BugcheckEvidenceSource.WindowsErrorReporting,
            candidate.Source,
            candidate.EventId,
            "0x119",
            0x119,
            "0x00000119",
            [2, 0, 0, 0],
            candidate.DumpFileName,
            candidate.DumpFileName,
            dumpPath);
        DumpCandidate[] dumps = dumpPath is null
            ? []
            :
            [
                new DumpCandidate(
                    DumpKind.WindowsMinidump,
                    "Dump inventory/Windows minidumps",
                    Path.GetFileName(dumpPath),
                    Path.GetFileName(dumpPath),
                    new FileInfo(dumpPath).Length,
                    incidentTime,
                    DumpFormat.MiniDump,
                    DumpInspectionState.Recognized,
                    4,
                    true,
                    "Recognized minidump signature.",
                    dumpPath)
            ];
        CrashCorrelation? correlation = dumps.Length == 0
            ? null
            : new CrashCorrelation(
                fingerprint,
                bugcheck,
                dumps[0],
                CrashCorrelationBasis.ExactRecordedPath,
                TimeSpan.Zero,
                dumps,
                "The matching path supports correlation but does not identify a cause.");
        DebuggerAnalysis debugger = new(
            DebuggerAnalysisState.Completed,
            incidentTime,
            incidentTime.AddSeconds(2),
            SymbolAccessMode.LocalOnly,
            "10.0-test",
            new string('a', 64),
            "0x00000119",
            ["0x2", "0x0", "0x0", "0x0"],
            "VIDEO_SCHEDULER_INTERNAL_ERROR",
            "sampledriver.sys",
            "sampledriver.sys",
            "samplegame.exe",
            "Local symbols",
            ["sampledriver.sys"],
            "WinDbg reported these fields; they do not confirm a faulty driver.",
            rawLogPath,
            new DebuggerBlackboxSummary(
                ["BSD"],
                new DebuggerBlackboxBootStatus(true, true, false, false, false, false, false, 1, 4, 3, 2),
                []));

        return new DiagnosticReportV3(
            3,
            "3.1.0-beta.2",
            "PC Crash Diagnostic",
            sessionId,
            DiagnosticMode.Retrospective,
            incidentTime.AddMinutes(-15),
            incidentTime.AddMinutes(15),
            "SelectedIncidentAnalyzed",
            selection,
            TargetProfile.Battlefield6,
            null,
            null,
            [
                new TargetPerformanceSample(
                    incidentTime,
                    true,
                    2,
                    25,
                    12,
                    20,
                    15,
                    40,
                    37.5,
                    4096,
                    3500,
                    40,
                    50,
                    55,
                    2048,
                    256,
                    5)
            ],
            [],
            [],
            [],
            [],
            [],
            [new CollectionStatus("Windows Event Log/System", CollectionState.Available, "Read bounded records.")],
            [new SourceCoverage("Windows Event Log/System", CollectionState.Available, 2, "Read bounded records.")],
            [bugcheck],
            null,
            new DumpInventory(dumps, []),
            null,
            correlation,
            debugger,
            fingerprint,
            "Observed Windows records are included. WinDbg reported a named module; this does not establish fault." );
    }

    private static DiagnosticReport CreateV2Report(string sessionId, DateTimeOffset incidentTime) => new(
        2,
        "2.0.0-beta.1",
        sessionId,
        DiagnosticMode.Retrospective,
        incidentTime.AddMinutes(-15),
        incidentTime.AddMinutes(15),
        "RetrospectiveAnalysisCompleted",
        new CrashAnchor(
            incidentTime,
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001,
            "Windows blue screen",
            "0x00000119"),
        null,
        null,
        [],
        [],
        [],
        [],
        [],
        [],
        [new CollectionStatus("Windows Event Log/System", CollectionState.Available, "Read bounded records.")],
        "Validated legacy report fixture.");

    private static string CopyArchive(string source, string directory, string name)
    {
        string destination = Path.Combine(directory, name);
        File.Copy(source, destination);
        return destination;
    }

    private static void ReplaceArchiveEntry(
        string archivePath,
        string memberName,
        Func<byte[], byte[]> transform)
    {
        using ZipArchive archive = ZipFile.Open(archivePath, ZipArchiveMode.Update);
        ZipArchiveEntry original = Assert.Single(archive.Entries, entry => entry.FullName == memberName);
        byte[] bytes;
        using (Stream input = original.Open())
        using (var buffer = new MemoryStream())
        {
            input.CopyTo(buffer);
            bytes = buffer.ToArray();
        }

        original.Delete();
        ZipArchiveEntry replacement = archive.CreateEntry(memberName, CompressionLevel.Optimal);
        using Stream output = replacement.Open();
        output.Write(transform(bytes));
    }

    private static void AddArchiveEntry(string archivePath, string memberName, byte[] bytes)
    {
        using ZipArchive archive = ZipFile.Open(archivePath, ZipArchiveMode.Update);
        ZipArchiveEntry entry = archive.CreateEntry(memberName, CompressionLevel.Optimal);
        using Stream output = entry.Open();
        output.Write(bytes);
    }

    private static string ReadEntry(ZipArchive archive, string name)
    {
        ZipArchiveEntry entry = Assert.Single(archive.Entries, item => item.FullName == name);
        using Stream stream = entry.Open();
        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
        return reader.ReadToEnd();
    }

    private static bool TryCreateDirectorySymbolicLink(string linkPath, string targetPath)
    {
        try
        {
            Directory.CreateSymbolicLink(linkPath, targetPath);
            return true;
        }
        catch (Exception exception) when (
            exception is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            return false;
        }
    }
}
