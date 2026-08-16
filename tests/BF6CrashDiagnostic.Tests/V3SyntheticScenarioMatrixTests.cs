using System.IO.Compression;
using System.Text.Json;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Tests;

/// <summary>
/// Fixed, offline v3 evidence combinations. These tests model records and files;
/// they never induce a crash, GPU reset, hang, or bugcheck.
/// </summary>
public sealed class V3SyntheticScenarioMatrixTests
{
    private static readonly DateTimeOffset IncidentTime =
        new(2026, 8, 3, 4, 42, 18, TimeSpan.Zero);

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public void ConfirmedBugcheck_WithMatchingRecordedDump_CorrelatesByExactPath()
    {
        const string dumpPath = @"C:\Windows\Minidump\080326-12345-01.dmp";
        DiagnosticEvent wer = Event(
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001,
            data: new Dictionary<string, string>
            {
                ["BugcheckCode"] = "0x119",
                ["BugcheckParameter1"] = "0x2",
                ["BugcheckParameter2"] = "0xFFFF800000000001",
                ["BugcheckParameter3"] = "0",
                ["BugcheckParameter4"] = "15",
                ["DumpFile"] = dumpPath
            },
            message: "The computer rebooted from a bugcheck.");
        DiagnosticEvent kernelPower = Event(
            "Microsoft-Windows-Kernel-Power",
            41,
            IncidentTime.AddSeconds(2),
            new Dictionary<string, string> { ["BugcheckCode"] = "281" });
        DiagnosticEvent shutdown = Event("EventLog", 6008, IncidentTime.AddSeconds(4));
        DiagnosticEvent[] events = [wer, kernelPower, shutdown];

        IncidentCandidate incident = Assert.Single(
            new IncidentDiscovery().Discover(events, targetProfile: TargetProfile.Battlefield6));
        IReadOnlyList<BugcheckRecord> bugchecks = BugcheckRecordDecoder.Decode(events);
        BugcheckRecord bugcheck = Assert.Single(
            bugchecks,
            item => item.EvidenceSource == BugcheckEvidenceSource.WindowsErrorReporting);
        DumpCandidate dump = Dump(
            "080326-12345-01.dmp",
            dumpPath,
            IncidentTime.AddSeconds(1),
            DumpKind.WindowsMinidump);
        IncidentSelection selection = new IncidentDiscovery().Select(incident);

        CrashCorrelation correlation = new CrashCorrelator().Correlate(
            selection,
            [bugcheck],
            [dump],
            currentBootUtc: IncidentTime.AddHours(-1));

        Assert.Equal(IncidentKind.Bugcheck, incident.Kind);
        Assert.Equal("0x00000119", incident.BugcheckCode);
        Assert.Equal(3, incident.SupportingRecordCount);
        Assert.Equal(2, bugchecks.Count);
        Assert.Contains(bugchecks, item => item.EvidenceSource == BugcheckEvidenceSource.KernelPower);
        Assert.Equal("0x00000119", bugcheck.NormalizedCode);
        Assert.Equal([2UL, 0xFFFF800000000001UL, 0UL, 15UL], bugcheck.Parameters);
        Assert.Same(dump, correlation.SelectedDump);
        Assert.Equal(CrashCorrelationBasis.ExactRecordedPath, correlation.Basis);
        Assert.NotNull(correlation.Bugcheck);
        Assert.Contains("does not establish", correlation.Limitation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public void UnexpectedRestart_WithoutBugcheckEvidence_RemainsUncleanShutdownOnly()
    {
        DiagnosticEvent kernelPower = Event(
            "Microsoft-Windows-Kernel-Power",
            41,
            data: new Dictionary<string, string> { ["BugcheckCode"] = "0" },
            message: "The system rebooted without cleanly shutting down.");
        DiagnosticEvent shutdown = Event(
            "EventLog",
            6008,
            IncidentTime.AddSeconds(2),
            message: "The previous system shutdown was unexpected.");
        DiagnosticEvent[] events = [kernelPower, shutdown];
        var discovery = new IncidentDiscovery();
        var analyzer = new EventAnalyzer();

        IncidentCandidate incident = Assert.Single(discovery.Discover(events));
        IReadOnlyList<DiagnosticFinding> findings = analyzer.Analyze(
            analyzer.SelectCrashAnchor(events),
            events,
            analyzer.GroupDuplicates(events),
            [],
            [],
            []);
        CrashCorrelation correlation = new CrashCorrelator().Correlate(
            discovery.Select(incident),
            BugcheckRecordDecoder.Decode(events),
            []);

        Assert.Equal(IncidentKind.UnexpectedRestart, incident.Kind);
        Assert.Null(incident.BugcheckCode);
        Assert.Empty(BugcheckRecordDecoder.Decode(events));
        Assert.Contains(findings, finding => finding.Id == "unclean-shutdown");
        Assert.DoesNotContain(findings, finding => finding.Id == "bugcheck");
        Assert.Null(correlation.Bugcheck);
        Assert.Null(correlation.SelectedDump);
        Assert.Equal(CrashCorrelationBasis.None, correlation.Basis);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public void Bugcheck_WithDumpWriteFailure_ExplainsMissingDumpButNotCrashCause()
    {
        DiagnosticEvent bugcheck = Event(
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001,
            data: new Dictionary<string, string> { ["BugcheckCode"] = "0x1A" },
            message: "The computer rebooted from a bugcheck.");
        DiagnosticEvent dumpFailure = Event(
            "volmgr",
            161,
            IncidentTime.AddSeconds(1),
            message: "Dump file creation failed due to error during dump creation.");
        DiagnosticEvent[] events = [bugcheck, dumpFailure];
        var analyzer = new EventAnalyzer();

        IReadOnlyList<DiagnosticFinding> findings = analyzer.Analyze(
            analyzer.SelectCrashAnchor(events),
            events,
            analyzer.GroupDuplicates(events),
            [],
            [],
            []);

        Assert.Contains(findings, finding => finding.Id == "bugcheck");
        DiagnosticFinding failure = Assert.Single(findings, finding => finding.Id == "dump-write-failure");
        Assert.Equal(FindingConfidence.High, failure.Confidence);
        Assert.Contains("why a dump is missing", failure.DoesNotProve, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("faulty", failure.Meaning, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(18, WheaEventClassification.Fatal, FindingSeverity.Critical, "Fatal hardware error")]
    [InlineData(17, WheaEventClassification.Corrected, FindingSeverity.Warning, "Corrected hardware error")]
    [Trait("Category", "SyntheticScenario")]
    public void Whea_FatalAndCorrectedRecords_UseSharedCatalogWithoutDeclaringDefect(
        int eventId,
        WheaEventClassification expectedClassification,
        FindingSeverity expectedSeverity,
        string expectedTitle)
    {
        DiagnosticEvent whea = Event(
            WheaEventCatalog.ProviderName,
            eventId,
            data: new Dictionary<string, string>
            {
                ["ErrorSource"] = "Machine Check Exception",
                ["CperSectionCategories"] = "Processor, Memory, PCIe"
            },
            message: expectedClassification == WheaEventClassification.Fatal
                ? "A fatal hardware error has occurred."
                : "A corrected hardware error has occurred.");
        var analyzer = new EventAnalyzer();

        Assert.True(WheaEventDecoder.TryDecode(whea, out DecodedWheaEvent? decoded));
        IncidentCandidate incident = Assert.Single(new IncidentDiscovery().Discover([whea]));
        DiagnosticFinding finding = Assert.Single(analyzer.Analyze(
            null,
            [whea],
            analyzer.GroupDuplicates([whea]),
            [],
            [],
            []));

        Assert.Equal(expectedClassification, WheaEventCatalog.Classify(eventId));
        Assert.Equal(expectedClassification, decoded.Classification);
        Assert.Equal("Processor, Memory, PCIe", decoded.Fields["CperSectionCategories"]);
        Assert.Equal(IncidentKind.HardwareError, incident.Kind);
        Assert.Equal(expectedTitle, incident.Title);
        Assert.Equal(expectedSeverity, finding.Severity);
        Assert.Equal(expectedTitle, finding.Title);
        Assert.Contains("does not establish", finding.DoesNotProve, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public void UnknownWheaEventId_IsNotPromotedFromRenderedMessageText()
    {
        DiagnosticEvent unknown = Event(
            WheaEventCatalog.ProviderName,
            999,
            data: new Dictionary<string, string> { ["ErrorType"] = "Machine Check" },
            message: "A fatal uncorrectable hardware error has occurred.");
        var analyzer = new EventAnalyzer();

        Assert.True(WheaEventDecoder.TryDecode(unknown, out DecodedWheaEvent? decoded));
        Assert.Equal(WheaEventClassification.Unknown, decoded.Classification);
        Assert.Empty(new IncidentDiscovery().Discover([unknown]));
        Assert.DoesNotContain(
            analyzer.Analyze(null, [unknown], analyzer.GroupDuplicates([unknown]), [], [], []),
            finding => finding.Id == "whea");
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public void GpuReset_WithLiveKernelDump_IsNotClassifiedAsBlueScreen()
    {
        DiagnosticEvent reset = Event(
            "Display",
            4101,
            message: "Display driver stopped responding and has successfully recovered.");
        var discovery = new IncidentDiscovery();
        var analyzer = new EventAnalyzer();
        IncidentCandidate incident = Assert.Single(discovery.Discover([reset]));
        DumpCandidate liveKernelDump = Dump(
            "WATCHDOG-20260803-0442.dmp",
            @"C:\Windows\LiveKernelReports\WATCHDOG\WATCHDOG-20260803-0442.dmp",
            IncidentTime.AddSeconds(2),
            DumpKind.LiveKernelDump);
        CrashCorrelation correlation = new CrashCorrelator().Correlate(
            discovery.Select(incident),
            [],
            [liveKernelDump]);
        IReadOnlyList<DiagnosticFinding> findings = analyzer.Analyze(
            null,
            [reset],
            analyzer.GroupDuplicates([reset]),
            [],
            [],
            []);

        Assert.Equal(IncidentKind.GpuTimeout, incident.Kind);
        Assert.Contains(findings, finding => finding.Id == "gpu-timeout");
        Assert.DoesNotContain(findings, finding => finding.Id == "bugcheck");
        Assert.Null(correlation.Bugcheck);
        Assert.Same(liveKernelDump, correlation.SelectedDump);
        Assert.Equal(CrashCorrelationBasis.TimestampProximity, correlation.Basis);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public void NormalTargetExit_AfterTwoMissedSamples_DoesNotInventCrashEvidence()
    {
        TargetProfile target = TargetProfile.FromExecutable(@"C:\Games\SyntheticGame.exe", "Synthetic game");
        TargetPerformanceSample[] samples =
        [
            Sample(IncidentTime.AddSeconds(-10), running: true, processCount: 2),
            Sample(IncidentTime.AddSeconds(-5), running: false, processCount: 0),
            Sample(IncidentTime, running: false, processCount: 0)
        ];
        IReadOnlyList<IncidentCandidate> discovered = new IncidentDiscovery().Discover([], targetProfile: target);
        IReadOnlyList<DiagnosticFinding> findings = new EventAnalyzer().Analyze(null, [], [], [], [], []);
        var closure = new IncidentCandidate(
            IncidentFingerprint.Create(IncidentKind.Unknown, IncidentTime, "Process monitoring", 0, target.Id),
            IncidentTime,
            IncidentKind.Unknown,
            "App closed",
            "Process monitoring",
            0,
            target.Id,
            null,
            null,
            1,
            1,
            IncidentTime,
            IncidentTime);

        Assert.True(samples[0].TargetRunning);
        Assert.Equal(2, samples.Skip(1).Count(sample => !sample.TargetRunning));
        Assert.All(samples.Skip(1), sample => Assert.Equal(0, sample.TargetProcessCount));
        Assert.Empty(discovered);
        Assert.Empty(findings);
        Assert.Equal(IncidentKind.Unknown, closure.Kind);
        Assert.Equal("App closed", closure.Title);
    }

    [Theory]
    [InlineData(1000, IncidentKind.ApplicationCrash, "Application crash")]
    [InlineData(1002, IncidentKind.ApplicationHang, "Application hang")]
    [Trait("Category", "SyntheticScenario")]
    public void ApplicationCrashAndHang_AreSeparatedFromBugchecks(
        int eventId,
        IncidentKind expectedKind,
        string expectedTitle)
    {
        DiagnosticEvent failure = Event(
            eventId == 1002 ? "Application Hang" : "Application Error",
            eventId,
            data: new Dictionary<string, string> { ["FaultingApplicationName"] = "SyntheticGame.exe" },
            message: eventId == 1002
                ? "SyntheticGame.exe stopped interacting with Windows and was closed."
                : "Faulting application name: SyntheticGame.exe, exception code 0xc0000005.");
        TargetProfile target = TargetProfile.FromExecutable(@"C:\Games\SyntheticGame.exe", "Synthetic game");

        IncidentCandidate incident = Assert.Single(new IncidentDiscovery().Discover([failure], targetProfile: target));

        Assert.Equal(expectedKind, incident.Kind);
        Assert.Equal(expectedTitle, incident.Title);
        Assert.Equal(target.Id, incident.TargetProfileId);
        Assert.Null(incident.BugcheckCode);
        Assert.False(BugcheckRecordDecoder.TryDecode(failure, out _));
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public void MultipleAmbiguousDumps_RequireExplicitUserSelection()
    {
        IncidentCandidate incident = Candidate(IncidentKind.Bugcheck, "0x00000119");
        IncidentSelection selection = new IncidentDiscovery().Select(incident);
        BugcheckRecord bugcheck = new(
            IncidentTime,
            BugcheckEvidenceSource.WindowsErrorReporting,
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001,
            "0x119",
            0x119,
            "0x00000119",
            [2, null, null, null],
            null,
            null);
        DumpCandidate first = Dump(
            "first.dmp",
            @"C:\Windows\Minidump\first.dmp",
            IncidentTime.AddSeconds(-2),
            DumpKind.WindowsMinidump);
        DumpCandidate second = Dump(
            "second.dmp",
            @"C:\Windows\Minidump\second.dmp",
            IncidentTime.AddSeconds(2),
            DumpKind.WindowsMinidump);
        var correlator = new CrashCorrelator();

        CrashCorrelation ambiguous = correlator.Correlate(selection, [bugcheck], [first, second]);

        Assert.Null(ambiguous.SelectedDump);
        Assert.Equal(CrashCorrelationBasis.None, ambiguous.Basis);
        Assert.Equal(2, ambiguous.RelatedDumps.Count);
        Assert.Contains("user must select", ambiguous.Limitation, StringComparison.OrdinalIgnoreCase);

        CrashCorrelation selected = correlator.SelectDump(ambiguous, second);
        Assert.Same(second, selected.SelectedDump);
        Assert.Equal(CrashCorrelationBasis.UserSelected, selected.Basis);
        Assert.Contains("does not establish", selected.Limitation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task InterruptedMonitoring_AfterReboot_RecoversCompleteV3Samples()
    {
        using var directory = new TestDirectory();
        string sessionsRoot = Path.Combine(directory.Path, "Sessions");
        const string sessionId = "synthetic-reboot";
        string sessionFolder = Path.Combine(sessionsRoot, sessionId);
        DateTimeOffset originalBoot = IncidentTime.AddHours(-2);
        TargetProfile target = TargetProfile.FromExecutable(@"C:\Games\SyntheticGame.exe", "Synthetic game");
        var marker = new ActiveTargetSessionMarker(
            3,
            sessionId,
            int.MaxValue,
            IncidentTime.AddMinutes(-20),
            originalBoot,
            IncidentTime.AddMinutes(-1),
            sessionFolder,
            target);
        var store = new TargetSessionStore();
        var journal = new TargetSampleJournal();
        await store.WriteAsync(marker, sessionsRoot, CancellationToken.None);
        await journal.AppendAsync(sessionFolder, Sample(IncidentTime.AddMinutes(-2), true, 1), CancellationToken.None);
        await journal.AppendAsync(sessionFolder, Sample(IncidentTime.AddMinutes(-1), true, 1), CancellationToken.None);
        await File.AppendAllTextAsync(journal.GetPath(sessionFolder), "{\"TimestampUtc\":", CancellationToken.None);

        TargetRecoveryCandidate recovery = Assert.Single(await store.FindStaleAsync(
            sessionsRoot,
            originalBoot.AddHours(3),
            CancellationToken.None));
        IReadOnlyList<TargetPerformanceSample> samples = await journal.ReadAsync(sessionFolder, CancellationToken.None);

        Assert.True(recovery.BootChanged);
        Assert.Equal("RecoveredAfterSystemRestart", recovery.CompletionReason);
        Assert.Equal(2, samples.Count);
        Assert.All(samples, sample => Assert.True(sample.TargetRunning));
        store.Complete(recovery.Marker.SessionFolder, sessionsRoot);
        Assert.False(File.Exists(Path.Combine(sessionFolder, "ACTIVE-v3.json")));
        Assert.True(File.Exists(journal.GetPath(sessionFolder)));
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task DeniedAndTimedOutSources_RemainVisibleInV3CoverageAndStatus()
    {
        using var directory = new TestDirectory();
        CollectionStatus[] statuses =
        [
            new("Windows Event Log/System", CollectionState.Denied, "Windows denied access."),
            new("Reliability history", CollectionState.TimedOut, "The bounded query timed out.")
        ];
        SourceCoverage[] coverage =
        [
            new("Windows Event Log/System", CollectionState.Denied, 0, "Windows denied access."),
            new("Reliability history", CollectionState.TimedOut, 0, "The bounded query timed out.")
        ];
        DiagnosticReportV3 report = CreateReport(
            "synthetic-source-states",
            IncidentTime,
            IncidentFingerprint.Create(IncidentKind.UnexpectedRestart, IncidentTime, "EventLog", 6008),
            statuses,
            coverage);

        ReportPackageV3 package = await new ReportWriter(directory.Path).WriteV3Async(report, CancellationToken.None);

        using ZipArchive archive = ZipFile.OpenRead(package.ZipPath);
        SourceCoverage[] exportedCoverage = ReadJsonEntry<SourceCoverage[]>(archive, "Source-Coverage.json");
        CollectionStatus[] exportedStatuses = ReadJsonEntry<CollectionStatus[]>(archive, "Collection-Status.json");
        Assert.Contains(exportedCoverage, item => item.State == CollectionState.Denied && item.RecordCount == 0);
        Assert.Contains(exportedCoverage, item => item.State == CollectionState.TimedOut && item.RecordCount == 0);
        Assert.Contains(exportedStatuses, item => item.State == CollectionState.Denied);
        Assert.Contains(exportedStatuses, item => item.State == CollectionState.TimedOut);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task RepeatedIncidentFingerprint_IsRetainedAcrossSeparateReports()
    {
        using var directory = new TestDirectory();
        IncidentFingerprint repeated = IncidentFingerprint.Create(
            IncidentKind.ApplicationCrash,
            IncidentTime,
            "Application Error",
            1000,
            "synthetic-game",
            "0xc0000005");
        var writer = new ReportWriter(directory.Path);
        await writer.WriteV3Async(
            CreateReport("synthetic-repeat-one", IncidentTime, repeated),
            CancellationToken.None);
        await writer.WriteV3Async(
            CreateReport("synthetic-repeat-two", IncidentTime.AddDays(1), repeated),
            CancellationToken.None);

        IncidentLibrarySnapshot history = await new IncidentLibrary(directory.Path).BuildAsync(CancellationToken.None);
        IncidentLibraryEntry[] repeatedEntries = history.Incidents
            .Where(item => item.IncidentFingerprint == repeated.Value)
            .ToArray();

        Assert.Equal(2, repeatedEntries.Length);
        Assert.Equal(2, repeatedEntries.Select(item => item.SessionId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.All(repeatedEntries, item => Assert.Equal(IncidentKind.ApplicationCrash, item.Kind));
        Assert.Contains(history.RecurringGroups, group =>
            group.Category == "Selected target" && group.Value == "Synthetic game" && group.Count == 2);
    }

    private static DiagnosticEvent Event(
        string provider,
        int eventId,
        DateTimeOffset? time = null,
        IReadOnlyDictionary<string, string>? data = null,
        string message = "") =>
        new(
            time ?? IncidentTime,
            "System",
            provider,
            provider.Equals(WheaEventCatalog.ProviderName, StringComparison.OrdinalIgnoreCase)
                ? WheaEventCatalog.ProviderGuid
                : null,
            eventId,
            2,
            "Error",
            message,
            data ?? new Dictionary<string, string>());

    private static IncidentCandidate Candidate(IncidentKind kind, string? bugcheckCode) =>
        new(
            IncidentFingerprint.Create(kind, IncidentTime, "Synthetic", 1, discriminator: bugcheckCode),
            IncidentTime,
            kind,
            "Synthetic incident",
            "Synthetic",
            1,
            null,
            bugcheckCode,
            null,
            1,
            1,
            IncidentTime,
            IncidentTime);

    private static DumpCandidate Dump(
        string name,
        string path,
        DateTimeOffset lastWriteUtc,
        DumpKind kind) =>
        new(
            kind,
            "Synthetic dump inventory",
            name,
            "<Windows>\\" + name,
            4096,
            lastWriteUtc,
            DumpFormat.MiniDump,
            DumpInspectionState.Recognized,
            32,
            true,
            "Recognized synthetic dump metadata.",
            path);

    private static TargetPerformanceSample Sample(
        DateTimeOffset timestamp,
        bool running,
        int processCount) =>
        new(
            timestamp,
            running,
            processCount,
            25,
            16,
            16,
            20,
            40,
            50,
            running ? 2048 : null,
            running ? 1800 : null,
            running ? 20 : null,
            running ? 40 : null,
            running ? 45 : null,
            running ? 1024 : null,
            running ? 128 : null,
            5);

    private static DiagnosticReportV3 CreateReport(
        string sessionId,
        DateTimeOffset time,
        IncidentFingerprint fingerprint,
        IReadOnlyList<CollectionStatus>? statuses = null,
        IReadOnlyList<SourceCoverage>? coverage = null)
    {
        TargetProfile target = TargetProfile.FromExecutable(@"C:\Games\SyntheticGame.exe", "Synthetic game");
        var candidate = new IncidentCandidate(
            fingerprint,
            time,
            IncidentKind.ApplicationCrash,
            "Application crash",
            "Application Error",
            1000,
            target.Id,
            null,
            null,
            650,
            1,
            time,
            time);
        return new DiagnosticReportV3(
            3,
            "3.1.0-beta.2",
            "PC Crash Diagnostic",
            sessionId,
            DiagnosticMode.Retrospective,
            time.AddMinutes(-10),
            time.AddMinutes(5),
            "SelectedIncidentAnalyzed",
            new IncidentSelection(
                candidate,
                time.AddMinutes(-10),
                time.AddMinutes(5),
                IncidentSelectionMethod.UserSelected),
            target,
            null,
            null,
            [],
            [],
            [],
            [],
            [],
            [],
            statuses ?? [],
            coverage ?? [],
            [],
            null,
            new DumpInventory([], []),
            null,
            null,
            null,
            fingerprint,
            "No cause was identified in the Windows records this app could read.");
    }

    private static T ReadJsonEntry<T>(ZipArchive archive, string name)
    {
        ZipArchiveEntry entry = Assert.Single(archive.Entries, item => item.FullName == name);
        using Stream stream = entry.Open();
        return JsonSerializer.Deserialize<T>(stream)
            ?? throw new InvalidDataException($"{name} did not contain the expected JSON value.");
    }
}
