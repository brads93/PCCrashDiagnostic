using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class EventAnalyzerTests
{
    private static readonly DateTimeOffset BaseTime = DateTimeOffset.Parse("2026-08-02T04:40:00Z");
    private static readonly Guid TraitsProviderGuid = Guid.Parse("8444a4fb-d8d3-4f38-84f8-89960a1ef12f");

    [Fact]
    public void ExactProviderTraitsMessage_IsRecognizedAsEventTracingContext()
    {
        const string message = "Error setting traits on Provider {8444a4fb-d8d3-4f38-84f8-89960a1ef12f}. Error: 0xC0000001";

        Assert.True(EventAnalyzer.IsProviderTraitsMessage(message));
        Assert.False(EventAnalyzer.IsProviderTraitsMessage("A registration for Provider has joined Provider Group"));
    }

    [Fact]
    public void SelectCrashAnchor_PrefersBugCheckOverUnexpectedShutdownMarkers()
    {
        var analyzer = new EventAnalyzer();
        DiagnosticEvent[] events =
        [
            Event("Microsoft-Windows-WER-SystemErrorReporting", 1001, BaseTime,
                "The computer has rebooted from a bugcheck.",
                new Dictionary<string, string>
                {
                    ["BugcheckCode"] = "0x00000119",
                    ["DumpFile"] = @"C:\Windows\Minidump\080226-10000-01.dmp"
                }),
            Event("Microsoft-Windows-Kernel-Power", 41, BaseTime.AddMinutes(3),
                "The system rebooted without cleanly shutting down.",
                new Dictionary<string, string> { ["BugcheckCode"] = "281" }),
            Event("EventLog", 6008, BaseTime.AddMinutes(4), "The previous shutdown was unexpected.")
        ];

        CrashAnchor? actual = analyzer.SelectCrashAnchor(events);

        Assert.NotNull(actual);
        Assert.Equal(1001, actual.EventId);
        Assert.Equal("0x00000119", actual.BugCheckCode);
        Assert.Equal(@"C:\Windows\Minidump\080226-10000-01.dmp", actual.DumpPath);
    }

    [Fact]
    public void SelectCrashAnchor_UsesNewestEventAtSameEvidencePriority()
    {
        var analyzer = new EventAnalyzer();
        DiagnosticEvent[] events =
        [
            Event("Microsoft-Windows-WER-SystemErrorReporting", 1001, BaseTime, "Rebooted from a bugcheck."),
            Event("Microsoft-Windows-WER-SystemErrorReporting", 1001, BaseTime.AddHours(2), "Rebooted from another bugcheck.")
        ];

        CrashAnchor? actual = analyzer.SelectCrashAnchor(events);

        Assert.NotNull(actual);
        Assert.Equal(BaseTime.AddHours(2), actual.TimeUtc);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public void Analyze_ManualCrashTimeAnchor_DoesNotInventBugcheckFinding()
    {
        var analyzer = new EventAnalyzer();
        var manualAnchor = new CrashAnchor(
            BaseTime,
            "Manual crash time",
            0,
            "Crash time supplied by the user",
            Priority: 1_000);

        IReadOnlyList<DiagnosticFinding> findings = analyzer.Analyze(
            manualAnchor,
            [],
            [],
            [],
            [],
            []);

        Assert.DoesNotContain(findings, finding => finding.Id == "bugcheck");
        Assert.Empty(findings);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public void Analyze_ManualCrashTimeAnchor_StillUsesRecordedBugcheckInWindow()
    {
        var analyzer = new EventAnalyzer();
        var manualAnchor = new CrashAnchor(
            BaseTime,
            "Manual crash time",
            0,
            "Crash time supplied by the user",
            Priority: 1_000);
        DiagnosticEvent bugcheck = Event(
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001,
            BaseTime.AddMinutes(1),
            "The computer rebooted from a bugcheck.",
            new Dictionary<string, string> { ["BugcheckCode"] = "0x00000119" });

        IReadOnlyList<DiagnosticFinding> findings = analyzer.Analyze(
            manualAnchor,
            [bugcheck],
            analyzer.GroupDuplicates([bugcheck]),
            [],
            [],
            []);

        Assert.Contains(findings, finding => finding.Id == "bugcheck");
    }

    [Fact]
    public void GroupDuplicates_NormalizesWhitespaceAndCase_AndKeepsTimeBounds()
    {
        var analyzer = new EventAnalyzer();
        DiagnosticEvent[] events =
        [
            TraitsEvent(BaseTime, "Error setting traits on Provider {8444a4fb-d8d3-4f38-84f8-89960a1ef12f}. Error: 0xC0000001"),
            TraitsEvent(BaseTime.AddMinutes(4), "error   setting traits on provider {8444A4FB-D8D3-4F38-84F8-89960A1EF12F}. error: 0xc0000001")
        ];

        DuplicateEventGroup actual = Assert.Single(analyzer.GroupDuplicates(events));

        Assert.Equal(2, actual.Count);
        Assert.Equal(BaseTime, actual.FirstSeenUtc);
        Assert.Equal(BaseTime.AddMinutes(4), actual.LastSeenUtc);
        Assert.Equal(TraitsProviderGuid, actual.ProviderGuid);
    }

    [Fact]
    public void Analyze_RanksBugCheckAndWheaAboveProviderTraitsContext()
    {
        var analyzer = new EventAnalyzer();
        DiagnosticEvent bugCheck = Event(
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001,
            BaseTime,
            "The computer has rebooted from a bugcheck.",
            new Dictionary<string, string> { ["BugcheckCode"] = "0x00000119" });
        DiagnosticEvent whea = Event(
            "Microsoft-Windows-WHEA-Logger",
            18,
            BaseTime.AddSeconds(-5),
            "A fatal hardware error has occurred.");
        DiagnosticEvent traits = TraitsEvent(
            BaseTime.AddSeconds(-10),
            "Error setting traits on Provider {8444a4fb-d8d3-4f38-84f8-89960a1ef12f}. Error: 0xC0000001");
        DiagnosticEvent[] events = [bugCheck, whea, traits];
        CrashAnchor? anchor = analyzer.SelectCrashAnchor(events);
        IReadOnlyList<DuplicateEventGroup> groups = analyzer.GroupDuplicates(events);

        IReadOnlyList<DiagnosticFinding> actual = analyzer.Analyze(
            anchor,
            events,
            groups,
            Array.Empty<ReliabilityRecord>(),
            Array.Empty<CrashArtifact>(),
            Array.Empty<PerformanceSample>());

        Assert.Equal("bugcheck", actual[0].Id);
        Assert.Equal("whea", actual[1].Id);
        DiagnosticFinding traitsFinding = Assert.Single(actual, finding => finding.Id.StartsWith("etw-provider-traits-", StringComparison.Ordinal));
        Assert.Equal(FindingSeverity.Context, traitsFinding.Severity);
        Assert.Equal(FindingConfidence.Low, traitsFinding.Confidence);
        Assert.Contains("not a memory-leak code", traitsFinding.Meaning, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not evidence of a memory leak", traitsFinding.DoesNotProve, StringComparison.OrdinalIgnoreCase);
        Assert.True(traitsFinding.Rank > actual[1].Rank);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public void Analyze_PrefersFatalWheaOverFrequentCorrectedWhea()
    {
        var analyzer = new EventAnalyzer();
        DiagnosticEvent[] events =
        [
            Event("Microsoft-Windows-WHEA-Logger", 17, BaseTime, "A corrected hardware error has occurred."),
            Event("Microsoft-Windows-WHEA-Logger", 17, BaseTime.AddSeconds(1), "A corrected hardware error has occurred."),
            Event("Microsoft-Windows-WHEA-Logger", 17, BaseTime.AddSeconds(2), "A corrected hardware error has occurred."),
            Event("Microsoft-Windows-WHEA-Logger", 18, BaseTime.AddSeconds(3), "A fatal hardware error has occurred.")
        ];

        DiagnosticFinding whea = Assert.Single(
            analyzer.Analyze(null, events, analyzer.GroupDuplicates(events), [], [], []),
            finding => finding.Id == "whea");

        Assert.Equal(FindingSeverity.Critical, whea.Severity);
        Assert.Equal(FindingConfidence.High, whea.Confidence);
        Assert.Equal("Fatal hardware error", whea.Title);
        Assert.Contains("event 18", whea.Evidence, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public void Analyze_CorrectedWheaIsNotLabeledFatal()
    {
        var analyzer = new EventAnalyzer();
        DiagnosticEvent corrected = Event(
            "Microsoft-Windows-WHEA-Logger",
            17,
            BaseTime,
            "A corrected hardware error has occurred.");

        DiagnosticFinding whea = Assert.Single(
            analyzer.Analyze(null, [corrected], analyzer.GroupDuplicates([corrected]), [], [], []));

        Assert.Equal(FindingSeverity.Warning, whea.Severity);
        Assert.Equal(FindingConfidence.Medium, whea.Confidence);
        Assert.Equal("Corrected hardware error", whea.Title);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public void Analyze_ApplicationErrorNamingGpuDriverDoesNotInventGpuReset()
    {
        var analyzer = new EventAnalyzer();
        DiagnosticEvent applicationError = Event(
            "Application Error",
            1000,
            BaseTime,
            "Faulting application BF6.exe, faulting module amdkmdag.sys.");

        IReadOnlyList<DiagnosticFinding> findings = analyzer.Analyze(
            null,
            [applicationError],
            analyzer.GroupDuplicates([applicationError]),
            [],
            [],
            [],
            TargetProfile.Battlefield6);

        Assert.DoesNotContain(findings, finding => finding.Id == "gpu-timeout");
        Assert.Contains(findings, finding => finding.Id == "application-failure");
    }

    [Fact]
    public void Analyze_LabelsRisingMemoryAsPossibleTrend_NotProof()
    {
        var analyzer = new EventAnalyzer();
        PerformanceSample[] samples =
        [
            Sample(BaseTime, privateMb: 3000, commitPct: 50),
            Sample(BaseTime.AddMinutes(10), privateMb: 6000, commitPct: 65)
        ];

        DiagnosticFinding actual = Assert.Single(analyzer.Analyze(
            null,
            Array.Empty<DiagnosticEvent>(),
            Array.Empty<DuplicateEventGroup>(),
            Array.Empty<ReliabilityRecord>(),
            Array.Empty<CrashArtifact>(),
            samples));

        Assert.Equal("rising-memory-trend", actual.Id);
        Assert.Equal(FindingConfidence.Low, actual.Confidence);
        Assert.Contains("not enough to call this a memory leak", actual.DoesNotProve, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Analyze_DoesNotClassifyDiagnosticToolCrashAsBf6Failure()
    {
        var analyzer = new EventAnalyzer();
        DiagnosticEvent selfCrash = Event(
            "Application Error",
            1000,
            BaseTime,
            @"Faulting application name: BF6CrashDiagnostic.exe. Faulting application path: C:\work\bf6-crash-diagnostic-dotnet\BF6CrashDiagnostic.exe");
        DiagnosticEvent[] events = [selfCrash];

        IReadOnlyList<DiagnosticFinding> actual = analyzer.Analyze(
            null,
            events,
            analyzer.GroupDuplicates(events),
            [],
            [],
            [],
            TargetProfile.Battlefield6);

        Assert.DoesNotContain(actual, finding => finding.Id == "application-failure");
        Assert.Empty(actual);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public void Analyze_UsesSelectedTargetInsteadOfHardcodedBattlefieldSignals()
    {
        var analyzer = new EventAnalyzer();
        TargetProfile target = TargetProfile.FromExecutable("ExampleGame.exe");
        DiagnosticEvent selectedTargetCrash = Event(
            "Application Error",
            1000,
            BaseTime,
            "Application failure record.",
            new Dictionary<string, string>
            {
                ["FaultingApplicationName"] = "ExampleGame.exe",
                ["FaultingModuleName"] = "ExampleEngine.dll"
            });
        DiagnosticEvent unrelatedBattlefieldCrash = Event(
            "Application Error",
            1000,
            BaseTime.AddSeconds(1),
            "Faulting application BF6.exe, faulting module amdkmdag.sys.");

        IReadOnlyList<DiagnosticFinding> findings = analyzer.Analyze(
            null,
            [selectedTargetCrash, unrelatedBattlefieldCrash],
            analyzer.GroupDuplicates([selectedTargetCrash, unrelatedBattlefieldCrash]),
            [],
            [],
            [],
            target);

        DiagnosticFinding finding = Assert.Single(findings, item => item.Id == "application-failure");
        Assert.Contains("ExampleGame", finding.Evidence, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("BF6.exe", finding.Evidence, StringComparison.OrdinalIgnoreCase);
    }

    private static DiagnosticEvent TraitsEvent(DateTimeOffset time, string message) =>
        new(
            time,
            "Microsoft-Windows-Kernel-EventTracing/Admin",
            "Microsoft-Windows-Kernel-EventTracing",
            TraitsProviderGuid,
            28,
            2,
            "Error",
            message,
            new Dictionary<string, string>
            {
                ["ProviderGuid"] = TraitsProviderGuid.ToString("B"),
                ["ErrorCode"] = "3221225473"
            });

    private static DiagnosticEvent Event(
        string provider,
        int eventId,
        DateTimeOffset time,
        string message,
        IReadOnlyDictionary<string, string>? data = null) =>
        new(
            time,
            "System",
            provider,
            null,
            eventId,
            2,
            "Error",
            message,
            data ?? new Dictionary<string, string>());

    private static PerformanceSample Sample(DateTimeOffset time, double privateMb, double commitPct) =>
        new(
            time,
            true,
            1234,
            "BF6",
            50,
            16,
            16,
            24,
            40,
            commitPct,
            5000,
            privateMb,
            40,
            75,
            80,
            9000,
            500,
            20);
}
