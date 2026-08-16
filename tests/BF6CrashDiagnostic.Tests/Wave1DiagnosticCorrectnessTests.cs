using System.Reflection;
using System.Text.Json;
using BF6CrashDiagnostic.Core;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Tests;

public sealed class Wave1DiagnosticCorrectnessTests
{
    private static readonly DateTimeOffset IncidentTime =
        new(2026, 8, 2, 4, 42, 18, TimeSpan.Zero);

    [Fact]
    public void ReliabilityBlueScreen_IsSupportingEvidenceNotAConfirmedBugcheck()
    {
        var reliability = new ReliabilityRecord(
            IncidentTime,
            "Windows",
            "Windows",
            "BlueScreen",
            "BlueScreen");
        IncidentCandidate candidate = Assert.Single(
            new IncidentDiscovery().Discover([], [reliability]));
        var analyzer = new EventAnalyzer();

        DiagnosticFinding finding = Assert.Single(analyzer.Analyze(
            null,
            [],
            [],
            [reliability],
            [],
            [],
            selectedIncident: candidate));

        Assert.Equal(IncidentEvidenceOrigin.ReliabilityMonitor, candidate.EvidenceOrigin);
        Assert.Equal("reliability-blue-screen", finding.Id);
        Assert.Equal(FindingConfidence.Medium, finding.Confidence);
        Assert.Contains("does not provide a verified stop code", finding.DoesNotProve, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("bugcheck recorded", finding.Title, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DirectWerBugcheck_SuppressesReliabilityOnlyFinding()
    {
        DiagnosticEvent wer = Event(
            IncidentTime,
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001,
            new Dictionary<string, string> { ["BugcheckCode"] = "281" });
        var reliability = new ReliabilityRecord(
            IncidentTime,
            "Windows",
            "Windows",
            "BlueScreen",
            "BlueScreen");
        IncidentCandidate candidate = Assert.Single(
            new IncidentDiscovery().Discover([wer], [reliability]));
        var analyzer = new EventAnalyzer();

        IReadOnlyList<DiagnosticFinding> findings = analyzer.Analyze(
            analyzer.SelectCrashAnchor([wer]),
            [wer],
            analyzer.GroupDuplicates([wer]),
            [reliability],
            [],
            [],
            selectedIncident: candidate);

        Assert.Contains(findings, item => item.Id == "bugcheck");
        Assert.DoesNotContain(findings, item => item.Id == "reliability-blue-screen");
        Assert.Contains("VIDEO_SCHEDULER_INTERNAL_ERROR", findings.Single(item => item.Id == "bugcheck").Evidence);
    }

    [Fact]
    public void KernelEventTracing29Fixture_IsCollectedAndClassifiedAsContext()
    {
        DiagnosticEvent diagnosticEvent = WindowsEventCollector.ParseEventXml(
            File.ReadAllText(Fixture("KernelEventTracing-29-sanitized.xml")));
        var analyzer = new EventAnalyzer();

        DiagnosticFinding finding = Assert.Single(analyzer.Analyze(
            null,
            [diagnosticEvent],
            analyzer.GroupDuplicates([diagnosticEvent]),
            [],
            [],
            []));

        Assert.Equal(29, diagnosticEvent.EventId);
        Assert.Equal(Guid.Parse("8444a4fb-d8d3-4f38-84f8-89960a1ef12f"), diagnosticEvent.ProviderGuid);
        Assert.Contains("0xC0000001", diagnosticEvent.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(FindingSeverity.Context, finding.Severity);
        Assert.Equal(FindingConfidence.Low, finding.Confidence);
        Assert.Contains("not evidence of a memory leak", finding.DoesNotProve, StringComparison.OrdinalIgnoreCase);
        string query = WindowsEventCollector.BuildEvidenceSystemXPath(
            IncidentTime.AddMinutes(-1),
            IncidentTime.AddMinutes(1));
        Assert.Contains("iaStorAC", query, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(29, KernelEventTracingCatalog.EvidenceEventIds);
    }

    [Fact]
    public void PrivilegedCoordinatorCoverageCountsCollectedKernelEventTracingRecord()
    {
        DiagnosticEvent diagnosticEvent = WindowsEventCollector.ParseEventXml(
            File.ReadAllText(Fixture("KernelEventTracing-29-sanitized.xml")));
        CollectionStatus[] statuses =
        [
            new(
                "Windows Event Log/Kernel-EventTracing Admin",
                CollectionState.Available,
                "Collected one bounded metadata record.")
        ];
        MethodInfo buildCoverage = typeof(PCCrashDiagnosticCoordinator).GetMethod(
            "BuildCoverage",
            BindingFlags.NonPublic | BindingFlags.Static) ??
            throw new MissingMethodException(nameof(PCCrashDiagnosticCoordinator), "BuildCoverage");

        object? value = buildCoverage.Invoke(
            null,
            [
                statuses,
                new[] { diagnosticEvent },
                Array.Empty<ReliabilityRecord>(),
                Array.Empty<CrashArtifact>(),
                Array.Empty<DumpCandidate>(),
                null,
                null,
                null,
                null,
                null,
                null,
                null
            ]);

        SourceCoverage coverage = Assert.Single(Assert.IsType<SourceCoverage[]>(value));
        Assert.Equal(1, coverage.RecordCount);
    }

    [Fact]
    public void IntelRst129Fixture_IsStorageResetEvidenceWithoutHardwareBlame()
    {
        DiagnosticEvent diagnosticEvent = WindowsEventCollector.ParseEventXml(
            File.ReadAllText(Fixture("IntelRst-129-sanitized.xml")));
        var analyzer = new EventAnalyzer();
        DiagnosticFinding finding = Assert.Single(analyzer.Analyze(
            null,
            [diagnosticEvent],
            analyzer.GroupDuplicates([diagnosticEvent]),
            [],
            [],
            []));

        Assert.True(StorageEventCatalog.TryClassify(diagnosticEvent, out StorageEventCategory category));
        Assert.Equal(StorageEventCategory.TimeoutOrReset, category);
        Assert.Equal("storage-evidence", finding.Id);
        Assert.Contains("does not identify the failing layer", finding.DoesNotProve, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void BugcheckCatalog_AddsKnownNameAndLeavesUnknownCodeNeutral()
    {
        DiagnosticEvent known = Event(
            IncidentTime,
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001,
            new Dictionary<string, string> { ["BugcheckCode"] = "0x119" });
        DiagnosticEvent unknown = Event(
            IncidentTime,
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001,
            new Dictionary<string, string> { ["BugcheckCode"] = "0xDEAD" });

        Assert.True(BugcheckRecordDecoder.TryDecode(known, out BugcheckRecord knownRecord));
        Assert.True(BugcheckRecordDecoder.TryDecode(unknown, out BugcheckRecord unknownRecord));
        Assert.Equal("VIDEO_SCHEDULER_INTERNAL_ERROR", knownRecord.BugcheckName);
        Assert.Null(unknownRecord.BugcheckName);
        Assert.Equal("0x0000DEAD", BugcheckCatalog.Format(unknownRecord.NormalizedCode));
    }

    [Fact]
    public void BootSessionReconstruction_UsesHistoricalMarkersForHistoricalIncident()
    {
        DiagnosticEvent[] markers =
        [
            Event(IncidentTime.AddHours(-2), "Microsoft-Windows-Kernel-General", 12),
            Event(IncidentTime.AddHours(-2).AddSeconds(1), "EventLog", 6005),
            Event(IncidentTime.AddMinutes(8), "Microsoft-Windows-Kernel-Power", 41),
            Event(IncidentTime.AddMinutes(10), "Microsoft-Windows-Kernel-General", 12),
            Event(IncidentTime.AddMinutes(10).AddSeconds(1), "EventLog", 6005)
        ];

        BootSessionContext context = new BootSessionReconstructor().Reconstruct(
            IncidentTime,
            markers,
            IncidentTime.AddMinutes(10));

        Assert.Equal(IncidentTime.AddHours(-2), context.StartUtc);
        Assert.Equal(IncidentTime.AddMinutes(10), context.EndUtc);
        Assert.True(context.IncidentOccurredInSession);
        Assert.Equal(BootSessionReconstructionConfidence.Corroborated, context.Confidence);
        Assert.Contains("do not identify why", context.Limitation, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void CrashCorrelator_RanksDumpInReconstructedSessionBeforeOtherBoot()
    {
        IncidentCandidate candidate = Candidate(IncidentEvidenceOrigin.WindowsEventLog);
        var selection = new IncidentSelection(
            candidate,
            IncidentTime.AddMinutes(-30),
            IncidentTime.AddMinutes(30),
            IncidentSelectionMethod.UserSelected);
        DumpCandidate sameBoot = Dump("same.dmp", IncidentTime.AddMinutes(1));
        DumpCandidate nextBoot = Dump("next.dmp", IncidentTime.AddMinutes(20));
        var boot = new BootSessionContext(
            IncidentTime,
            IncidentTime.AddHours(-1),
            IncidentTime.AddMinutes(10),
            true,
            "start",
            "end",
            BootSessionReconstructionConfidence.Corroborated,
            [],
            "Boot markers do not identify a cause.");

        CrashCorrelation correlation = new CrashCorrelator().Correlate(
            selection,
            [],
            [nextBoot, sameBoot],
            IncidentTime.AddMinutes(10),
            boot);

        Assert.Equal([sameBoot, nextBoot], correlation.RelatedDumps);
        Assert.Null(correlation.SelectedDump);
    }

    [Fact]
    public void PreviewBuildFinding_IsVersionContextNotCauseClaim()
    {
        SystemSnapshot snapshot = Snapshot(preview: true);

        DiagnosticFinding finding = Assert.IsType<DiagnosticFinding>(
            DiagnosticContextAnalyzer.CreatePreviewBuildFinding(null, snapshot));

        Assert.Equal(FindingSeverity.Context, finding.Severity);
        Assert.Contains("build 26200", finding.Evidence, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("does not establish", finding.DoesNotProve, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void DebuggerAvailability_FiltersUntrustedCandidatesAndProvidesOfficialHandoff()
    {
        string root = Path.Combine(Path.GetTempPath(), "pc-crash-debugger-availability-" + Guid.NewGuid().ToString("N"));
        using var coordinator = new PCCrashDiagnosticCoordinator(
            root,
            static (_, _) => Task.CompletedTask,
            null,
            null,
            null,
            static () => false,
            static _ => false,
            discoverInstalledDebuggers: static () =>
            [
                new CdbInstallation("C:\\untrusted\\cdb.exe", "99.0", "Other", false, true, "Other"),
                new CdbInstallation("C:\\sdk\\cdb.exe", "10.0.1", "Windows SDK", true, true, "Microsoft Windows")
            ]);

        DebuggerAvailability availability = coordinator.InspectDebuggerAvailability();

        Assert.True(availability.IsAvailable);
        Assert.Equal("10.0.1", availability.Version);
        Assert.Equal("Windows SDK", availability.Source);
    }

    [Fact]
    public void DebuggerAvailability_WhenAbsentExplainsMicrosoftHandoff()
    {
        string root = Path.Combine(Path.GetTempPath(), "pc-crash-debugger-absent-" + Guid.NewGuid().ToString("N"));
        using var coordinator = new PCCrashDiagnosticCoordinator(
            root,
            static (_, _) => Task.CompletedTask,
            null,
            null,
            null,
            static () => false,
            static _ => false,
            discoverInstalledDebuggers: static () => []);

        DebuggerAvailability availability = coordinator.InspectDebuggerAvailability();

        Assert.Equal(DebuggerAvailabilityState.NotFound, availability.State);
        Assert.Contains("Install WinDbg from Microsoft", availability.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("C:\\", availability.Detail, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AdditiveSchemaFields_DefaultSafelyWhenReadingOlderCandidateJson()
    {
        IncidentCandidate candidate = Candidate(IncidentEvidenceOrigin.WindowsEventLog);
        string currentJson = JsonSerializer.Serialize(candidate);
        using JsonDocument document = JsonDocument.Parse(currentJson);
        var legacyFields = document.RootElement.EnumerateObject()
            .Where(property => property.Name != nameof(IncidentCandidate.EvidenceOrigin))
            .ToDictionary(property => property.Name, property => property.Value.Clone());
        string legacyJson = JsonSerializer.Serialize(legacyFields);

        IncidentCandidate restored = Assert.IsType<IncidentCandidate>(
            JsonSerializer.Deserialize<IncidentCandidate>(legacyJson));

        Assert.Equal(IncidentEvidenceOrigin.Unknown, restored.EvidenceOrigin);
    }

    private static string Fixture(string name) =>
        Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    private static DiagnosticEvent Event(
        DateTimeOffset timeUtc,
        string provider,
        int eventId,
        IReadOnlyDictionary<string, string>? data = null) =>
        new(
            timeUtc,
            "System",
            provider,
            null,
            eventId,
            2,
            "Error",
            $"{provider} event {eventId}",
            data ?? new Dictionary<string, string>());

    private static IncidentCandidate Candidate(IncidentEvidenceOrigin origin) =>
        new(
            IncidentFingerprint.Create(IncidentKind.Bugcheck, IncidentTime, "Test", 1001),
            IncidentTime,
            IncidentKind.Bugcheck,
            "Test bugcheck",
            "Test",
            1001,
            null,
            null,
            null,
            1,
            1,
            IncidentTime,
            IncidentTime,
            origin);

    private static DumpCandidate Dump(string name, DateTimeOffset timeUtc) =>
        new(
            DumpKind.WindowsMinidump,
            "Test",
            name,
            "%SystemRoot%\\Minidump\\" + name,
            4096,
            timeUtc,
            DumpFormat.MiniDump,
            DumpInspectionState.Recognized,
            8,
            true,
            "recognized");

    private static SystemSnapshot Snapshot(bool preview) =>
        new(
            IncidentTime,
            "OEM",
            "Model",
            "OEM",
            "Board",
            "BIOS",
            "2026-01-01",
            "CPU",
            32UL * 1024 * 1024 * 1024,
            [],
            [],
            "Microsoft Windows 11 Pro",
            "10.0.26200",
            "26200",
            "64-bit",
            "Insider Dev",
            preview,
            IncidentTime.AddHours(-2));
}
