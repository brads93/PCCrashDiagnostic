using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Tests;

/// <summary>
/// Offline simulations for diagnostic paths that must not be reproduced on a real PC.
/// These tests do not launch BF6, write the Windows Event Log, induce a GPU reset,
/// create a dump, or crash Windows.
/// </summary>
public sealed class SyntheticScenarioTests
{
    private static readonly DateTimeOffset BaseTime = DateTimeOffset.Parse("2026-08-02T04:40:00Z");
    private static readonly JsonSerializerOptions FixtureJsonOptions = new()
    {
        PropertyNameCaseInsensitive = false
    };

    public static IEnumerable<object[]> ClassificationScenarios()
    {
        string fixturePath = Path.Combine(AppContext.BaseDirectory, "Fixtures", "SyntheticScenarios.json");
        string json = File.ReadAllText(fixturePath, Encoding.UTF8);
        ScenarioSpec[] scenarios = JsonSerializer.Deserialize<ScenarioSpec[]>(json, FixtureJsonOptions)
            ?? throw new InvalidDataException("Synthetic scenario fixture did not contain an array.");

        return scenarios.Select(scenario => new object[] { scenario });
    }

    [Theory]
    [Trait("Category", "SyntheticScenario")]
    [MemberData(nameof(ClassificationScenarios))]
    public void ClassificationFixture_ProducesOnlySupportedConclusions(ScenarioSpec scenario)
    {
        var analyzer = new EventAnalyzer();
        DiagnosticEvent[] events = scenario.Events.Select(CreateEvent).ToArray();
        PerformanceSample[] samples = scenario.Samples.Select(CreateSample).ToArray();
        IReadOnlyList<DuplicateEventGroup> groups = analyzer.GroupDuplicates(events);

        IReadOnlyList<DiagnosticFinding> findings = analyzer.Analyze(
            analyzer.SelectCrashAnchor(events),
            events,
            groups,
            [],
            [],
            samples,
            TargetProfile.Battlefield6);

        foreach (string expectedPrefix in scenario.ExpectedFindingPrefixes)
        {
            Assert.Contains(
                findings,
                finding => finding.Id.StartsWith(expectedPrefix, StringComparison.Ordinal));
        }

        foreach (string unexpectedId in scenario.UnexpectedFindingIds)
        {
            Assert.DoesNotContain(findings, finding => finding.Id == unexpectedId);
        }

        if (scenario.Name == "generic-status-unsuccessful")
        {
            DiagnosticFinding traits = Assert.Single(
                findings,
                finding => finding.Id.StartsWith("etw-provider-traits-", StringComparison.Ordinal));
            Assert.Equal(FindingSeverity.Context, traits.Severity);
            Assert.Equal(FindingConfidence.Low, traits.Confidence);
            Assert.Contains("generic operation failure", traits.Meaning, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("not evidence of a memory leak", traits.DoesNotProve, StringComparison.OrdinalIgnoreCase);
        }

        if (scenario.Name == "gpu-reset-tdr")
        {
            DiagnosticFinding gpu = Assert.Single(findings, finding => finding.Id == "gpu-timeout");
            Assert.Equal(FindingConfidence.High, gpu.Confidence);
            Assert.Contains("does not prove", gpu.DoesNotProve, StringComparison.OrdinalIgnoreCase);
        }

        if (scenario.Name == "rising-private-memory-and-commit")
        {
            DiagnosticFinding trend = Assert.Single(findings, finding => finding.Id == "rising-memory-trend");
            Assert.Equal(FindingConfidence.Low, trend.Confidence);
            Assert.Contains("not enough to call this a memory leak", trend.DoesNotProve, StringComparison.OrdinalIgnoreCase);
        }

        if (scenario.Name == "high-but-stable-memory")
        {
            Assert.Empty(findings);
        }
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task DeniedSourcesAndPrivateText_AreRedactedAndPackagedWithoutExtraFiles()
    {
        using var directory = new TestDirectory();
        var analyzer = new EventAnalyzer();
        var redactor = new PrivacyRedactor("Brad", "FRIEND-PC", "EXAMPLE", @"C:\Users\Brad");
        var summaryBuilder = new SummaryBuilder();
        var writer = new ReportWriter(directory.Path);
        var rawEvent = new DiagnosticEvent(
            BaseTime,
            "Application",
            "Application Error",
            Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            1000,
            2,
            "Error",
            @"BF6.exe failed for Brad at C:\Users\Brad\Desktop from brad@example.com on 192.168.1.42, activity aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.",
            new Dictionary<string, string>
            {
                ["Computer"] = "FRIEND-PC",
                ["Account"] = @"EXAMPLE\Brad"
            });
        var rawArtifact = new CrashArtifact(
            "Crash dump for Brad",
            "BF6-Brad.dmp",
            @"C:\Users\Brad\AppData\Local\CrashDumps\BF6-Brad.dmp",
            4096,
            BaseTime,
            true,
            @"C:\Users\Brad\AppData\Local\CrashDumps\BF6-Brad.dmp");
        CollectionStatus[] rawStatuses =
        [
            new("Windows Event Log for FRIEND-PC", CollectionState.Denied, @"Access denied for EXAMPLE\Brad."),
            new("Reliability history", CollectionState.Unavailable, "Source is unavailable.")
        ];

        DiagnosticEvent[] safeEvents = [redactor.RedactEvent(rawEvent)];
        DuplicateEventGroup[] safeGroups = analyzer.GroupDuplicates([rawEvent])
            .Select(redactor.RedactGroup)
            .ToArray();
        DiagnosticFinding[] safeFindings = analyzer.Analyze(
                null,
                [rawEvent],
                analyzer.GroupDuplicates([rawEvent]),
                [],
                [rawArtifact],
                [],
                TargetProfile.Battlefield6)
            .Select(redactor.RedactFinding)
            .ToArray();
        CrashArtifact[] safeArtifacts = [redactor.RedactArtifact(rawArtifact)];
        CollectionStatus[] safeStatuses = rawStatuses.Select(redactor.RedactStatus).ToArray();
        string summary = summaryBuilder.Build(
            "synthetic-private-report",
            DiagnosticMode.Retrospective,
            BaseTime,
            BaseTime.AddMinutes(1),
            "RetrospectiveAnalysisCompleted",
            null,
            [],
            safeArtifacts,
            safeFindings,
            safeStatuses);
        var report = new DiagnosticReport(
            2,
            "2.0.0-beta.1",
            "synthetic-private-report",
            DiagnosticMode.Retrospective,
            BaseTime,
            BaseTime.AddMinutes(1),
            "RetrospectiveAnalysisCompleted",
            null,
            null,
            null,
            [],
            safeEvents,
            safeGroups,
            [],
            safeArtifacts,
            safeFindings,
            safeStatuses,
            summary);

        ReportPackage package = await writer.WriteAsync(report, CancellationToken.None);

        Assert.Contains("Mode: Past crash", summary, StringComparison.Ordinal);
        Assert.Contains("Completion: Past-crash analysis completed", summary, StringComparison.Ordinal);
        Assert.DoesNotContain("RetrospectiveAnalysisCompleted", summary, StringComparison.Ordinal);
        Assert.Equal(await ComputeSha256Async(package.ZipPath), package.Sha256);
        using ZipArchive archive = ZipFile.OpenRead(package.ZipPath);
        string[] expectedEntries =
        [
            "Artifacts.json",
            "Collection-Status.json",
            "Manifest.json",
            "Performance-Samples.csv",
            "Reliability.json",
            "Report.json",
            "SUMMARY.txt",
            "Windows-Event-Groups.json",
            "Windows-Events.json"
        ];
        Assert.Equal(expectedEntries, archive.Entries.Select(entry => entry.FullName).Order(StringComparer.Ordinal).ToArray());
        Assert.DoesNotContain(
            archive.Entries,
            entry => entry.FullName.EndsWith(".dmp", StringComparison.OrdinalIgnoreCase));

        var payload = new StringBuilder();
        foreach (ZipArchiveEntry entry in archive.Entries)
        {
            await using Stream stream = entry.Open();
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
            payload.AppendLine(await reader.ReadToEndAsync(CancellationToken.None));
        }

        string packagedText = payload.ToString();
        Assert.Contains("[REDACTED-", packagedText, StringComparison.Ordinal);
        Assert.DoesNotContain("Brad", packagedText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("FRIEND-PC", packagedText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("example.com", packagedText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("192.168.1.42", packagedText, StringComparison.Ordinal);
        Assert.DoesNotContain(@"C:\Users\Brad", packagedText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("OriginalPath", packagedText, StringComparison.Ordinal);

        ZipArchiveEntry statusEntry = Assert.Single(archive.Entries, entry => entry.FullName == "Collection-Status.json");
        await using Stream statusStream = statusEntry.Open();
        CollectionStatus[] packagedStatuses = await JsonSerializer.DeserializeAsync<CollectionStatus[]>(statusStream)
            ?? throw new InvalidDataException("Packaged collection status was unreadable.");
        Assert.Contains(packagedStatuses, status => status.State == CollectionState.Denied);
        Assert.Contains(packagedStatuses, status => status.State == CollectionState.Unavailable);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task CancelledReportWrite_PublishesNoArchiveOrChecksum()
    {
        using var directory = new TestDirectory();
        var writer = new ReportWriter(directory.Path);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            writer.WriteAsync(CreateMinimalReport("synthetic-cancelled-report"), cancellation.Token));

        Assert.True(Directory.Exists(writer.ReportsRoot));
        Assert.Empty(Directory.EnumerateFiles(writer.ReportsRoot, "*", SearchOption.TopDirectoryOnly));
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task InterruptedSession_KeepsCompleteSamplesAndCanBeMarkedRecovered()
    {
        using var directory = new TestDirectory();
        var store = new ActiveSessionStore();
        var journal = new SessionSampleJournal();
        string sessionFolder = Path.Combine(directory.Path, "Sessions", "synthetic-interrupted");
        DateTimeOffset boot = BaseTime.AddHours(-1);
        var marker = new ActiveSessionMarker(
            1,
            "synthetic-interrupted",
            int.MaxValue,
            BaseTime,
            boot,
            BaseTime.AddMinutes(10),
            sessionFolder,
            "BF6",
            DiagnosticMode.Monitor);
        string sessionsRoot = Path.Combine(directory.Path, "Sessions");
        await store.WriteAsync(marker, sessionsRoot, CancellationToken.None);
        await journal.AppendAsync(sessionFolder, CreateSample(new SampleSpec(0, 4096, 50)), CancellationToken.None);
        await journal.AppendAsync(sessionFolder, CreateSample(new SampleSpec(5, 4352, 52)), CancellationToken.None);
        await File.AppendAllTextAsync(journal.GetPath(sessionFolder), "{\"TimestampUtc\":", CancellationToken.None);

        RecoveryCandidate candidate = Assert.Single(await store.FindStaleAsync(
            Path.Combine(directory.Path, "Sessions"),
            boot,
            CancellationToken.None));
        IReadOnlyList<PerformanceSample> recoveredSamples = await journal.ReadAsync(sessionFolder, CancellationToken.None);

        Assert.False(candidate.BootChanged);
        Assert.Equal("RecoveredAfterToolInterruption", candidate.CompletionReason);
        Assert.Equal(2, recoveredSamples.Count);
        Assert.Equal(4096, recoveredSamples[0].BF6PrivateMB);
        Assert.Equal(4352, recoveredSamples[1].BF6PrivateMB);

        store.Complete(candidate.Marker.SessionFolder, sessionsRoot);
        Assert.False(File.Exists(Path.Combine(sessionFolder, "ACTIVE.json")));
        Assert.True(File.Exists(journal.GetPath(sessionFolder)));
    }

    private static DiagnosticReport CreateMinimalReport(string sessionId) =>
        new(
            2,
            "2.0.0-beta.1",
            sessionId,
            DiagnosticMode.Retrospective,
            BaseTime,
            BaseTime.AddMinutes(1),
            "SyntheticFixture",
            null,
            null,
            null,
            [],
            [],
            [],
            [],
            [],
            [],
            [new CollectionStatus("Synthetic fixture", CollectionState.Available, "In-memory data only.")],
            "Synthetic report.\n");

    private static DiagnosticEvent CreateEvent(EventSpec specification) =>
        new(
            BaseTime.AddMinutes(specification.Minute),
            specification.Provider == "Display" ? "System" : "Microsoft-Windows-Kernel-EventTracing/Admin",
            specification.Provider,
            string.IsNullOrWhiteSpace(specification.ProviderGuid) ? null : Guid.Parse(specification.ProviderGuid),
            specification.EventId,
            2,
            "Error",
            specification.Message,
            specification.Data);

    private static PerformanceSample CreateSample(SampleSpec specification) =>
        new(
            BaseTime.AddMinutes(specification.Minute),
            true,
            1234,
            "BF6",
            50,
            16,
            16,
            specification.CommitPct / 100 * 40,
            40,
            specification.CommitPct,
            5000,
            specification.PrivateMb,
            40,
            70,
            75,
            9000,
            500,
            20);

    private static async Task<string> ComputeSha256Async(string path)
    {
        await using FileStream stream = File.OpenRead(path);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream)).ToLowerInvariant();
    }

    public sealed record ScenarioSpec(
        string Name,
        IReadOnlyList<EventSpec> Events,
        IReadOnlyList<SampleSpec> Samples,
        IReadOnlyList<string> ExpectedFindingPrefixes,
        IReadOnlyList<string> UnexpectedFindingIds)
    {
        public override string ToString() => Name;
    }

    public sealed record EventSpec(
        double Minute,
        string Provider,
        int EventId,
        string Message,
        string? ProviderGuid,
        IReadOnlyDictionary<string, string> Data);

    public sealed record SampleSpec(double Minute, double PrivateMb, double CommitPct);
}
