using System.Text.Json;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class RecentChangeCollectorTests
{
    [Beta2Fact]
    [Trait("Category", "SyntheticScenario")]
    public void SetupApiParser_KeepsTimelineFactsAndDropsDeviceIdentifiersAndPaths()
    {
        DateTime local = DateTime.Now;
        string text = $"""
            >>>  [Device Install (Hardware initiated) - PCI\VEN_1234&DEV_5678\PRIVATE-ID]
            >>>  Section start {local:yyyy/MM/dd HH:mm:ss.fff}
                 Published Name: oem42.inf
                 User path: C:\Users\Alice\private\driver.inf
            <<<  [Exit status: SUCCESS]
            """;
        DateTimeOffset center = new(local);

        IReadOnlyList<RecentSystemChange> records = SetupApiTimelineReader.Parse(
            new StringReader(text),
            center.AddMinutes(-1).ToUniversalTime(),
            center.AddMinutes(1).ToUniversalTime(),
            CancellationToken.None);

        RecentSystemChange record = Assert.Single(records);
        Assert.Equal(RecentChangeKind.DriverInstallation, record.Kind);
        Assert.Equal("Device Install (Hardware initiated)", record.Title);
        Assert.Equal("Published oem42.inf", record.Operation);
        Assert.Equal("Succeeded", record.Result);
        string json = JsonSerializer.Serialize(records);
        Assert.DoesNotContain("VEN_1234", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PRIVATE-ID", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Alice", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("driver.inf", json, StringComparison.OrdinalIgnoreCase);
    }

    [Beta2Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task Collector_MergesSourcesInTimeOrderAndPreservesCoverage()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var updateRecord = new RecentSystemChange(
            now.AddMinutes(-3),
            RecentChangeKind.WindowsUpdate,
            "Security update",
            "Installation",
            "Succeeded",
            string.Empty);
        var driverRecord = new RecentSystemChange(
            now.AddMinutes(-1),
            RecentChangeKind.DriverInstallation,
            "Device install",
            "Published oem4.inf",
            "Succeeded",
            string.Empty);
        var collector = new RecentChangeCollector(
            new FakeUpdateReader(new RecentChangeSourceResult(
                [updateRecord],
                new CollectionStatus("updates", CollectionState.Available, "read"))),
            new FakeSetupReader(new RecentChangeSourceResult(
                [driverRecord],
                new CollectionStatus("setup", CollectionState.Available, "read"))),
            TimeProvider.System);

        RecentChangeTimeline result = await collector.CollectAsync(
            now.AddHours(-1),
            now.AddHours(1));

        Assert.Equal([updateRecord, driverRecord], result.Records);
        Assert.Equal(2, result.CollectionStatus.Count);
        Assert.All(result.CollectionStatus, status => Assert.Equal(CollectionState.Available, status.State));
    }

    [Beta2Fact]
    public void SanitizeText_RedactsWindowsPathsAndCollapsesWhitespace()
    {
        string result = RecentChangeCollector.SanitizeText(
            "Driver   installed from C:\\Users\\Alice\\Desktop\\private.inf");

        Assert.Equal("Driver installed from <path>", result);
        Assert.DoesNotContain("Alice", result, StringComparison.OrdinalIgnoreCase);
    }

    [Beta2Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task IncidentCollection_IsBoundedToPriorSevenDaysAndAddsTimingContext()
    {
        DateTimeOffset incident = new(2026, 8, 5, 12, 0, 0, TimeSpan.Zero);
        var withinDay = new RecentSystemChange(
            incident.AddHours(-12), RecentChangeKind.WindowsUpdate, "Within day", "Installation", "Succeeded", string.Empty);
        var withinWeek = new RecentSystemChange(
            incident.AddDays(-3), RecentChangeKind.DriverInstallation, "Within week", "Published oem1.inf", "Succeeded", string.Empty);
        var tooOld = new RecentSystemChange(
            incident.AddDays(-8), RecentChangeKind.WindowsUpdate, "Too old", "Installation", "Succeeded", string.Empty);
        var future = new RecentSystemChange(
            incident.AddMinutes(1), RecentChangeKind.WindowsUpdate, "Future", "Installation", "Succeeded", string.Empty);
        var collector = new RecentChangeCollector(
            new FakeUpdateReader(new RecentChangeSourceResult(
                [withinDay, tooOld, future],
                new CollectionStatus("updates", CollectionState.Available, "read"))),
            new FakeSetupReader(new RecentChangeSourceResult(
                [withinWeek],
                new CollectionStatus("setup", CollectionState.Available, "read"))),
            TimeProvider.System);

        RecentChangeTimeline timeline = await collector.CollectForIncidentAsync(incident);

        Assert.Equal(incident.AddDays(-7), timeline.WindowStartUtc);
        Assert.Equal(incident, timeline.WindowEndUtc);
        Assert.Equal(2, timeline.Records.Count);
        RecentSystemChange first = Assert.Single(timeline.Records, item => item.Title == "Within week");
        Assert.Equal(TimeSpan.FromDays(3), first.TimeBeforeIncident);
        Assert.False(first.Within24Hours);
        Assert.True(first.WithinSevenDays);
        RecentSystemChange second = Assert.Single(timeline.Records, item => item.Title == "Within day");
        Assert.Equal(TimeSpan.FromHours(12), second.TimeBeforeIncident);
        Assert.True(second.Within24Hours);
        Assert.True(second.WithinSevenDays);
        Assert.DoesNotContain(timeline.Records, item => item.Title is "Too old" or "Future");
    }

    [Beta2Fact]
    public void IncidentProximity_DoesNotMislabelPostIncidentEntry()
    {
        DateTimeOffset incident = DateTimeOffset.UtcNow;
        var future = new RecentSystemChange(
            incident.AddMinutes(1), RecentChangeKind.WindowsUpdate, "Future", "Installation", "Succeeded", string.Empty);

        RecentSystemChange result = RecentChangeCollector.WithIncidentProximity(future, incident);

        Assert.Null(result.TimeBeforeIncident);
        Assert.False(result.Within24Hours);
        Assert.False(result.WithinSevenDays);
    }

    private sealed class FakeUpdateReader(RecentChangeSourceResult result) : IWindowsUpdateHistoryReader
    {
        public RecentChangeSourceResult Read(
            DateTimeOffset startUtc,
            DateTimeOffset endUtc,
            CancellationToken cancellationToken) => result;
    }

    private sealed class FakeSetupReader(RecentChangeSourceResult result) : ISetupApiTimelineReader
    {
        public RecentChangeSourceResult Read(
            DateTimeOffset startUtc,
            DateTimeOffset endUtc,
            CancellationToken cancellationToken) => result;
    }
}
