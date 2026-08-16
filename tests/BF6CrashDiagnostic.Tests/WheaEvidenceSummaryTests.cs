using System.Text.Json;
using System.Text.Json.Nodes;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Tests;

public sealed class WheaEvidenceSummaryTests
{
    private static readonly DateTimeOffset EventTime =
        new(2026, 8, 16, 14, 30, 0, TimeSpan.Zero);

    [Fact]
    public void Summarize_UsesOnlyCatalogedEventsAndControlledCperCategories()
    {
        DiagnosticEvent[] events =
        [
            Event(18, "Processor, Memory, Memory"),
            Event(18, "Processor, Memory"),
            Event(17, "Memory"),
            Event(999, "Processor"),
            Event(18, "Network adapter"),
            Event(18, "PCIe", providerName: "Example-WHEA-Logger")
        ];

        IReadOnlyList<WheaEvidence> actual = WheaEvidenceSummarizer.Summarize(events);

        Assert.Equal(3, actual.Count);
        Assert.Contains(actual, item =>
            item.EventId == 18 &&
            item.Classification == WheaEventClassification.Fatal &&
            item.Category == WheaEvidenceCategory.Processor &&
            item.Count == 2);
        Assert.Contains(actual, item =>
            item.EventId == 18 &&
            item.Classification == WheaEventClassification.Fatal &&
            item.Category == WheaEvidenceCategory.Memory &&
            item.Count == 2);
        Assert.Contains(actual, item =>
            item.EventId == 17 &&
            item.Classification == WheaEventClassification.Corrected &&
            item.Category == WheaEvidenceCategory.Memory &&
            item.Count == 1);
        Assert.DoesNotContain(actual, item => item.Category == WheaEvidenceCategory.Generic);
    }

    [Fact]
    public void Summarize_MapsAllDocumentedCollectorCategoryLabels()
    {
        IReadOnlyList<WheaEvidence> actual = WheaEvidenceSummarizer.Summarize(
            [Event(3, "Processor, Memory, PCIe, Generic hardware")]);

        Assert.Equal(
            [
                WheaEvidenceCategory.Processor,
                WheaEvidenceCategory.Memory,
                WheaEvidenceCategory.PCIe,
                WheaEvidenceCategory.Generic
            ],
            actual.Select(item => item.Category));
        Assert.All(actual, item => Assert.Equal(WheaEventClassification.Informational, item.Classification));
    }

    [Fact]
    public void ReportSchema3_DeserializesOlderReportWithoutWheaEvidence()
    {
        DiagnosticReportV3 current = SafeSummaryTestData.Create("whea-backward-compatible") with
        {
            WheaEvidence = [new WheaEvidence(18, WheaEventClassification.Fatal, WheaEvidenceCategory.Processor, 2)]
        };
        JsonObject oldSchema3 = Assert.IsType<JsonObject>(JsonSerializer.SerializeToNode(current));
        Assert.True(oldSchema3.Remove(nameof(DiagnosticReportV3.WheaEvidence)));

        DiagnosticReportV3? restored = JsonSerializer.Deserialize<DiagnosticReportV3>(oldSchema3.ToJsonString());

        Assert.NotNull(restored);
        Assert.Equal(3, restored.ReportSchemaVersion);
        Assert.Null(restored.WheaEvidence);
    }

    [Fact]
    public async Task WriteV3Async_IncludesTypedWheaEvidenceInIncidentMember()
    {
        using var directory = new TestDirectory();
        var evidence = new WheaEvidence(
            18,
            WheaEventClassification.Fatal,
            WheaEvidenceCategory.PCIe,
            3);
        DiagnosticReportV3 report = SafeSummaryTestData.Create("whea-incident-member") with
        {
            WheaEvidence = [evidence]
        };

        ReportPackageV3 package = await new ReportWriter(directory.Path)
            .WriteV3Async(report, CancellationToken.None);
        using JsonDocument document = JsonDocument.Parse(
            await File.ReadAllTextAsync(Path.Combine(package.SessionFolder, "Incident.json")));
        JsonElement item = document.RootElement.GetProperty("WheaEvidence")[0];

        Assert.Equal(18, item.GetProperty("EventId").GetInt32());
        Assert.Equal((int)WheaEventClassification.Fatal, item.GetProperty("Classification").GetInt32());
        Assert.Equal((int)WheaEvidenceCategory.PCIe, item.GetProperty("Category").GetInt32());
        Assert.Equal(3, item.GetProperty("Count").GetInt32());
    }

    private static DiagnosticEvent Event(
        int eventId,
        string categories,
        string providerName = WheaEventCatalog.ProviderName) =>
        new(
            EventTime,
            "System",
            providerName,
            providerName == WheaEventCatalog.ProviderName ? WheaEventCatalog.ProviderGuid : null,
            eventId,
            2,
            "Error",
            "Rendered message is not used for the typed summary.",
            new Dictionary<string, string> { ["CperSectionCategories"] = categories });
}
