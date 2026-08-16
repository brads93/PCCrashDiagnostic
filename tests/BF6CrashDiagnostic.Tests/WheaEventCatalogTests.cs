using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class WheaEventCatalogTests
{
    [Fact]
    public void Catalog_ProvidesStableDisjointClassifications()
    {
        Assert.Equal(
            [1, 16, 18, 20, 22, 24, 26, 29, 40, 42, 44, 46, 48],
            WheaEventCatalog.FatalEventIds);
        Assert.Equal(
            [2, 17, 19, 21, 23, 25, 27, 28, 41, 43, 45, 47, 49],
            WheaEventCatalog.CorrectedEventIds);
        Assert.Equal([3], WheaEventCatalog.InformationalEventIds);
        Assert.Empty(WheaEventCatalog.FatalEventIds.Intersect(WheaEventCatalog.CorrectedEventIds));
        Assert.Equal(
            WheaEventCatalog.FatalEventIds
                .Concat(WheaEventCatalog.CorrectedEventIds)
                .Concat(WheaEventCatalog.InformationalEventIds)
                .Order(),
            WheaEventCatalog.KnownEventIds);
    }

    [Theory]
    [InlineData(1, WheaEventClassification.Fatal)]
    [InlineData(18, WheaEventClassification.Fatal)]
    [InlineData(46, WheaEventClassification.Fatal)]
    [InlineData(3, WheaEventClassification.Informational)]
    [InlineData(17, WheaEventClassification.Corrected)]
    [InlineData(47, WheaEventClassification.Corrected)]
    [InlineData(999, WheaEventClassification.Unknown)]
    public void Classify_ReturnsOnlyCatalogedMeaning(int eventId, WheaEventClassification expected)
    {
        Assert.Equal(expected, WheaEventCatalog.Classify(eventId));
        Assert.Equal(expected != WheaEventClassification.Unknown, WheaEventCatalog.IsKnown(eventId));
    }

    [Theory]
    [InlineData("Microsoft-Windows-WHEA-Logger", true)]
    [InlineData("microsoft-windows-whea-logger", true)]
    [InlineData(" Microsoft-Windows-WHEA-Logger ", true)]
    [InlineData("Example-WHEA-Logger", false)]
    [InlineData("Microsoft-Windows-WHEA-Logger-Clone", false)]
    [InlineData(null, false)]
    public void IsProvider_RequiresCanonicalProviderIdentity(string? providerName, bool expected)
    {
        Assert.Equal(expected, WheaEventCatalog.IsProvider(providerName));
    }

    [Fact]
    public void IsProvider_RejectsConflictingProviderGuid()
    {
        Assert.True(WheaEventCatalog.IsProvider(WheaEventCatalog.ProviderName, WheaEventCatalog.ProviderGuid));
        Assert.True(WheaEventCatalog.IsProvider(WheaEventCatalog.ProviderName, null));
        Assert.False(WheaEventCatalog.IsProvider(WheaEventCatalog.ProviderName, Guid.Empty));
    }

    [Fact]
    public void EventAnalyzer_UsesEveryFatalAndCorrectedCatalogClassification()
    {
        var analyzer = new EventAnalyzer();
        DateTimeOffset time = DateTimeOffset.Parse("2026-08-03T04:30:00Z");
        foreach ((IReadOnlyList<int> eventIds, string expectedTitle) in new[]
                 {
                     (WheaEventCatalog.FatalEventIds, "Fatal hardware error"),
                     (WheaEventCatalog.CorrectedEventIds, "Corrected hardware error")
                 })
        {
            foreach (int eventId in eventIds)
            {
                var diagnosticEvent = new DiagnosticEvent(
                    time,
                    "System",
                    WheaEventCatalog.ProviderName,
                    WheaEventCatalog.ProviderGuid,
                    eventId,
                    2,
                    "Error",
                    "Windows stored a standardized hardware error record.",
                    new Dictionary<string, string>());
                IReadOnlyList<DuplicateEventGroup> groups = analyzer.GroupDuplicates([diagnosticEvent]);

                DiagnosticFinding finding = Assert.Single(
                    analyzer.Analyze(null, [diagnosticEvent], groups, [], [], []),
                    item => item.Id == "whea");

                Assert.Equal(expectedTitle, finding.Title);
            }
        }
    }
}
