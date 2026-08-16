using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Analysis;

public static class WheaEvidenceSummarizer
{
    private const string CategoriesField = "CperSectionCategories";

    public static IReadOnlyList<WheaEvidence> Summarize(IEnumerable<DiagnosticEvent> events)
    {
        ArgumentNullException.ThrowIfNull(events);

        return events
            .SelectMany(SummarizeEvent)
            .GroupBy(item => new { item.EventId, item.Classification, item.Category })
            .Select(group => new WheaEvidence(
                group.Key.EventId,
                group.Key.Classification,
                group.Key.Category,
                group.Count()))
            .OrderBy(item => item.EventId)
            .ThenBy(item => item.Category)
            .ToArray();
    }

    private static IEnumerable<WheaEvidence> SummarizeEvent(DiagnosticEvent diagnosticEvent)
    {
        if (!WheaEventCatalog.IsKnown(diagnosticEvent.EventId) ||
            !WheaEventDecoder.TryDecode(diagnosticEvent, out DecodedWheaEvent? decoded) ||
            !decoded.Fields.TryGetValue(CategoriesField, out string? categories))
        {
            yield break;
        }

        foreach (WheaEvidenceCategory category in ParseCategories(categories).Distinct())
        {
            yield return new WheaEvidence(
                decoded.EventId,
                decoded.Classification,
                category,
                1);
        }
    }

    private static IEnumerable<WheaEvidenceCategory> ParseCategories(string categories)
    {
        foreach (string item in categories.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            if (item.Equals("Processor", StringComparison.OrdinalIgnoreCase))
            {
                yield return WheaEvidenceCategory.Processor;
            }
            else if (item.Equals("Memory", StringComparison.OrdinalIgnoreCase))
            {
                yield return WheaEvidenceCategory.Memory;
            }
            else if (item.Equals("PCIe", StringComparison.OrdinalIgnoreCase))
            {
                yield return WheaEvidenceCategory.PCIe;
            }
            else if (item.Equals("Generic hardware", StringComparison.OrdinalIgnoreCase))
            {
                yield return WheaEvidenceCategory.Generic;
            }
        }
    }
}
