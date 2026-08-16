using System.Collections.ObjectModel;

namespace BF6CrashDiagnostic.Core.Analysis;

/// <summary>
/// Identifies the WHEA-Logger event IDs the diagnostic understands. Event IDs not listed
/// here remain unclassified; callers must not infer severity from parity or message text.
/// </summary>
public static class WheaEventCatalog
{
    public const string ProviderName = "Microsoft-Windows-WHEA-Logger";

    public static Guid ProviderGuid { get; } = new("c26c4f3c-3f66-4e99-8f8a-39405cfed220");

    private static readonly HashSet<int> FatalIds =
        [1, 16, 18, 20, 22, 24, 26, 29, 40, 42, 44, 46, 48];

    private static readonly HashSet<int> CorrectedIds =
        [2, 17, 19, 21, 23, 25, 27, 28, 41, 43, 45, 47, 49];

    private static readonly HashSet<int> InformationalIds = [3];

    private static readonly ReadOnlyCollection<int> FatalIdsView =
        Array.AsReadOnly(FatalIds.Order().ToArray());

    private static readonly ReadOnlyCollection<int> CorrectedIdsView =
        Array.AsReadOnly(CorrectedIds.Order().ToArray());

    private static readonly ReadOnlyCollection<int> InformationalIdsView =
        Array.AsReadOnly(InformationalIds.Order().ToArray());

    private static readonly ReadOnlyCollection<int> KnownIdsView =
        Array.AsReadOnly(FatalIds.Concat(CorrectedIds).Concat(InformationalIds).Order().ToArray());

    public static IReadOnlyList<int> FatalEventIds => FatalIdsView;

    public static IReadOnlyList<int> CorrectedEventIds => CorrectedIdsView;

    public static IReadOnlyList<int> InformationalEventIds => InformationalIdsView;

    public static IReadOnlyList<int> KnownEventIds => KnownIdsView;

    public static bool IsProvider(string? providerName) =>
        ProviderName.Equals(providerName?.Trim(), StringComparison.OrdinalIgnoreCase);

    public static bool IsProvider(string? providerName, Guid? providerGuid) =>
        IsProvider(providerName) && (providerGuid is null || providerGuid == ProviderGuid);

    public static bool IsKnown(int eventId) =>
        FatalIds.Contains(eventId) || CorrectedIds.Contains(eventId) || InformationalIds.Contains(eventId);

    public static WheaEventClassification Classify(int eventId)
    {
        if (FatalIds.Contains(eventId))
        {
            return WheaEventClassification.Fatal;
        }

        if (CorrectedIds.Contains(eventId))
        {
            return WheaEventClassification.Corrected;
        }

        return InformationalIds.Contains(eventId)
            ? WheaEventClassification.Informational
            : WheaEventClassification.Unknown;
    }
}

public enum WheaEventClassification
{
    Unknown,
    Informational,
    Corrected,
    Fatal
}
