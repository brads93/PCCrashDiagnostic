using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Analysis;

public enum StorageEventCategory
{
    IoError,
    TimeoutOrReset
}

public sealed record StorageEventSignal(
    string ProviderName,
    IReadOnlyList<int> EventIds,
    StorageEventCategory Category);

/// <summary>
/// Explicit provider/event pairs for storage evidence, including Intel Rapid
/// Storage Technology provider names seen with controller-reset Event 129.
/// </summary>
public static class StorageEventCatalog
{
    public static IReadOnlyList<StorageEventSignal> Signals { get; } =
    [
        new("disk", [7, 11, 51], StorageEventCategory.IoError),
        new("disk", [153], StorageEventCategory.TimeoutOrReset),
        new("storahci", [129], StorageEventCategory.TimeoutOrReset),
        new("stornvme", [129], StorageEventCategory.TimeoutOrReset),
        new("Microsoft-Windows-StorPort", [129], StorageEventCategory.TimeoutOrReset),
        new("iaStorA", [129], StorageEventCategory.TimeoutOrReset),
        new("iaStorAC", [129], StorageEventCategory.TimeoutOrReset),
        new("iaStorAV", [129], StorageEventCategory.TimeoutOrReset),
        new("iaStorAVC", [129], StorageEventCategory.TimeoutOrReset),
        new("iaStorV", [129], StorageEventCategory.TimeoutOrReset),
        new("iaStorVD", [129], StorageEventCategory.TimeoutOrReset)
    ];

    public static bool TryClassify(string? providerName, int eventId, out StorageEventCategory category)
    {
        StorageEventSignal? signal = Signals.FirstOrDefault(item =>
            item.ProviderName.Equals(providerName, StringComparison.OrdinalIgnoreCase) &&
            item.EventIds.Contains(eventId));
        if (signal is null)
        {
            category = default;
            return false;
        }

        category = signal.Category;
        return true;
    }

    public static bool TryClassify(DiagnosticEvent diagnosticEvent, out StorageEventCategory category) =>
        TryClassify(diagnosticEvent.ProviderName, diagnosticEvent.EventId, out category);
}
