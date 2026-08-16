using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Analysis;

/// <summary>
/// Shared bounded catalog for Kernel-EventTracing evidence. Keeping the IDs in
/// one place prevents collection and interpretation from drifting apart.
/// </summary>
public static class KernelEventTracingCatalog
{
    public const string ProviderName = "Microsoft-Windows-Kernel-EventTracing";
    public const string AdminLogName = "Microsoft-Windows-Kernel-EventTracing/Admin";

    public static IReadOnlyList<int> EvidenceEventIds { get; } = [2, 3, 4, 28, 29];

    public static IReadOnlyList<int> ProviderTraitsEventIds { get; } = [28, 29];

    public static bool IsProvider(string? providerName) =>
        !string.IsNullOrWhiteSpace(providerName) &&
        providerName.Contains("Kernel-EventTracing", StringComparison.OrdinalIgnoreCase);

    public static bool IsProviderTraitsEvent(int eventId) => ProviderTraitsEventIds.Contains(eventId);

    public static bool IsProviderTraitsEvent(DiagnosticEvent diagnosticEvent) =>
        IsProvider(diagnosticEvent.ProviderName) &&
        IsProviderTraitsEvent(diagnosticEvent.EventId);
}
