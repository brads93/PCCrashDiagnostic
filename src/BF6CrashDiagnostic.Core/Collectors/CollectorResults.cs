using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Collectors;

public sealed record WindowsEventCollection(
    CrashAnchor? Anchor,
    DateTimeOffset WindowStartUtc,
    DateTimeOffset WindowEndUtc,
    IReadOnlyList<DiagnosticEvent> Events,
    IReadOnlyList<DuplicateEventGroup> DuplicateGroups,
    IReadOnlyList<CollectionStatus> Statuses);

public sealed record SystemSnapshotCollection(
    SystemSnapshot Snapshot,
    IReadOnlyList<CollectionStatus> Statuses);

public sealed record ReliabilityCollection(
    IReadOnlyList<ReliabilityRecord> Records,
    IReadOnlyList<CollectionStatus> Statuses);

public sealed record ArtifactCollection(
    IReadOnlyList<CrashArtifact> Artifacts,
    IReadOnlyList<CollectionStatus> Statuses);
