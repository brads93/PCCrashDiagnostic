using System.Text.RegularExpressions;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Analysis;

public sealed partial class IncidentDiscovery
{
    private static readonly TimeSpan ClusterWindow = TimeSpan.FromMinutes(3);

    public IReadOnlyList<IncidentCandidate> Discover(
        IEnumerable<DiagnosticEvent> events,
        IEnumerable<ReliabilityRecord>? reliability = null,
        TargetProfile? targetProfile = null,
        int maximumCandidates = 32)
    {
        ArgumentNullException.ThrowIfNull(events);
        if (maximumCandidates <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maximumCandidates));
        }

        var seeds = new List<IncidentSeed>();
        foreach (DiagnosticEvent diagnosticEvent in events)
        {
            if (TryCreateSeed(diagnosticEvent, targetProfile, out IncidentSeed seed))
            {
                seeds.Add(seed);
            }
        }

        foreach (ReliabilityRecord record in reliability ?? [])
        {
            if (TryCreateSeed(record, targetProfile, out IncidentSeed seed))
            {
                seeds.Add(seed);
            }
        }

        var candidates = new List<IncidentCandidate>();
        bool[] consumed = new bool[seeds.Count];
        foreach (int primaryIndex in Enumerable.Range(0, seeds.Count)
                     .OrderByDescending(index => seeds[index].Priority)
                     .ThenByDescending(index => seeds[index].TimeUtc))
        {
            if (consumed[primaryIndex])
            {
                continue;
            }

            consumed[primaryIndex] = true;
            IncidentSeed primary = seeds[primaryIndex];
            int[] supportingIndexes = Enumerable.Range(0, seeds.Count)
                .Where(index => !consumed[index] &&
                                IsCompatible(primary, seeds[index]) &&
                                (seeds[index].TimeUtc - primary.TimeUtc).Duration() <= ClusterWindow)
                .ToArray();
            foreach (int supportingIndex in supportingIndexes)
            {
                consumed[supportingIndex] = true;
            }

            IncidentSeed[] supporting = supportingIndexes.Select(index => seeds[index]).ToArray();
            DateTimeOffset[] times = [primary.TimeUtc, .. supporting.Select(seed => seed.TimeUtc)];
            IncidentFingerprint fingerprint = IncidentFingerprint.Create(
                primary.Kind,
                primary.TimeUtc,
                primary.Source,
                primary.EventId,
                primary.TargetProfileId,
                primary.BugcheckCode);
            candidates.Add(new IncidentCandidate(
                fingerprint,
                primary.TimeUtc,
                primary.Kind,
                primary.Title,
                primary.Source,
                primary.EventId,
                primary.TargetProfileId,
                primary.BugcheckCode,
                primary.DumpFileName,
                primary.Priority,
                supporting.Length + 1,
                times.Min(),
                times.Max(),
                primary.EvidenceOrigin));
        }

        return candidates
            .OrderByDescending(candidate => candidate.TimeUtc)
            .ThenByDescending(candidate => candidate.EvidencePriority)
            .Take(maximumCandidates)
            .ToArray();
    }

    public IncidentSelection Select(
        IncidentCandidate candidate,
        IncidentSelectionMethod method = IncidentSelectionMethod.UserSelected,
        TimeSpan? evidenceBefore = null,
        TimeSpan? evidenceAfter = null)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        TimeSpan before = evidenceBefore ?? DefaultBefore(candidate.Kind);
        TimeSpan after = evidenceAfter ?? DefaultAfter(candidate.Kind);
        if (before < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(evidenceBefore));
        }

        if (after < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(evidenceAfter));
        }

        return new IncidentSelection(
            candidate,
            candidate.TimeUtc - before,
            candidate.TimeUtc + after,
            method);
    }

    private static bool TryCreateSeed(
        DiagnosticEvent item,
        TargetProfile? targetProfile,
        out IncidentSeed seed)
    {
        if (BugcheckRecordDecoder.TryDecode(item, out BugcheckRecord bugcheck))
        {
            seed = new IncidentSeed(
                item.TimeUtc,
                IncidentKind.Bugcheck,
                "Windows bugcheck",
                item.ProviderName,
                item.EventId,
                targetProfile?.Id,
                bugcheck.NormalizedCode,
                bugcheck.DumpFileName,
                bugcheck.EvidenceSource == BugcheckEvidenceSource.WindowsErrorReporting ? 1_000 : 900);
            return true;
        }

        if (item.EventId == 41 && item.ProviderName.Contains("Kernel-Power", StringComparison.OrdinalIgnoreCase))
        {
            seed = Seed(item, IncidentKind.UnexpectedRestart, "Unexpected restart", targetProfile, 500);
            return true;
        }

        if (item.EventId == 6008 && item.ProviderName.Equals("EventLog", StringComparison.OrdinalIgnoreCase))
        {
            seed = Seed(item, IncidentKind.UnexpectedRestart, "Unexpected shutdown", targetProfile, 400);
            return true;
        }

        if (WheaEventCatalog.IsProvider(item.ProviderName, item.ProviderGuid) &&
            WheaEventCatalog.IsKnown(item.EventId))
        {
            bool fatal = WheaEventCatalog.Classify(item.EventId) == WheaEventClassification.Fatal;
            seed = Seed(
                item,
                IncidentKind.HardwareError,
                fatal ? "Fatal hardware error" : "Corrected hardware error",
                targetProfile,
                fatal ? 850 : 450);
            return true;
        }

        if (IsGpuTimeout(item))
        {
            seed = Seed(item, IncidentKind.GpuTimeout, "GPU timeout or driver reset", targetProfile, 750);
            return true;
        }

        if (item.EventId == 2004 &&
            item.ProviderName.Contains("Resource-Exhaustion", StringComparison.OrdinalIgnoreCase))
        {
            seed = Seed(item, IncidentKind.ResourceExhaustion, "Low resource warning", targetProfile, 600);
            return true;
        }

        string searchable = item.ProviderName + " " + item.Message + " " + string.Join(' ', item.Data.Values);
        if (item.EventId is 1000 or 1001 or 1002 &&
            targetProfile is not null &&
            targetProfile.MatchesApplicationEvidence(searchable))
        {
            IncidentKind kind = item.EventId == 1002 ? IncidentKind.ApplicationHang : IncidentKind.ApplicationCrash;
            seed = Seed(
                item,
                kind,
                kind == IncidentKind.ApplicationHang ? "Application hang" : "Application crash",
                targetProfile,
                kind == IncidentKind.ApplicationHang ? 625 : 650);
            return true;
        }

        seed = default!;
        return false;
    }

    private static bool TryCreateSeed(
        ReliabilityRecord item,
        TargetProfile? targetProfile,
        out IncidentSeed seed)
    {
        string searchable = string.Join(' ', item.SourceName, item.ProductName, item.EventIdentifier, item.Message);
        if (searchable.Contains("BlueScreen", StringComparison.OrdinalIgnoreCase))
        {
            seed = new IncidentSeed(
                item.TimeUtc,
                IncidentKind.Bugcheck,
                "Windows blue-screen report",
                item.SourceName,
                0,
                targetProfile?.Id,
                null,
                null,
                950,
                IncidentEvidenceOrigin.ReliabilityMonitor);
            return true;
        }

        if (GpuReliabilityRegex().IsMatch(searchable))
        {
            seed = new IncidentSeed(
                item.TimeUtc,
                IncidentKind.GpuTimeout,
                "GPU timeout or driver reset",
                item.SourceName,
                0,
                targetProfile?.Id,
                null,
                null,
                725,
                IncidentEvidenceOrigin.ReliabilityMonitor);
            return true;
        }

        if (searchable.Contains("HardwareError", StringComparison.OrdinalIgnoreCase) ||
            searchable.Contains("Windows Hardware Error", StringComparison.OrdinalIgnoreCase))
        {
            seed = new IncidentSeed(
                item.TimeUtc,
                IncidentKind.HardwareError,
                "Hardware error report",
                item.SourceName,
                0,
                targetProfile?.Id,
                null,
                null,
                700,
                IncidentEvidenceOrigin.ReliabilityMonitor);
            return true;
        }

        if (targetProfile is not null && targetProfile.MatchesReliabilityEvidence(searchable))
        {
            seed = new IncidentSeed(
                item.TimeUtc,
                IncidentKind.ApplicationCrash,
                "Application reliability failure",
                item.SourceName,
                0,
                targetProfile.Id,
                null,
                null,
                575,
                IncidentEvidenceOrigin.ReliabilityMonitor);
            return true;
        }

        seed = default!;
        return false;
    }

    private static IncidentSeed Seed(
        DiagnosticEvent item,
        IncidentKind kind,
        string title,
        TargetProfile? targetProfile,
        int priority) =>
        new(
            item.TimeUtc,
            kind,
            title,
            item.ProviderName,
            item.EventId,
            targetProfile?.Id,
            null,
            null,
            priority);

    private static bool IsCompatible(IncidentSeed primary, IncidentSeed other)
    {
        if (!string.Equals(primary.TargetProfileId, other.TargetProfileId, StringComparison.OrdinalIgnoreCase) &&
            primary.TargetProfileId is not null &&
            other.TargetProfileId is not null)
        {
            return false;
        }

        if (primary.Kind is IncidentKind.ApplicationCrash or IncidentKind.ApplicationHang ||
            other.Kind is IncidentKind.ApplicationCrash or IncidentKind.ApplicationHang)
        {
            return primary.Kind is IncidentKind.ApplicationCrash or IncidentKind.ApplicationHang &&
                   other.Kind is IncidentKind.ApplicationCrash or IncidentKind.ApplicationHang;
        }

        return true;
    }

    private static bool IsGpuTimeout(DiagnosticEvent item)
    {
        if (item.ProviderName.Equals("Display", StringComparison.OrdinalIgnoreCase) && item.EventId == 4101)
        {
            return true;
        }

        string text = item.ProviderName + " " + item.Message;
        bool provider = item.ProviderName.Contains("DxgKrnl", StringComparison.OrdinalIgnoreCase) ||
                        item.ProviderName.Contains("nvlddmkm", StringComparison.OrdinalIgnoreCase) ||
                        item.ProviderName.Contains("amdkmdag", StringComparison.OrdinalIgnoreCase) ||
                        item.ProviderName.Contains("amdwddmg", StringComparison.OrdinalIgnoreCase);
        return provider && GpuEventRegex().IsMatch(text);
    }

    private static TimeSpan DefaultBefore(IncidentKind kind) => kind switch
    {
        IncidentKind.Bugcheck or IncidentKind.UnexpectedRestart or IncidentKind.HardwareError => TimeSpan.FromMinutes(30),
        IncidentKind.GpuTimeout or IncidentKind.ResourceExhaustion => TimeSpan.FromMinutes(15),
        _ => TimeSpan.FromMinutes(10)
    };

    private static TimeSpan DefaultAfter(IncidentKind kind) => kind switch
    {
        IncidentKind.Bugcheck or IncidentKind.UnexpectedRestart or IncidentKind.HardwareError => TimeSpan.FromMinutes(15),
        IncidentKind.GpuTimeout or IncidentKind.ResourceExhaustion => TimeSpan.FromMinutes(10),
        _ => TimeSpan.FromMinutes(5)
    };

    [GeneratedRegex(@"(?i)LiveKernelEvent\s*(117|141)|VIDEO_(?:ENGINE|TDR)_TIMEOUT|display driver", RegexOptions.CultureInvariant)]
    private static partial Regex GpuReliabilityRegex();

    [GeneratedRegex(@"(?i)stopped responding|successfully recovered|\breset\b|\btimeout\b|\bTDR\b", RegexOptions.CultureInvariant)]
    private static partial Regex GpuEventRegex();

    private sealed record IncidentSeed(
        DateTimeOffset TimeUtc,
        IncidentKind Kind,
        string Title,
        string Source,
        int EventId,
        string? TargetProfileId,
        string? BugcheckCode,
        string? DumpFileName,
        int Priority,
        IncidentEvidenceOrigin EvidenceOrigin = IncidentEvidenceOrigin.WindowsEventLog);
}
