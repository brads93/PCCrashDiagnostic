using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Analysis;

public sealed class BootSessionReconstructor
{
    private static readonly TimeSpan CorroborationWindow = TimeSpan.FromMinutes(2);

    public BootSessionContext Reconstruct(
        DateTimeOffset incidentTimeUtc,
        IEnumerable<DiagnosticEvent> events,
        DateTimeOffset? currentBootUtc = null)
    {
        ArgumentNullException.ThrowIfNull(events);
        DateTimeOffset incident = incidentTimeUtc.ToUniversalTime();
        BootSessionRecord[] records = events
            .Select(TryCreateRecord)
            .Where(record => record is not null)
            .Cast<BootSessionRecord>()
            .OrderBy(record => record.TimeUtc)
            .ThenBy(record => record.ProviderName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(record => record.EventId)
            .ToArray();

        BootSessionRecord[] starts = records
            .Where(record => record.BoundaryKind == BootSessionBoundaryKind.StartMarker)
            .ToArray();
        BootSessionRecord? latestPriorStart = starts.LastOrDefault(record => record.TimeUtc <= incident);
        BootSessionRecord? priorStart = latestPriorStart is null
            ? null
            : starts
                .Where(record => record.TimeUtc <= incident &&
                                 (record.TimeUtc - latestPriorStart.TimeUtc).Duration() <= CorroborationWindow)
                .MinBy(record => record.TimeUtc);
        BootSessionRecord? nextStart = starts.FirstOrDefault(record => record.TimeUtc > incident);
        BootSessionRecord? cleanEnd = records.FirstOrDefault(record =>
            record.BoundaryKind == BootSessionBoundaryKind.CleanEndMarker &&
            record.TimeUtc > incident &&
            (nextStart is null || record.TimeUtc <= nextStart.TimeUtc));

        DateTimeOffset? startUtc = priorStart?.TimeUtc;
        string startEvidence = priorStart is null
            ? "No boot-start marker was available before the incident in the bounded history window."
            : DescribeBoundary(priorStart, starts);

        DateTimeOffset? endUtc;
        string endEvidence;
        if (cleanEnd is not null)
        {
            endUtc = cleanEnd.TimeUtc;
            endEvidence = $"A clean shutdown marker was {DescribeRecord(cleanEnd)}.";
        }
        else if (nextStart is not null)
        {
            endUtc = nextStart.TimeUtc;
            endEvidence = $"The next boot-start marker was {DescribeRecord(nextStart)}. It is an upper bound for the earlier session, not the crash time.";
        }
        else if (currentBootUtc is { } currentBoot && currentBoot.ToUniversalTime() > incident)
        {
            endUtc = currentBoot.ToUniversalTime();
            endEvidence = "The current Windows boot time is after the incident and provides an upper bound for the earlier session.";
        }
        else
        {
            endUtc = null;
            endEvidence = "No later boot-start or clean-shutdown marker was available in the bounded history window.";
        }

        bool? occurredInSession = startUtc is null
            ? null
            : incident >= startUtc && (endUtc is null || incident < endUtc);
        int corroboratingStarts = priorStart is null
            ? 0
            : starts.Count(record => (record.TimeUtc - priorStart.TimeUtc).Duration() <= CorroborationWindow);
        BootSessionReconstructionConfidence confidence = startUtc is not null &&
                                                          (endUtc is not null || corroboratingStarts >= 2)
            ? BootSessionReconstructionConfidence.Corroborated
            : startUtc is not null || endUtc is not null || records.Length > 0
                ? BootSessionReconstructionConfidence.Partial
                : BootSessionReconstructionConfidence.Unavailable;

        return new BootSessionContext(
            incident,
            startUtc,
            endUtc,
            occurredInSession,
            startEvidence,
            endEvidence,
            confidence,
            records,
            "Boot markers bound a Windows session; they do not identify why the session ended or what caused the incident.");
    }

    public static bool IsBootMarker(DiagnosticEvent diagnosticEvent) =>
        TryCreateRecord(diagnosticEvent) is not null;

    private static BootSessionRecord? TryCreateRecord(DiagnosticEvent diagnosticEvent)
    {
        BootSessionBoundaryKind? boundary = diagnosticEvent.ProviderName switch
        {
            string provider when provider.Equals("Microsoft-Windows-Kernel-General", StringComparison.OrdinalIgnoreCase) &&
                                 diagnosticEvent.EventId == 12 => BootSessionBoundaryKind.StartMarker,
            string provider when provider.Equals("Microsoft-Windows-Kernel-General", StringComparison.OrdinalIgnoreCase) &&
                                 diagnosticEvent.EventId == 13 => BootSessionBoundaryKind.CleanEndMarker,
            string provider when provider.Equals("EventLog", StringComparison.OrdinalIgnoreCase) &&
                                 diagnosticEvent.EventId == 6005 => BootSessionBoundaryKind.StartMarker,
            string provider when provider.Equals("EventLog", StringComparison.OrdinalIgnoreCase) &&
                                 diagnosticEvent.EventId == 6006 => BootSessionBoundaryKind.CleanEndMarker,
            string provider when provider.Equals("EventLog", StringComparison.OrdinalIgnoreCase) &&
                                 diagnosticEvent.EventId == 6008 => BootSessionBoundaryKind.UnexpectedEndMarker,
            string provider when provider.Equals("Microsoft-Windows-Kernel-Power", StringComparison.OrdinalIgnoreCase) &&
                                 diagnosticEvent.EventId == 41 => BootSessionBoundaryKind.UnexpectedEndMarker,
            _ => null
        };

        return boundary is null
            ? null
            : new BootSessionRecord(
                diagnosticEvent.TimeUtc.ToUniversalTime(),
                diagnosticEvent.ProviderName,
                diagnosticEvent.EventId,
                boundary.Value);
    }

    private static string DescribeBoundary(BootSessionRecord boundary, IReadOnlyList<BootSessionRecord> starts)
    {
        string[] sources = starts
            .Where(record => (record.TimeUtc - boundary.TimeUtc).Duration() <= CorroborationWindow)
            .Select(record => $"{record.ProviderName} event {record.EventId}")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return $"Boot start reconstructed at {boundary.TimeUtc:O} from {string.Join(" and ", sources)}.";
    }

    private static string DescribeRecord(BootSessionRecord record) =>
        $"{record.ProviderName} event {record.EventId} at {record.TimeUtc:O}";
}
