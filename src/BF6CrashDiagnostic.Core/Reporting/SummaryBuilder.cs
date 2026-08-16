using System.Globalization;
using System.Text;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Reporting;

public sealed class SummaryBuilder
{
    public string Build(
        string sessionId,
        DiagnosticMode mode,
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        string completionReason,
        CrashAnchor? anchor,
        IReadOnlyList<PerformanceSample> samples,
        IReadOnlyList<CrashArtifact> artifacts,
        IReadOnlyList<DiagnosticFinding> findings,
        IReadOnlyList<CollectionStatus> collectionStatus)
    {
        var text = new StringBuilder();
        text.AppendLine("Unofficial BF6 Crash Diagnostic");
        text.AppendLine("Version: 2.0.0-beta.1");
        text.AppendLine("Report schema: 2");
        text.AppendLine($"Session: {sessionId}");
        text.AppendLine($"Mode: {FormatMode(mode)}");
        text.AppendLine($"Start (UTC): {startUtc:O}");
        text.AppendLine($"End (UTC): {endUtc:O}");
        text.AppendLine($"Completion: {FormatCompletionReason(completionReason)}");
        text.AppendLine(anchor switch
        {
            null => "Crash record: none found",
            { Source: "Manual crash time" } => $"Crash time: {anchor.TimeUtc:O} · supplied by the user",
            _ => $"Crash record: {anchor.TimeUtc:O} · {anchor.Source} event {anchor.EventId} · {anchor.Description}"
        });

        text.AppendLine();
        text.AppendLine("Session data");
        AppendMetrics(text, mode, samples, artifacts);

        text.AppendLine();
        text.AppendLine("Ranked findings");
        if (findings.Count == 0)
        {
            text.AppendLine("No clear cause was found in the collected Windows records.");
        }
        for (int index = 0; index < findings.Count; index++)
        {
            DiagnosticFinding finding = findings[index];
            text.AppendLine($"{index + 1}. {finding.Title} [{finding.Confidence} confidence]");
            if (finding.FirstSeenUtc is not null && finding.LastSeenUtc is not null)
            {
                string occurrenceLabel = finding.OccurrenceCount == 1 ? "1 occurrence" : $"{finding.OccurrenceCount} occurrences";
                text.AppendLine($"   Observed: {occurrenceLabel} · {finding.FirstSeenUtc:O} through {finding.LastSeenUtc:O}");
            }
            text.AppendLine($"   Evidence: {finding.Evidence}");
            text.AppendLine($"   Meaning: {finding.Meaning}");
            text.AppendLine($"   Limits: {finding.DoesNotProve}");
            text.AppendLine($"   Next check: {finding.NextCheck}");
        }

        CollectionStatus[] failures = collectionStatus.Where(item => item.State != CollectionState.Available).ToArray();
        if (failures.Length > 0)
        {
            text.AppendLine();
            text.AppendLine("Collection limits");
            foreach (CollectionStatus failure in failures)
            {
                text.AppendLine($"- {failure.Source}: {failure.State} · {failure.Detail}");
            }
        }

        text.AppendLine();
        text.AppendLine("Notes");
        text.AppendLine("- Events close in time may be related, but timing alone does not identify the cause.");
        text.AppendLine("- Kernel-Power 41 and EventLog 6008 record an improper shutdown, not why it happened.");
        text.AppendLine("- One rising memory graph is not enough to call a memory leak.");
        text.AppendLine("- 0xC0000001 is STATUS_UNSUCCESSFUL, a generic failure. It is not a memory-leak code.");
        text.AppendLine("- Standard reports exclude crash dump data, arbitrary log-file contents, and raw Event Log XML. Selected event messages remain; review every file before sharing the ZIP.");
        return text.ToString().TrimEnd() + Environment.NewLine;
    }

    private static void AppendMetrics(
        StringBuilder text,
        DiagnosticMode mode,
        IReadOnlyList<PerformanceSample> samples,
        IReadOnlyList<CrashArtifact> artifacts)
    {
        PerformanceSample[] running = samples.Where(sample => sample.BF6Running).OrderBy(sample => sample.TimestampUtc).ToArray();
        if (samples.Count == 0)
        {
            text.AppendLine(mode switch
            {
                DiagnosticMode.Retrospective => "- Performance sampling: not used for past-crash analysis.",
                DiagnosticMode.Recovered => "- No live samples were recovered.",
                _ => "- No live performance samples were collected."
            });
        }
        else
        {
            double peakMemory = samples.Max(sample => sample.SystemMemoryUsedGB);
            double peakCommit = samples.Max(sample => sample.SystemCommitPct);
            text.AppendLine(string.Create(CultureInfo.InvariantCulture, $"- Peak system memory used: {peakMemory:F2} GB"));
            text.AppendLine(string.Create(CultureInfo.InvariantCulture, $"- Peak system commit: {peakCommit:F1}%"));
        }

        if (running.Length > 0)
        {
            double? first = running.First().BF6PrivateMB;
            double? last = running.Last().BF6PrivateMB;
            double? peak = running.Where(sample => sample.BF6PrivateMB is not null).Select(sample => sample.BF6PrivateMB).Max();
            if (first is not null && last is not null && peak is not null)
            {
                text.AppendLine(string.Create(CultureInfo.InvariantCulture,
                    $"- BF6 private memory: {first:F0} MB first → {last:F0} MB last; peak {peak:F0} MB"));
            }
        }

        text.AppendLine(artifacts.Count switch
        {
            0 => "- No dump or Windows Error Reporting artifact metadata is included in this report.",
            1 => "- 1 relevant dump or Windows Error Reporting artifact record was found; contents were excluded.",
            _ => $"- {artifacts.Count} relevant dump or Windows Error Reporting artifact records were found; contents were excluded."
        });
    }

    private static string FormatMode(DiagnosticMode mode) => mode switch
    {
        DiagnosticMode.Retrospective => "Past crash",
        DiagnosticMode.Monitor => "Live monitor",
        DiagnosticMode.Recovered => "Recovered monitor",
        _ => mode.ToString()
    };

    private static string FormatCompletionReason(string reason) => reason switch
    {
        "RetrospectiveAnalysisCompleted" => "Past-crash analysis completed",
        "BF6Exited" => "BF6 exited",
        "RecoveredAfterToolInterruption" => "Recovered after the app closed unexpectedly",
        "RecoveredAfterSystemRestart" => "Recovered after Windows restarted",
        _ => reason
    };
}
