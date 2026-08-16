using System.Globalization;
using System.Text;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Reporting;

public sealed class SummaryBuilderV3
{
    public string Build(
        string toolVersion,
        string sessionId,
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        string completionReason,
        IncidentSelection? incidentSelection,
        TargetProfile? targetProfile,
        IReadOnlyList<DiagnosticFinding> findings,
        IReadOnlyList<SourceCoverage> coverage,
        CrashCorrelation? correlation,
        DebuggerAnalysis? debuggerAnalysis,
        CrashReadiness? crashReadiness = null,
        DumpQuality? dumpQuality = null,
        RecentChangeTimeline? recentChanges = null,
        StorageHealthSnapshot? storageHealth = null,
        DriverVerifierState? driverVerifier = null,
        BootSessionContext? bootSession = null)
    {
        var text = new StringBuilder();
        text.AppendLine("PC Crash Diagnostic");
        text.AppendLine($"Version: {toolVersion}");
        text.AppendLine($"Session: {sessionId}");
        text.AppendLine($"Evidence window (UTC): {startUtc:O} to {endUtc:O}");
        text.AppendLine($"Completion: {completionReason}");
        if (incidentSelection is not null)
        {
            text.AppendLine($"Selected incident: {incidentSelection.Candidate.Title} at {incidentSelection.Candidate.TimeUtc:O}");
            if (incidentSelection.Candidate.EvidenceOrigin != IncidentEvidenceOrigin.Unknown)
            {
                text.AppendLine($"Selected evidence source: {incidentSelection.Candidate.EvidenceOrigin}");
            }
        }

        if (targetProfile is not null)
        {
            text.AppendLine($"Selected target: {targetProfile.DisplayName}");
        }

        text.AppendLine();
        text.AppendLine("Source coverage");
        foreach (SourceCoverage source in coverage.OrderBy(item => item.Source, StringComparer.OrdinalIgnoreCase))
        {
            text.AppendLine($"- {source.Source}: {source.State}; {source.RecordCount.ToString(CultureInfo.InvariantCulture)} records. {source.Detail}");
        }

        if (crashReadiness is not null)
        {
            text.AppendLine();
            text.AppendLine("Crash capture readiness");
            text.AppendLine($"- State: {ReadinessLabel(crashReadiness.Assessment)}");
            text.AppendLine($"- Dump type: {DumpModeLabel(crashReadiness.DumpMode)}");
            text.AppendLine($"- Assessment: {crashReadiness.AssessmentDetail}");
            if (crashReadiness.RecommendedDestinationFreeBytes is { } recommended)
            {
                text.AppendLine($"- Recommended free space: {FormatBytes(recommended)}");
            }
        }

        if (bootSession is not null)
        {
            text.AppendLine();
            text.AppendLine("Boot session reconstruction");
            text.AppendLine($"- Confidence: {bootSession.Confidence}");
            text.AppendLine($"- Start: {(bootSession.StartUtc is { } start ? start.ToString("O", CultureInfo.InvariantCulture) : "not established")}");
            text.AppendLine($"- End boundary: {(bootSession.EndUtc is { } end ? end.ToString("O", CultureInfo.InvariantCulture) : "not established")}");
            text.AppendLine($"- Incident within reconstructed session: {FormatBoolean(bootSession.IncidentOccurredInSession)}");
            text.AppendLine($"- Limitation: {bootSession.Limitation}");
        }

        text.AppendLine();
        text.AppendLine("Results");
        if (findings.Count == 0)
        {
            text.AppendLine("No cause was identified in the Windows records this app could read.");
            text.AppendLine("Next check: Review source coverage and collect another report close to the next problem.");
        }
        else
        {
            foreach (DiagnosticFinding finding in findings.OrderBy(item => item.Rank))
            {
                text.AppendLine();
                text.AppendLine($"Observed: {finding.Title}");
                text.AppendLine($"Evidence strength: {finding.Confidence}");
                text.AppendLine($"Evidence: {finding.Evidence}");
                text.AppendLine($"Possible relevance: {finding.Meaning}");
                text.AppendLine($"Does not establish: {finding.DoesNotProve}");
                text.AppendLine($"Next check: {finding.NextCheck}");
            }
        }

        if (correlation is not null)
        {
            text.AppendLine();
            text.AppendLine($"Dump correlation: {correlation.Basis}");
            text.AppendLine(correlation.Limitation);
        }

        if (dumpQuality is not null)
        {
            text.AppendLine();
            text.AppendLine($"Dump quality: {dumpQuality.Classification}");
            text.AppendLine(dumpQuality.Detail);
        }

        if (recentChanges is not null)
        {
            int withinDay = recentChanges.Records.Count(item => item.Within24Hours);
            int withinWeek = recentChanges.Records.Count(item => item.WithinSevenDays);
            text.AppendLine();
            text.AppendLine($"Recent-change timing: {withinDay} within 24 hours; {withinWeek} within seven days.");
            text.AppendLine("A nearby update or driver installation is timing context, not proof of causation.");
        }

        if (storageHealth is not null)
        {
            int warnings = storageHealth.Devices.Count(IsStorageWarning);
            text.AppendLine();
            text.AppendLine($"Storage health: {storageHealth.Devices.Count} device record{(storageHealth.Devices.Count == 1 ? string.Empty : "s")}; {warnings} warning record{(warnings == 1 ? string.Empty : "s")}.");
            text.AppendLine("A storage health state or counter does not establish that a drive caused the incident.");
        }

        if (driverVerifier is not null)
        {
            text.AppendLine();
            text.AppendLine($"Driver Verifier: {driverVerifier.Status}");
            text.AppendLine(driverVerifier.Detail);
        }

        if (debuggerAnalysis is not null)
        {
            text.AppendLine();
            text.AppendLine($"WinDbg reported: {debuggerAnalysis.State}");
            if (!string.IsNullOrWhiteSpace(debuggerAnalysis.BugcheckCode))
            {
                text.AppendLine(string.IsNullOrWhiteSpace(debuggerAnalysis.BugcheckName)
                    ? $"Stop code: {debuggerAnalysis.BugcheckCode}"
                    : $"Stop code: {debuggerAnalysis.BugcheckCode} ({debuggerAnalysis.BugcheckName})");
            }

            if (!string.IsNullOrWhiteSpace(debuggerAnalysis.FailureBucket))
            {
                text.AppendLine($"Failure bucket: {debuggerAnalysis.FailureBucket}");
            }

            if (!string.IsNullOrWhiteSpace(debuggerAnalysis.ModuleName))
            {
                text.AppendLine($"Named module: {debuggerAnalysis.ModuleName}");
            }

            if (debuggerAnalysis.Blackbox is { } blackbox)
            {
                text.AppendLine($"Black-box sources available: {(blackbox.AvailableSources.Count == 0 ? "none reported" : string.Join(", ", blackbox.AvailableSources))}");
                if (blackbox.BootStatus is { } boot)
                {
                    text.AppendLine($"Cached boot status: last boot succeeded={FormatBoolean(boot.LastBootSucceeded)}; last boot shutdown={FormatBoolean(boot.LastBootShutdown)}.");
                }

                if (blackbox.ServiceControlRequests.Count > 0)
                {
                    text.AppendLine($"Outstanding service-control requests reported: {blackbox.ServiceControlRequests.Count}.");
                }
            }

            text.AppendLine("A WinDbg named module is not a confirmed faulty driver.");
        }

        text.AppendLine();
        text.AppendLine("This report records correlation and bounded evidence. One event or named module does not prove a root cause.");
        return text.ToString();
    }

    private static string ReadinessLabel(CrashReadinessState state) => state switch
    {
        CrashReadinessState.AtRisk => "At risk",
        CrashReadinessState.PendingRestart => "Pending restart",
        _ => state.ToString()
    };

    private static string DumpModeLabel(CrashDumpMode mode) => mode switch
    {
        CrashDumpMode.AutomaticMemory => "Automatic memory dump",
        CrashDumpMode.ActiveMemory => "Active memory dump",
        CrashDumpMode.CompleteMemory => "Complete memory dump",
        CrashDumpMode.KernelMemory => "Kernel memory dump",
        CrashDumpMode.SmallMemory => "Small memory dump",
        CrashDumpMode.None => "Off",
        _ => "Unavailable"
    };

    private static string FormatBytes(long bytes) => bytes switch
    {
        >= 1024L * 1024 * 1024 => $"{bytes / 1024d / 1024d / 1024d:0.#} GiB",
        >= 1024L * 1024 => $"{bytes / 1024d / 1024d:0.#} MiB",
        _ => $"{bytes.ToString(CultureInfo.InvariantCulture)} bytes"
    };

    private static string FormatBoolean(bool? value) => value switch
    {
        true => "yes",
        false => "no",
        null => "not reported"
    };

    private static bool IsStorageWarning(StorageHealthRecord record) =>
        (!record.HealthStatus.Equals("Healthy", StringComparison.OrdinalIgnoreCase) &&
         !record.HealthStatus.Equals("Unavailable", StringComparison.OrdinalIgnoreCase) &&
         !record.HealthStatus.Equals("Unknown", StringComparison.OrdinalIgnoreCase)) ||
        record.OperationalStatus.Any(status =>
            status.Contains("error", StringComparison.OrdinalIgnoreCase) ||
            status.Contains("failure", StringComparison.OrdinalIgnoreCase) ||
            status.Equals("Degraded", StringComparison.OrdinalIgnoreCase) ||
            status.Equals("Stressed", StringComparison.OrdinalIgnoreCase)) ||
        record.ReadErrorsUncorrected is > 0 ||
        record.WriteErrorsUncorrected is > 0;
}
