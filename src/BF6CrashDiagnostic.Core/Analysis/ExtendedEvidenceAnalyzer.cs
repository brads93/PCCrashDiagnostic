using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Analysis;

/// <summary>
/// Converts the bounded v3.1 collectors into neutral findings. Healthy or
/// unavailable optional sources do not become reassuring negative findings.
/// </summary>
public sealed class ExtendedEvidenceAnalyzer
{
    public IReadOnlyList<DiagnosticFinding> Analyze(
        DumpQuality? dumpQuality,
        RecentChangeTimeline? recentChanges,
        StorageHealthSnapshot? storageHealth,
        DriverVerifierState? driverVerifier)
    {
        var findings = new List<DiagnosticFinding>();

        AddDumpQualityFinding(findings, dumpQuality);
        AddStorageFinding(findings, storageHealth);
        AddDriverVerifierFinding(findings, driverVerifier);
        AddRecentChangeFinding(findings, recentChanges);

        return findings
            .OrderBy(item => item.Rank)
            .ThenBy(item => item.Id, StringComparer.Ordinal)
            .ToArray();
    }

    private static void AddDumpQualityFinding(
        ICollection<DiagnosticFinding> findings,
        DumpQuality? quality)
    {
        if (quality is null || quality.Classification is
            DumpQualityClassification.Valid or DumpQualityClassification.Recognized)
        {
            return;
        }

        (FindingSeverity severity, FindingConfidence confidence, string title, string relevance, string nextCheck) =
            quality.Classification switch
            {
                DumpQualityClassification.Truncated => (
                    FindingSeverity.Warning,
                    FindingConfidence.High,
                    "Crash dump appears incomplete",
                    "The selected dump may not contain enough data for reliable debugger analysis.",
                    "Prepare crash capture before the next incident and check whether Windows records a dump-write failure."),
                DumpQualityClassification.Corrupt => (
                    FindingSeverity.Warning,
                    FindingConfidence.High,
                    "Crash dump could not be validated",
                    "The selected file is not usable as a normal Windows crash dump according to the bounded checks.",
                    "Collect another dump and review crash-capture readiness and dump-write events."),
                DumpQualityClassification.Inaccessible => (
                    FindingSeverity.Information,
                    FindingConfidence.Medium,
                    "Crash dump access was denied",
                    "A potentially relevant dump exists, but this collection could not validate it.",
                    "Select the dump and retry the protected evidence operation with UAC if you want it inspected locally."),
                _ => (
                    FindingSeverity.Context,
                    FindingConfidence.Low,
                    "Crash dump quality was not determined",
                    "The optional dump-quality check did not return a usable result.",
                    "Review source coverage or retry with an installed Microsoft DumpChk tool.")
            };

        findings.Add(new DiagnosticFinding(
            "dump-quality-" + quality.Classification.ToString().ToLowerInvariant(),
            24,
            severity,
            confidence,
            "Crash dump",
            title,
            quality.Detail,
            relevance,
            "Dump quality does not identify why Windows or the application crashed.",
            nextCheck));
    }

    private static void AddStorageFinding(
        ICollection<DiagnosticFinding> findings,
        StorageHealthSnapshot? storage)
    {
        if (storage is null)
        {
            return;
        }

        StorageHealthRecord[] concerning = storage.Devices
            .Where(IsConcerningStorageRecord)
            .ToArray();
        if (concerning.Length == 0)
        {
            return;
        }

        string[] observations = concerning
            .Take(4)
            .Select(item =>
                $"Disk {item.Ordinal} ({item.MediaType}, {item.BusType}) reported health {item.HealthStatus}" +
                (item.OperationalStatus.Count == 0
                    ? "."
                    : $" and status {string.Join(", ", item.OperationalStatus.Take(3))}."))
            .ToArray();
        findings.Add(new DiagnosticFinding(
            "storage-health-warning",
            28,
            FindingSeverity.Warning,
            FindingConfidence.Medium,
            "Storage",
            "Windows reported a storage health warning",
            string.Join(" ", observations),
            "A storage warning or error counter can be relevant when crashes coincide with I/O failures.",
            "This read-only health record does not prove that a drive caused the selected incident or that the drive is defective.",
            "Compare this record with storage and filesystem events near repeated incidents before choosing a hardware test.",
            concerning.Length));
    }

    private static bool IsConcerningStorageRecord(StorageHealthRecord record)
    {
        bool healthConcern = !record.HealthStatus.Equals("Healthy", StringComparison.OrdinalIgnoreCase) &&
                             !record.HealthStatus.Equals("Unavailable", StringComparison.OrdinalIgnoreCase) &&
                             !record.HealthStatus.Equals("Unknown", StringComparison.OrdinalIgnoreCase);
        bool statusConcern = record.OperationalStatus.Any(status =>
            status.Contains("error", StringComparison.OrdinalIgnoreCase) ||
            status.Contains("failure", StringComparison.OrdinalIgnoreCase) ||
            status.Equals("Degraded", StringComparison.OrdinalIgnoreCase) ||
            status.Equals("Stressed", StringComparison.OrdinalIgnoreCase));
        bool uncorrectedErrors = record.ReadErrorsUncorrected is > 0 || record.WriteErrorsUncorrected is > 0;
        return healthConcern || statusConcern || uncorrectedErrors;
    }

    private static void AddDriverVerifierFinding(
        ICollection<DiagnosticFinding> findings,
        DriverVerifierState? verifier)
    {
        if (verifier?.Status != DriverVerifierStatusKind.Enabled)
        {
            return;
        }

        string driverDetail = verifier.VerifiedDriverBasenames.Count == 0
            ? "Windows reported active Driver Verifier flags but did not return a bounded driver list."
            : $"Windows reported Driver Verifier for {verifier.VerifiedDriverBasenames.Count} driver" +
              (verifier.VerifiedDriverBasenames.Count == 1 ? "." : "s.");
        findings.Add(new DiagnosticFinding(
            "driver-verifier-enabled",
            32,
            FindingSeverity.Warning,
            FindingConfidence.High,
            "Driver Verifier",
            "Driver Verifier is configured",
            driverDetail,
            "Driver Verifier deliberately applies extra checks and can make a driver violation stop Windows.",
            "Its presence does not prove that it caused this incident or that a verified driver is faulty.",
            "Tell whoever analyzes the dump that Driver Verifier was active. This app will not enable, reset, or change it."));
    }

    private static void AddRecentChangeFinding(
        ICollection<DiagnosticFinding> findings,
        RecentChangeTimeline? timeline)
    {
        if (timeline is null)
        {
            return;
        }

        RecentSystemChange[] withinWeek = timeline.Records
            .Where(item => item.WithinSevenDays &&
                           item.TimeBeforeIncident.HasValue &&
                           item.TimeBeforeIncident.Value >= TimeSpan.Zero)
            .OrderBy(item => item.TimeBeforeIncident)
            .ToArray();
        if (withinWeek.Length == 0)
        {
            return;
        }

        int withinDay = withinWeek.Count(item => item.Within24Hours);
        int updates = withinWeek.Count(item => item.Kind == RecentChangeKind.WindowsUpdate);
        int drivers = withinWeek.Length - updates;
        string evidence = $"The local timeline contains {withinWeek.Length} change" +
                          (withinWeek.Length == 1 ? string.Empty : "s") +
                          $" before the incident: {updates} Windows update" +
                          (updates == 1 ? string.Empty : "s") +
                          $" and {drivers} driver installation" +
                          (drivers == 1 ? string.Empty : "s") +
                          $". {withinDay} occurred within 24 hours.";
        findings.Add(new DiagnosticFinding(
            "recent-system-changes",
            75,
            FindingSeverity.Context,
            FindingConfidence.Low,
            "Recent changes",
            "System changes occurred before the incident",
            evidence,
            "The timing may help compare when a recurring problem began.",
            "Timing alone does not show that an update or driver installation caused the crash.",
            "Compare the first failing incident with the change timeline and look for the same pattern across later reports.",
            withinWeek.Length,
            withinWeek.Min(item => item.TimeUtc),
            withinWeek.Max(item => item.TimeUtc)));
    }
}
