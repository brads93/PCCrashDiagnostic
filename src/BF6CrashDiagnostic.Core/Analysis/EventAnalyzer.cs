using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Analysis;

public sealed class EventAnalyzer
{
    private static readonly Regex WhitespaceRegex = new(@"\s+", RegexOptions.Compiled, TimeSpan.FromSeconds(1));
    private static readonly Regex TraitsRegex = new(
        @"(?i)(?:Error\s+setting|Failed\s+to\s+set)\s+traits\s+on\s+Provider\s*\{?(?<guid>[0-9a-f-]{36})\}?\.?\s*Error:\s*(?<code>0x[0-9a-f]{8})",
        RegexOptions.Compiled,
        TimeSpan.FromSeconds(1));

    public CrashAnchor? SelectCrashAnchor(IEnumerable<DiagnosticEvent> events)
    {
        return events
            .Select(TryCreateAnchor)
            .Where(anchor => anchor is not null)
            .Cast<CrashAnchor>()
            .OrderByDescending(anchor => anchor.Priority)
            .ThenByDescending(anchor => anchor.TimeUtc)
            .FirstOrDefault();
    }

    public IReadOnlyList<DuplicateEventGroup> GroupDuplicates(IEnumerable<DiagnosticEvent> events)
    {
        return events
            .GroupBy(CreateDuplicateKey, StringComparer.Ordinal)
            .Select(group =>
            {
                DiagnosticEvent first = group.OrderBy(item => item.TimeUtc).First();
                DateTimeOffset[] occurrences = group.Select(item => item.TimeUtc).OrderBy(item => item).ToArray();
                return new DuplicateEventGroup(
                    group.Key,
                    first.ProviderName,
                    first.ProviderGuid,
                    first.EventId,
                    first.Message,
                    occurrences.Length,
                    occurrences[0],
                    occurrences[^1],
                    occurrences);
            })
            .OrderByDescending(group => group.Count)
            .ThenByDescending(group => group.LastSeenUtc)
            .ToArray();
    }

    public IReadOnlyList<DiagnosticFinding> Analyze(
        CrashAnchor? anchor,
        IReadOnlyList<DiagnosticEvent> events,
        IReadOnlyList<DuplicateEventGroup> groups,
        IReadOnlyList<ReliabilityRecord> reliability,
        IReadOnlyList<CrashArtifact> artifacts,
        IReadOnlyList<PerformanceSample> samples,
        TargetProfile? targetProfile = null,
        IncidentCandidate? selectedIncident = null)
    {
        var findings = new List<DiagnosticFinding>();
        string combinedReliability = string.Join('\n', reliability.Select(item => $"{item.SourceName} {item.ProductName} {item.Message}"));

        CrashAnchor? bugcheckAnchor = anchor is not null && IsRecordedBugcheckAnchor(anchor)
            ? anchor
            : SelectCrashAnchor(events);
        if (bugcheckAnchor is not null && IsRecordedBugcheckAnchor(bugcheckAnchor))
        {
            string dumpEvidence = string.IsNullOrWhiteSpace(bugcheckAnchor.DumpPath) ? "No dump path was recorded in the bugcheck event." : $"Windows named dump metadata for {Path.GetFileName(bugcheckAnchor.DumpPath)}.";
            string formattedBugcheck = BugcheckCatalog.Format(bugcheckAnchor.BugCheckCode);
            findings.Add(new DiagnosticFinding(
                "bugcheck",
                10,
                FindingSeverity.Critical,
                FindingConfidence.High,
                "Blue screen",
                "Windows bugcheck recorded",
                "Windows recorded a bugcheck" + (string.IsNullOrWhiteSpace(formattedBugcheck) ? "." : $" ({formattedBugcheck}).") + " " + dumpEvidence,
                "Windows recorded a kernel bugcheck.",
                "This event does not identify the faulty driver or component.",
                "Open the matching minidump in WinDbg and check the stop code and stack."));
        }
        else if (selectedIncident is
                 {
                     Kind: IncidentKind.Bugcheck,
                     EvidenceOrigin: IncidentEvidenceOrigin.ReliabilityMonitor
                 } &&
                 FindReliabilityBlueScreen(reliability, selectedIncident) is { } reliabilityBlueScreen)
        {
            findings.Add(new DiagnosticFinding(
                "reliability-blue-screen",
                15,
                FindingSeverity.Warning,
                FindingConfidence.Medium,
                "Reliability Monitor",
                "Blue-screen entry in Reliability Monitor",
                $"Reliability Monitor recorded a BlueScreen entry at {reliabilityBlueScreen.TimeUtc:O}. The collected System events did not include a matching bugcheck record with a non-zero stop code.",
                "This supports that Windows recorded a system crash near the selected time.",
                "This entry does not provide a verified stop code, parameters, matching dump, or root cause.",
                "Check System-event coverage and inspect a dump whose time matches this incident."));
        }

        DuplicateEventGroup? whea = groups
            .Where(IsWheaGroup)
            .OrderByDescending(group => IsFatalWheaGroup(group))
            .ThenByDescending(group => group.LastSeenUtc)
            .FirstOrDefault();
        if (whea is not null)
        {
            bool fatal = IsFatalWheaGroup(whea);
            bool corrected = IsCorrectedWheaGroup(whea);
            findings.Add(FromGroup(
                whea,
                "whea",
                20,
                fatal ? FindingSeverity.Critical : FindingSeverity.Warning,
                fatal ? FindingConfidence.High : FindingConfidence.Medium,
                fatal ? "Fatal hardware error" : corrected ? "Corrected hardware error" : "Hardware error",
                fatal
                    ? "Windows reported a fatal hardware or firmware error."
                    : corrected
                        ? "Windows reported and corrected a hardware error."
                        : "Windows reported a hardware or firmware error.",
                fatal
                    ? "The hardware-error category does not establish that a component is defective."
                    : "A corrected record is not a fatal hardware failure and does not establish that a component is defective.",
                "Compare the CPER category and event time with another incident or a matching dump."));
        }

        DuplicateEventGroup? dumpFailure = groups.FirstOrDefault(group =>
            group.ProviderName.Contains("volmgr", StringComparison.OrdinalIgnoreCase) && group.EventId is 46 or 161);
        if (dumpFailure is not null)
        {
            findings.Add(FromGroup(
                dumpFailure, "dump-write-failure", 25, FindingSeverity.Warning, FindingConfidence.High, "Crash dump not written",
                "Windows could not create the crash dump.",
                "This explains why a dump is missing, not why the crash happened.",
                "Check free space on the system drive and the Windows crash-dump settings before another test."));
        }

        DuplicateEventGroup? gpu = groups.FirstOrDefault(IsGpuRecoveryGroup);
        bool reliabilityGpu = Regex.IsMatch(combinedReliability, @"(?i)LiveKernelEvent\s*(117|141)|VIDEO_(?:ENGINE|TDR)_TIMEOUT|display driver");
        if (gpu is not null || reliabilityGpu)
        {
            findings.Add(gpu is not null
                ? FromGroup(gpu, "gpu-timeout", 30, FindingSeverity.Warning, FindingConfidence.High, "GPU timeout or driver reset",
                    "Windows reset the display driver or recorded a GPU timeout.",
                    "This does not prove that the GPU or current driver is faulty.",
                    "Compare the event time with the bugcheck or dump and note whether the same reset pattern recurs.")
                : new DiagnosticFinding("gpu-timeout", 30, FindingSeverity.Warning, FindingConfidence.Medium, "Graphics", "GPU timeout or driver reset",
                    "Windows Reliability records include LiveKernelEvent 117/141 or display-timeout evidence.",
                    "Windows recorded a GPU timeout or display-driver problem.",
                    "This does not prove that the GPU or current driver is faulty.",
                    "Compare the Reliability timestamp with the dump and Windows events."));
        }

        DuplicateEventGroup? exhaustion = groups.FirstOrDefault(group =>
            group.ProviderName.Contains("Resource-Exhaustion", StringComparison.OrdinalIgnoreCase) ||
            group.EventId == 2004 ||
            group.Message.Contains("resource exhaustion", StringComparison.OrdinalIgnoreCase));
        if (exhaustion is not null)
        {
            findings.Add(FromGroup(
                exhaustion, "resource-exhaustion", 35, FindingSeverity.Warning, FindingConfidence.High, "Low memory or resource warning",
                "Windows was low on commit or another resource near the crash.",
                "This does not identify which process used the resource or prove a memory leak.",
                "Compare target private memory with system commit across another similar session."));
        }
        else if (HasRisingMemoryTrend(samples, out string trendEvidence))
        {
            findings.Add(new DiagnosticFinding(
                "rising-memory-trend", 45, FindingSeverity.Warning, FindingConfidence.Low, "Memory trend", "Memory increased during the session",
                trendEvidence,
                "Target private memory and system commit increased during this session.",
                "One session is not enough to call this a memory leak.",
                "Repeat a similar multi-match session and check whether the same growth returns with a Windows resource warning."));
        }

        DuplicateEventGroup? storage = groups.FirstOrDefault(group =>
            StorageEventCatalog.TryClassify(group.ProviderName, group.EventId, out _));
        if (storage is not null &&
            StorageEventCatalog.TryClassify(storage.ProviderName, storage.EventId, out StorageEventCategory storageCategory))
        {
            findings.Add(FromGroup(
                storage,
                "storage-evidence",
                40,
                FindingSeverity.Warning,
                FindingConfidence.High,
                storageCategory == StorageEventCategory.TimeoutOrReset
                    ? "Storage timeout or controller reset"
                    : "Storage I/O error",
                storageCategory == StorageEventCategory.TimeoutOrReset
                    ? "Windows recorded a storage timeout or controller reset near the incident."
                    : "Windows recorded a storage I/O error near the incident.",
                "This event does not identify the failing layer or establish that a drive caused the incident.",
                "Compare its timestamp with the selected incident and check whether the same provider and event recur."));
        }

        HashSet<string> applicationFailureKeys = events
            .Where(item => IsApplicationFailureEvent(item, targetProfile))
            .Select(CreateDuplicateKey)
            .ToHashSet(StringComparer.Ordinal);
        DuplicateEventGroup? applicationFailure = groups.FirstOrDefault(group =>
            applicationFailureKeys.Contains(group.Key));
        if (applicationFailure is not null)
        {
            DiagnosticFinding applicationFinding = FromGroup(
                applicationFailure, "application-failure", 50, FindingSeverity.Warning, FindingConfidence.Medium, "Application failure",
                "Windows recorded a crash or hang matching the selected target or related application evidence.",
                "An application crash and a Windows bugcheck can be separate failures.",
                "Check the faulting module and exception code, then compare its time with any bugcheck event.");
            findings.Add(targetProfile is null
                ? applicationFinding
                : applicationFinding with
                {
                    Evidence = applicationFinding.Evidence + $" Matched target profile: {targetProfile.DisplayName}."
                });
        }

        foreach (DuplicateEventGroup traits in groups.Where(IsProviderTraitsGroup))
        {
            Match match = TraitsRegex.Match(traits.Message);
            string code = match.Success ? match.Groups["code"].Value : "the recorded status";
            findings.Add(FromGroup(
                traits, "etw-provider-traits-" + traits.Key[..Math.Min(10, traits.Key.Length)], 80,
                FindingSeverity.Context, FindingConfidence.Low, "Event Tracing setup error",
                $"Windows Kernel Event Tracing could not set provider traits; {StatusCodeInterpreter.Explain(code)}",
                "This is a logging error, not evidence of a memory leak, faulty RAM, or the cause of the blue screen.",
                "Use the provider GUID for comparison, but check bugcheck, dump, WHEA, GPU, and low-resource records first."));
        }

        DuplicateEventGroup? unclean = groups.FirstOrDefault(group =>
            (group.ProviderName.Contains("Kernel-Power", StringComparison.OrdinalIgnoreCase) && group.EventId == 41) ||
            (group.ProviderName.Equals("EventLog", StringComparison.OrdinalIgnoreCase) && group.EventId == 6008));
        if (unclean is not null && findings.All(item => item.Id != "bugcheck"))
        {
            findings.Add(FromGroup(
                unclean, "unclean-shutdown", 90, FindingSeverity.Context, FindingConfidence.High, "Unexpected shutdown",
                "Windows recorded that the previous shutdown was not clean.",
                "Events 41 and 6008 usually record the result, not the cause.",
                "Check for a BugCheck 1001 event or matching dump."));
        }

        return findings
            .OrderBy(item => item.Rank)
            .ThenBy(item => item.Title, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static bool IsProviderTraitsMessage(string? message) =>
        !string.IsNullOrWhiteSpace(message) && TraitsRegex.IsMatch(message);

    private static CrashAnchor? TryCreateAnchor(DiagnosticEvent diagnosticEvent)
    {
        string provider = diagnosticEvent.ProviderName;
        if (BugcheckRecordDecoder.TryDecode(diagnosticEvent, out BugcheckRecord decoded))
        {
            return new CrashAnchor(
                diagnosticEvent.TimeUtc,
                provider,
                diagnosticEvent.EventId,
                decoded.EvidenceSource == BugcheckEvidenceSource.WindowsErrorReporting
                    ? "Windows bugcheck/system-error report"
                    : "Unexpected restart with non-zero bugcheck data",
                decoded.NormalizedCode == "Unknown" ? null : decoded.NormalizedCode,
                decoded.OriginalDumpPath,
                decoded.EvidenceSource == BugcheckEvidenceSource.WindowsErrorReporting ? 500 : 450);
        }

        if (diagnosticEvent.EventId == 1001 &&
            (provider.Contains("SystemErrorReporting", StringComparison.OrdinalIgnoreCase) ||
             provider.Contains("BugCheck", StringComparison.OrdinalIgnoreCase) ||
             diagnosticEvent.Message.Contains("bugcheck", StringComparison.OrdinalIgnoreCase)))
        {
            string? bugCheck = FirstNonEmpty(diagnosticEvent.Data, "BugcheckCode", "BugCheckCode", "param1");
            string? dump = FirstNonEmpty(diagnosticEvent.Data, "DumpFile", "DumpPath", "param6");
            return new CrashAnchor(diagnosticEvent.TimeUtc, provider, diagnosticEvent.EventId,
                "Windows bugcheck/system-error report", bugCheck, dump, 500);
        }

        if (diagnosticEvent.EventId == 41 && provider.Contains("Kernel-Power", StringComparison.OrdinalIgnoreCase))
        {
            string? code = FirstNonEmpty(diagnosticEvent.Data, "BugcheckCode", "BugCheckCode");
            int priority = IsZeroLike(code) ? 200 : 450;
            return new CrashAnchor(diagnosticEvent.TimeUtc, provider, diagnosticEvent.EventId,
                priority == 450 ? "Unexpected restart with non-zero bugcheck data" : "Unexpected restart marker",
                code, null, priority);
        }

        if (diagnosticEvent.EventId == 6008 && provider.Equals("EventLog", StringComparison.OrdinalIgnoreCase))
        {
            return new CrashAnchor(diagnosticEvent.TimeUtc, provider, diagnosticEvent.EventId,
                "Previous shutdown was unexpected", null, null, 150);
        }

        return null;
    }

    private static bool IsZeroLike(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        string trimmed = value.Trim();
        return trimmed is "0" or "0x0" or "0x00000000";
    }

    private static bool IsRecordedBugcheckAnchor(CrashAnchor anchor) =>
        (anchor.EventId == 1001 &&
         (anchor.Source.Contains("SystemErrorReporting", StringComparison.OrdinalIgnoreCase) ||
          anchor.Source.Contains("BugCheck", StringComparison.OrdinalIgnoreCase) ||
          anchor.Description.Contains("bugcheck", StringComparison.OrdinalIgnoreCase))) ||
        (anchor.EventId == 41 &&
         anchor.Source.Contains("Kernel-Power", StringComparison.OrdinalIgnoreCase) &&
         !IsZeroLike(anchor.BugCheckCode));

    private static string? FirstNonEmpty(IReadOnlyDictionary<string, string> data, params string[] names)
    {
        foreach (string name in names)
        {
            KeyValuePair<string, string> match = data.FirstOrDefault(pair =>
                pair.Key.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrWhiteSpace(match.Value))
            {
                return match.Value;
            }
        }

        return null;
    }

    private static string CreateDuplicateKey(DiagnosticEvent diagnosticEvent)
    {
        string normalized = WhitespaceRegex.Replace(diagnosticEvent.Message.Trim(), " ").ToUpperInvariant();
        string identity = $"{diagnosticEvent.ProviderName.ToUpperInvariant()}|{diagnosticEvent.ProviderGuid}|{diagnosticEvent.EventId}|{normalized}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity))).ToLowerInvariant();
    }

    private static bool IsGpuRecoveryGroup(DuplicateEventGroup group)
    {
        string text = group.ProviderName + " " + group.Message;
        if ((group.ProviderName.Equals("Display", StringComparison.OrdinalIgnoreCase) && group.EventId == 4101) ||
            Regex.IsMatch(text, @"(?i)LiveKernelEvent\s*(117|141)|VIDEO_(?:ENGINE|TDR)_TIMEOUT"))
        {
            return true;
        }

        bool gpuProvider = group.ProviderName.Contains("Display", StringComparison.OrdinalIgnoreCase) ||
            group.ProviderName.Contains("DxgKrnl", StringComparison.OrdinalIgnoreCase) ||
            group.ProviderName.Contains("nvlddmkm", StringComparison.OrdinalIgnoreCase) ||
            group.ProviderName.Contains("amdkmdag", StringComparison.OrdinalIgnoreCase) ||
            group.ProviderName.Contains("amdwddmg", StringComparison.OrdinalIgnoreCase);
        return gpuProvider && Regex.IsMatch(
            group.Message,
            @"(?i)stopped responding|successfully recovered|\breset\b|\btimeout\b|\bTDR\b");
    }

    private static bool IsWheaGroup(DuplicateEventGroup group) =>
        WheaEventCatalog.IsProvider(group.ProviderName, group.ProviderGuid) &&
        WheaEventCatalog.IsKnown(group.EventId);

    private static bool IsFatalWheaGroup(DuplicateEventGroup group) =>
        WheaEventCatalog.Classify(group.EventId) == WheaEventClassification.Fatal;

    private static bool IsCorrectedWheaGroup(DuplicateEventGroup group) =>
        WheaEventCatalog.Classify(group.EventId) == WheaEventClassification.Corrected;

    private static bool IsApplicationFailureEvent(
        DiagnosticEvent item,
        TargetProfile? targetProfile)
    {
        if (item.EventId is not (1000 or 1001 or 1002))
        {
            return false;
        }

        string text = item.ProviderName + " " + item.Message + " " + string.Join(' ', item.Data.Values);
        if (DiagnosticSignalClassifier.IsDiagnosticToolSelfSignal(text))
        {
            return false;
        }

        return targetProfile?.MatchesApplicationEvidence(text) == true;
    }

    private static bool IsProviderTraitsGroup(DuplicateEventGroup group) =>
        KernelEventTracingCatalog.IsProvider(group.ProviderName) &&
        KernelEventTracingCatalog.IsProviderTraitsEvent(group.EventId) &&
        IsProviderTraitsMessage(group.Message);

    private static ReliabilityRecord? FindReliabilityBlueScreen(
        IReadOnlyList<ReliabilityRecord> reliability,
        IncidentCandidate selectedIncident) =>
        reliability
            .Where(item => IsReliabilityBlueScreen(item) &&
                           (item.TimeUtc - selectedIncident.TimeUtc).Duration() <= TimeSpan.FromMinutes(3))
            .OrderBy(item => (item.TimeUtc - selectedIncident.TimeUtc).Duration())
            .FirstOrDefault();

    private static bool IsReliabilityBlueScreen(ReliabilityRecord record) =>
        string.Join(' ', record.SourceName, record.ProductName, record.EventIdentifier, record.Message)
            .Contains("BlueScreen", StringComparison.OrdinalIgnoreCase);

    private static bool HasRisingMemoryTrend(IReadOnlyList<PerformanceSample> samples, out string evidence)
    {
        PerformanceSample[] running = samples.Where(sample => sample.BF6Running && sample.BF6PrivateMB is not null)
            .OrderBy(sample => sample.TimestampUtc)
            .ToArray();
        if (running.Length < 2 || running[^1].TimestampUtc - running[0].TimestampUtc < TimeSpan.FromMinutes(5))
        {
            evidence = string.Empty;
            return false;
        }

        double firstPrivate = running[0].BF6PrivateMB ?? 0;
        double lastPrivate = running[^1].BF6PrivateMB ?? 0;
        double privateIncrease = lastPrivate - firstPrivate;
        double commitIncrease = running[^1].SystemCommitPct - running[0].SystemCommitPct;
        bool materialPrivateGrowth = privateIncrease >= 2048 && (firstPrivate <= 0 || lastPrivate >= firstPrivate * 1.5);
        bool materialCommitGrowth = commitIncrease >= 10;
        evidence = string.Create(CultureInfo.InvariantCulture,
            $"Over {(running[^1].TimestampUtc - running[0].TimestampUtc).TotalMinutes:F1} minutes, target private memory changed from {firstPrivate:F0} MB to {lastPrivate:F0} MB and system commit changed from {running[0].SystemCommitPct:F1}% to {running[^1].SystemCommitPct:F1}%.");
        return materialPrivateGrowth && materialCommitGrowth;
    }

    private static DiagnosticFinding FromGroup(
        DuplicateEventGroup group,
        string id,
        int rank,
        FindingSeverity severity,
        FindingConfidence confidence,
        string title,
        string meaning,
        string doesNotProve,
        string nextCheck)
    {
        return new DiagnosticFinding(
            id,
            rank,
            severity,
            confidence,
            group.ProviderName,
            title,
            $"{group.ProviderName} event {group.EventId}: {group.Message}",
            meaning,
            doesNotProve,
            nextCheck,
            group.Count,
            group.FirstSeenUtc,
            group.LastSeenUtc);
    }

}
