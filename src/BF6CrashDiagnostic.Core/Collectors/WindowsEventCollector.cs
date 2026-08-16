using System.Collections.ObjectModel;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Collectors;

/// <summary>
/// Reads a deliberately narrow set of Windows Event Log records. The collector does not
/// export EVTX files and only copies explicitly whitelisted XML fields into the report model.
/// </summary>
public sealed partial class WindowsEventCollector
{
    private const string SystemLog = "System";
    private const string ApplicationLog = "Application";
    private const string KernelEventTracingLog = "Microsoft-Windows-Kernel-EventTracing/Admin";
    private const int DefaultMaxEventsPerLog = 1_500;

    private static readonly TimeSpan DefaultAnchorLookback = TimeSpan.FromDays(14);
    private static readonly TimeSpan DefaultEvidenceBeforeAnchor = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan DefaultEvidenceAfterAnchor = TimeSpan.FromMinutes(15);

    // Provider and event-ID pairs are intentionally explicit. Do not replace these with a
    // provider-only query: several of these publishers also emit high-volume operational data.
    private static readonly (string Provider, int[] EventIds)[] StorageEvidenceSignals =
    [
        ("disk", [7, 11, 51, 153]),
        ("storahci", [129]),
        ("stornvme", [129]),
        ("Microsoft-Windows-StorPort", [129])
    ];

    private static readonly (string Provider, int[] EventIds)[] FileSystemEvidenceSignals =
    [
        ("Ntfs", [50, 55, 98, 140]),
        ("Microsoft-Windows-Ntfs", [50, 55, 98, 140]),
        ("ReFS", [134]),
        ("Microsoft-Windows-ReFS", [134])
    ];

    private static readonly (string Provider, int[] EventIds)[] DumpWriteEvidenceSignals =
    [
        ("volmgr", [46, 161])
    ];

    private static readonly (string Provider, int[] EventIds)[] MemoryDiagnosticEvidenceSignals =
    [
        ("Microsoft-Windows-MemoryDiagnostics-Results", [1101, 1102, 1103, 1104, 1201, 1202])
    ];

    private static readonly HashSet<string> AllowedDataNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "ProviderGuid",
        "ErrorCode",
        "FailureReason",
        "SessionName",
        "FileName",
        "LoggingMode",
        "BugcheckCode",
        "BugCheckCode",
        "BugcheckParameter1",
        "BugcheckParameter2",
        "BugcheckParameter3",
        "BugcheckParameter4",
        "DumpFile",
        "DumpPath",
        "SleepInProgress",
        "PowerButtonTimestamp",
        "BootAppStatus",
        "Checkpoint",
        "ConnectedStandbyInProgress",
        "SystemSleepTransitionsToOn",
        "AppName",
        "ApplicationName",
        "FaultingApplicationName",
        "FaultingApplicationPath",
        "FaultingModuleName",
        "ExceptionCode",
        "FaultingOffset",
        "EventName",
        "Response",
        "ProcessName",
        "ProcessId",
        "CommitCharge",
        "CommitLimit",
        "VirtualSize",
        "DeviceName",
        "DriverName",
        "ErrorSource",
        "ApicId",
        "MCABank",
        "MciStat",
        "MciAddr",
        "MciMisc",
        "ErrorType",
        "TransactionType",
        "Participation",
        "RequestType",
        "MemorIO",
        "MemoryHierarchyLvl",
        "Timeout",
        "OperationType",
        "Channel",
        "Length",
        "CompletionType"
    };

    private static readonly HashSet<string> AllowedNumberedDataNames = new(
        Enumerable.Range(1, 10)
            .SelectMany(index => new[] { $"param{index}", $"P{index}" }),
        StringComparer.OrdinalIgnoreCase);

    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _anchorLookback;
    private readonly TimeSpan _evidenceBeforeAnchor;
    private readonly TimeSpan _evidenceAfterAnchor;
    private readonly int _maxEventsPerLog;

    public WindowsEventCollector(
        TimeProvider? timeProvider = null,
        TimeSpan? anchorLookback = null,
        TimeSpan? evidenceBeforeAnchor = null,
        TimeSpan? evidenceAfterAnchor = null,
        int maxEventsPerLog = DefaultMaxEventsPerLog)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _anchorLookback = RequirePositive(anchorLookback ?? DefaultAnchorLookback, nameof(anchorLookback));
        _evidenceBeforeAnchor = RequireNonNegative(
            evidenceBeforeAnchor ?? DefaultEvidenceBeforeAnchor,
            nameof(evidenceBeforeAnchor));
        _evidenceAfterAnchor = RequireNonNegative(
            evidenceAfterAnchor ?? DefaultEvidenceAfterAnchor,
            nameof(evidenceAfterAnchor));
        _maxEventsPerLog = maxEventsPerLog > 0
            ? maxEventsPerLog
            : throw new ArgumentOutOfRangeException(nameof(maxEventsPerLog));
    }

    public Task<WindowsEventCollection> CollectRetrospectiveAsync(
        DateTimeOffset? manualAnchorUtc = null,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => CollectRetrospective(manualAnchorUtc, cancellationToken), cancellationToken);

    public Task<WindowsEventCollection> CollectWindowAsync(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        CancellationToken cancellationToken = default)
        => CollectWindowAsync(startUtc, endUtc, TargetProfile.Battlefield6, cancellationToken);

    public Task<WindowsEventCollection> CollectWindowAsync(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        TargetProfile? targetProfile,
        CancellationToken cancellationToken = default)
    {
        ValidateWindow(startUtc, endUtc);
        return Task.Run(
            () => CollectWindow(startUtc.ToUniversalTime(), endUtc.ToUniversalTime(), null, targetProfile, cancellationToken),
            cancellationToken);
    }

    /// <summary>
    /// Reads exactly one allowlisted event-log source for the elevated retry
    /// protocol. The returned model contains parsed, whitelisted fields rather
    /// than raw event XML or an EVTX export.
    /// </summary>
    internal Task<WindowsEventCollection> CollectProtectedSourceWindowAsync(
        ProtectedEvidenceSource source,
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        TargetProfile? targetProfile,
        CancellationToken cancellationToken = default)
    {
        ValidateWindow(startUtc, endUtc);
        LogSpecification specification = source switch
        {
            ProtectedEvidenceSource.SystemEventLog => new LogSpecification(
                SystemLog,
                "Windows Event Log/System",
                BuildEvidenceSystemXPath(startUtc, endUtc)),
            ProtectedEvidenceSource.ApplicationEventLog => new LogSpecification(
                ApplicationLog,
                "Windows Event Log/Application",
                $"*[System[{TimePredicate(startUtc, endUtc)} and (EventID=1000 or EventID=1001 or EventID=1002)]]",
                item => IsRelevantApplicationEvent(item, targetProfile)),
            _ => throw new ArgumentOutOfRangeException(nameof(source), "The selected source is not an event log.")
        };

        return Task.Run(() =>
        {
            cancellationToken.ThrowIfCancellationRequested();
            LogReadResult result = ReadLog(specification, cancellationToken);
            DiagnosticEvent[] events = result.Events
                .OrderBy(item => item.TimeUtc)
                .ThenBy(item => item.ProviderName, StringComparer.OrdinalIgnoreCase)
                .ThenBy(item => item.EventId)
                .ToArray();
            return new WindowsEventCollection(
                null,
                startUtc.ToUniversalTime(),
                endUtc.ToUniversalTime(),
                events,
                new EventAnalyzer().GroupDuplicates(events),
                [result.Status]);
        }, cancellationToken);
    }

    internal static bool IsAllowedProtectedEvidenceEvent(
        ProtectedEvidenceSource source,
        DiagnosticEvent item,
        TargetProfile? targetProfile)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (source == ProtectedEvidenceSource.ApplicationEventLog)
        {
            return item.LogName.Equals(ApplicationLog, StringComparison.OrdinalIgnoreCase) &&
                   item.EventId is 1000 or 1001 or 1002 &&
                   IsRelevantApplicationEvent(item, targetProfile);
        }

        if (source != ProtectedEvidenceSource.SystemEventLog ||
            !item.LogName.Equals(SystemLog, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if ((item.ProviderName.Equals("Microsoft-Windows-WER-SystemErrorReporting", StringComparison.OrdinalIgnoreCase) && item.EventId == 1001) ||
            (item.ProviderName.Equals("Microsoft-Windows-Kernel-Power", StringComparison.OrdinalIgnoreCase) && item.EventId == 41) ||
            (item.ProviderName.Equals("EventLog", StringComparison.OrdinalIgnoreCase) && item.EventId == 6008) ||
            (item.ProviderName.Equals("Display", StringComparison.OrdinalIgnoreCase) && item.EventId == 4101) ||
            (item.ProviderName.Equals("Microsoft-Windows-Resource-Exhaustion-Detector", StringComparison.OrdinalIgnoreCase) && item.EventId == 2004) ||
            (WheaEventCatalog.IsProvider(item.ProviderName, item.ProviderGuid) && WheaEventCatalog.IsKnown(item.EventId)))
        {
            return true;
        }

        if (IsProviderEventSignal(StorageEvidenceSignals, item) ||
            IsProviderEventSignal(FileSystemEvidenceSignals, item) ||
            IsProviderEventSignal(DumpWriteEvidenceSignals, item) ||
            IsProviderEventSignal(MemoryDiagnosticEvidenceSignals, item))
        {
            return true;
        }

        return item.ProviderName.Equals("nvlddmkm", StringComparison.OrdinalIgnoreCase) ||
               item.ProviderName.Equals("amdwddmg", StringComparison.OrdinalIgnoreCase) ||
               item.ProviderName.Equals("amdkmdag", StringComparison.OrdinalIgnoreCase) ||
               item.ProviderName.Equals("Microsoft-Windows-DxgKrnl", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsProviderEventSignal(
        IEnumerable<(string Provider, int[] EventIds)> signals,
        DiagnosticEvent item) => signals.Any(signal =>
            item.ProviderName.Equals(signal.Provider, StringComparison.OrdinalIgnoreCase) &&
            signal.EventIds.Contains(item.EventId));

    /// <summary>
    /// Parses event XML without copying Computer, Security, Correlation, or Execution fields.
    /// This method is public so the parser can be verified against captured, sanitized fixtures.
    /// </summary>
    public static DiagnosticEvent ParseEventXml(string xml, string? renderedMessage = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(xml);

        using var stringReader = new StringReader(xml);
        using XmlReader reader = XmlReader.Create(stringReader, new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            IgnoreComments = true,
            IgnoreProcessingInstructions = true
        });

        XDocument document = XDocument.Load(reader, LoadOptions.None);
        XElement root = document.Root ?? throw new XmlException("The event XML has no root element.");
        XElement system = Child(root, "System") ?? throw new XmlException("The event XML has no System element.");
        XElement provider = Child(system, "Provider") ?? throw new XmlException("The event XML has no Provider element.");

        string providerName = Attribute(provider, "Name") ?? "Unknown";
        Guid? publisherGuid = ParseGuid(Attribute(provider, "Guid"));
        int eventId = ParseInt(Child(system, "EventID")?.Value);
        byte? level = ParseByte(Child(system, "Level")?.Value);
        DateTimeOffset timeUtc = ParseTimestamp(
            Attribute(Child(system, "TimeCreated"), "SystemTime"));
        string logName = Child(system, "Channel")?.Value.Trim() ?? "Unknown";

        IReadOnlyDictionary<string, string> data = ParseWhitelistedData(root, providerName);
        Guid? subjectProviderGuid = FindProviderGuid(data);
        bool isKernelEventTracing = providerName.Contains(
            "Kernel-EventTracing",
            StringComparison.OrdinalIgnoreCase);
        Guid? diagnosticProviderGuid = isKernelEventTracing
            ? subjectProviderGuid ?? publisherGuid
            : publisherGuid;

        string? embeddedMessage = Descendants(root, "RenderingInfo")
            .Select(element => Child(element, "Message")?.Value)
            .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
        string message = CreateMessage(
            providerName,
            eventId,
            diagnosticProviderGuid,
            data,
            renderedMessage ?? embeddedMessage);

        return new DiagnosticEvent(
            timeUtc,
            logName,
            providerName,
            diagnosticProviderGuid,
            eventId,
            level,
            LevelName(level),
            message,
            data);
    }

    private WindowsEventCollection CollectRetrospective(
        DateTimeOffset? manualAnchorUtc,
        CancellationToken cancellationToken)
    {
        DateTimeOffset nowUtc = _timeProvider.GetUtcNow();
        CrashAnchor? anchor;
        var statuses = new List<CollectionStatus>();

        if (manualAnchorUtc is not null)
        {
            DateTimeOffset timeUtc = manualAnchorUtc.Value.ToUniversalTime();
            if (timeUtc > nowUtc.AddMinutes(5))
            {
                throw new ArgumentOutOfRangeException(
                    nameof(manualAnchorUtc),
                    "The manual crash time cannot be in the future.");
            }

            anchor = new CrashAnchor(
                timeUtc,
                "Manual crash time",
                0,
                "Crash time supplied by the user",
                Priority: 1_000);
        }
        else
        {
            DateTimeOffset scanStartUtc = nowUtc - _anchorLookback;
            LogReadBatch scan = ReadLogs(
                scanStartUtc,
                nowUtc,
                anchorScan: true,
                TargetProfile.Battlefield6,
                cancellationToken);
            statuses.AddRange(scan.Statuses.Select(status => status with
            {
                Source = status.Source + " (anchor scan)"
            }));
            anchor = SelectLatestAnchor(scan.Events);
        }

        DateTimeOffset windowEndUtc = anchor is null
            ? nowUtc
            : Min(nowUtc, anchor.TimeUtc + _evidenceAfterAnchor);
        DateTimeOffset windowStartUtc = anchor is null
            ? nowUtc - _evidenceBeforeAnchor
            : anchor.TimeUtc - _evidenceBeforeAnchor;

        return CollectWindow(windowStartUtc, windowEndUtc, anchor, TargetProfile.Battlefield6, cancellationToken, statuses);
    }

    private WindowsEventCollection CollectWindow(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        CrashAnchor? anchor,
        TargetProfile? targetProfile,
        CancellationToken cancellationToken,
        List<CollectionStatus>? existingStatuses = null)
    {
        cancellationToken.ThrowIfCancellationRequested();
        LogReadBatch batch = ReadLogs(startUtc, endUtc, anchorScan: false, targetProfile, cancellationToken);
        var statuses = existingStatuses ?? [];
        statuses.AddRange(batch.Statuses);

        DiagnosticEvent[] events = batch.Events
            .OrderBy(item => item.TimeUtc)
            .ThenBy(item => item.LogName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.EventId)
            .ToArray();
        IReadOnlyList<DuplicateEventGroup> groups = new EventAnalyzer().GroupDuplicates(events);

        return new WindowsEventCollection(
            anchor,
            startUtc,
            endUtc,
            events,
            groups,
            statuses.ToArray());
    }

    private LogReadBatch ReadLogs(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        bool anchorScan,
        TargetProfile? targetProfile,
        CancellationToken cancellationToken)
    {
        ValidateWindow(startUtc, endUtc);
        var events = new List<DiagnosticEvent>();
        var statuses = new List<CollectionStatus>();

        IEnumerable<LogSpecification> specifications = anchorScan
            ? AnchorSpecifications(startUtc, endUtc, targetProfile)
            : EvidenceSpecifications(startUtc, endUtc, targetProfile);

        foreach (LogSpecification specification in specifications)
        {
            cancellationToken.ThrowIfCancellationRequested();
            LogReadResult result = ReadLog(specification, cancellationToken);
            events.AddRange(result.Events);
            statuses.Add(result.Status);
        }

        return new LogReadBatch(events, statuses);
    }

    private LogReadResult ReadLog(LogSpecification specification, CancellationToken cancellationToken)
    {
        try
        {
            var query = new EventLogQuery(
                specification.LogName,
                PathType.LogName,
                specification.XPath)
            {
                ReverseDirection = true,
                TolerateQueryErrors = false
            };

            using var eventReader = new EventLogReader(query);
            var events = new List<DiagnosticEvent>();
            bool truncated = false;
            int recordsRead = 0;
            while (recordsRead < _maxEventsPerLog)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using EventRecord? eventRecord = eventReader.ReadEvent();
                if (eventRecord is null)
                {
                    break;
                }

                recordsRead++;

                DiagnosticEvent parsed;
                try
                {
                    parsed = ParseEventXml(eventRecord.ToXml(), SafeFormatDescription(eventRecord));
                }
                catch (XmlException)
                {
                    continue;
                }
                catch (FormatException)
                {
                    continue;
                }

                if (specification.Filter is null || specification.Filter(parsed))
                {
                    events.Add(parsed);
                }
            }

            if (recordsRead == _maxEventsPerLog)
            {
                using EventRecord? next = eventReader.ReadEvent();
                truncated = next is not null;
            }

            EventLogStatus? failedStatus = eventReader.LogStatus.FirstOrDefault(status => status.StatusCode != 0);
            if (failedStatus is not null)
            {
                return new LogReadResult(
                    events,
                    StatusFromWin32Code(specification.SourceName, failedStatus.StatusCode));
            }

            string detail = truncated
                ? $"Inspected {_maxEventsPerLog} matching records and retained {events.Count}; additional matches were not read."
                : $"Inspected {recordsRead} matching {(recordsRead == 1 ? "record" : "records")} and retained {events.Count}.";
            return new LogReadResult(
                events,
                new CollectionStatus(specification.SourceName, CollectionState.Available, detail));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            return Denied(specification.SourceName);
        }
        catch (SecurityException)
        {
            return Denied(specification.SourceName);
        }
        catch (EventLogNotFoundException)
        {
            return new LogReadResult(
                [],
                new CollectionStatus(
                    specification.SourceName,
                    CollectionState.Unavailable,
                    "The log is not present or enabled on this Windows installation."));
        }
        catch (PlatformNotSupportedException)
        {
            return new LogReadResult(
                [],
                new CollectionStatus(
                    specification.SourceName,
                    CollectionState.Unavailable,
                    "Windows Event Log APIs are unavailable on this platform."));
        }
        catch (EventLogException exception)
        {
            return new LogReadResult(
                [],
                new CollectionStatus(
                    specification.SourceName,
                    CollectionState.Error,
                    $"Windows Event Log returned error 0x{exception.HResult:X8}."));
        }
        catch (InvalidOperationException exception)
        {
            return new LogReadResult(
                [],
                new CollectionStatus(
                    specification.SourceName,
                    CollectionState.Error,
                    $"The event source could not be read (0x{exception.HResult:X8})."));
        }
    }

    private static IEnumerable<LogSpecification> AnchorSpecifications(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        TargetProfile? targetProfile)
    {
        string time = TimePredicate(startUtc, endUtc);
        string fatalWheaIds = EventIdPredicate(WheaEventCatalog.FatalEventIds);
        yield return new LogSpecification(
            SystemLog,
            "Windows Event Log/System",
            $"*[System[{time} and (" +
            "(Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] and EventID=1001) or " +
            "(Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=41) or " +
            "(Provider[@Name='EventLog'] and EventID=6008) or " +
            $"(Provider[@Name='{WheaEventCatalog.ProviderName}'] and ({fatalWheaIds})) or " +
            "(Provider[@Name='Display'] and EventID=4101) or " +
            "(Provider[@Name='Microsoft-Windows-Resource-Exhaustion-Detector'] and EventID=2004)" +
            ")]]");

        yield return new LogSpecification(
            ApplicationLog,
            "Windows Event Log/Application",
            $"*[System[{time} and (EventID=1000 or EventID=1001 or EventID=1002)]]",
            item => IsRelevantApplicationEvent(item, targetProfile));
    }

    private static IEnumerable<LogSpecification> EvidenceSpecifications(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        TargetProfile? targetProfile)
    {
        string time = TimePredicate(startUtc, endUtc);
        yield return new LogSpecification(
            SystemLog,
            "Windows Event Log/System",
            BuildEvidenceSystemXPath(startUtc, endUtc));

        yield return new LogSpecification(
            ApplicationLog,
            "Windows Event Log/Application",
            $"*[System[{time} and (EventID=1000 or EventID=1001 or EventID=1002)]]",
            item => IsRelevantApplicationEvent(item, targetProfile));

        yield return new LogSpecification(
            KernelEventTracingLog,
            "Windows Event Log/Kernel-EventTracing Admin",
            $"*[System[{time} and (EventID=2 or EventID=3 or EventID=4 or EventID=28)]]");
    }

    internal static string BuildEvidenceSystemXPath(DateTimeOffset startUtc, DateTimeOffset endUtc)
    {
        ValidateWindow(startUtc, endUtc);
        string time = TimePredicate(startUtc, endUtc);
        string knownWheaIds = EventIdPredicate(WheaEventCatalog.KnownEventIds);
        var predicates = new List<string>
        {
            "(Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] and EventID=1001)",
            "(Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=41)",
            "(Provider[@Name='EventLog'] and EventID=6008)",
            $"(Provider[@Name='{WheaEventCatalog.ProviderName}'] and ({knownWheaIds}))",
            "(Provider[@Name='Display'] and EventID=4101)",
            "(Provider[@Name='Microsoft-Windows-Resource-Exhaustion-Detector'] and EventID=2004)"
        };

        predicates.AddRange(StorageEvidenceSignals.Select(ProviderEventPredicate));
        predicates.AddRange(FileSystemEvidenceSignals.Select(ProviderEventPredicate));
        predicates.AddRange(DumpWriteEvidenceSignals.Select(ProviderEventPredicate));
        predicates.AddRange(MemoryDiagnosticEvidenceSignals.Select(ProviderEventPredicate));

        // Preserve the existing display-driver evidence surface. These providers do not have
        // one stable cross-version event-ID catalog, so their records remain bounded by time.
        predicates.Add("Provider[@Name='nvlddmkm']");
        predicates.Add("Provider[@Name='amdwddmg']");
        predicates.Add("Provider[@Name='amdkmdag']");
        predicates.Add("Provider[@Name='Microsoft-Windows-DxgKrnl']");

        return $"*[System[{time} and ({string.Join(" or ", predicates)})]]";
    }

    private static string ProviderEventPredicate((string Provider, int[] EventIds) signal) =>
        $"(Provider[@Name='{signal.Provider}'] and ({EventIdPredicate(signal.EventIds)}))";

    private static CrashAnchor? SelectLatestAnchor(IReadOnlyList<DiagnosticEvent> events)
    {
        var candidates = events
            .Select(TryCreateAnchor)
            .Where(candidate => candidate is not null)
            .Cast<CrashAnchor>()
            .OrderByDescending(candidate => candidate.TimeUtc)
            .ToArray();
        if (candidates.Length == 0)
        {
            return null;
        }

        DateTimeOffset newest = candidates[0].TimeUtc;
        return candidates
            .Where(candidate => newest - candidate.TimeUtc <= TimeSpan.FromMinutes(15))
            .OrderByDescending(candidate => candidate.Priority)
            .ThenByDescending(candidate => candidate.TimeUtc)
            .First();
    }

    private static CrashAnchor? TryCreateAnchor(DiagnosticEvent item)
    {
        CrashAnchor? standard = new EventAnalyzer().SelectCrashAnchor([item]);
        if (standard is not null)
        {
            return standard;
        }

        string searchable = item.ProviderName + " " + item.Message + " " +
            string.Join(' ', item.Data.Values);
        if (WheaEventCatalog.IsProvider(item.ProviderName, item.ProviderGuid) &&
            WheaEventCatalog.Classify(item.EventId) == WheaEventClassification.Fatal)
        {
            return new CrashAnchor(
                item.TimeUtc,
                item.ProviderName,
                item.EventId,
                "Windows hardware-error event",
                Priority: 425);
        }

        if (item.EventId is 1000 or 1001 or 1002 && ContainsBf6OrEaSignal(searchable))
        {
            return new CrashAnchor(
                item.TimeUtc,
                item.ProviderName,
                item.EventId,
                item.EventId == 1002
                    ? "BF6, EA, or Javelin application hang"
                    : "BF6, EA, or Javelin application failure",
                Priority: 300);
        }

        if (item.ProviderName.Equals("Display", StringComparison.OrdinalIgnoreCase) && item.EventId == 4101)
        {
            return new CrashAnchor(
                item.TimeUtc,
                item.ProviderName,
                item.EventId,
                "Display driver timeout or recovery",
                Priority: 275);
        }

        if (item.EventId == 2004 &&
            item.ProviderName.Contains("Resource-Exhaustion", StringComparison.OrdinalIgnoreCase))
        {
            return new CrashAnchor(
                item.TimeUtc,
                item.ProviderName,
                item.EventId,
                "Windows resource-exhaustion event",
                Priority: 250);
        }

        return null;
    }

    private static IReadOnlyDictionary<string, string> ParseWhitelistedData(XElement root, string providerName)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        XElement? eventData = Child(root, "EventData");
        if (eventData is not null)
        {
            int unnamedIndex = 0;
            foreach (XElement element in eventData.Elements().Where(element => element.Name.LocalName == "Data"))
            {
                string? name = Attribute(element, "Name");
                if (string.IsNullOrWhiteSpace(name))
                {
                    name = $"param{++unnamedIndex}";
                }

                AddAllowedValue(values, name, element.Value);
            }
        }

        XElement? userData = Child(root, "UserData");
        if (userData is not null)
        {
            foreach (XElement leaf in userData.Descendants().Where(element => !element.HasElements))
            {
                AddAllowedValue(values, leaf.Name.LocalName, leaf.Value);
            }
        }

        if (WheaEventCatalog.IsProvider(providerName))
        {
            string? encodedRecord = Descendants(root, "Binary")
                .Select(element => element.Value)
                .FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
            if (CperRecordDecoder.TryClassifyBase64(encodedRecord, out IReadOnlyList<string> categories))
            {
                values["CperSectionCategories"] = string.Join(", ", categories);
            }
        }

        return new ReadOnlyDictionary<string, string>(values);
    }

    private static void AddAllowedValue(IDictionary<string, string> values, string name, string rawValue)
    {
        if ((!AllowedDataNames.Contains(name) && !AllowedNumberedDataNames.Contains(name)) ||
            values.ContainsKey(name))
        {
            return;
        }

        string value = CollapseWhitespace(rawValue, 1_024);
        if (!string.IsNullOrWhiteSpace(value))
        {
            values.Add(name, value);
        }
    }

    private static Guid? FindProviderGuid(IReadOnlyDictionary<string, string> data)
    {
        KeyValuePair<string, string> match = data.FirstOrDefault(pair =>
            pair.Key.Equals("ProviderGuid", StringComparison.OrdinalIgnoreCase));
        return ParseGuid(match.Value);
    }

    private static string CreateMessage(
        string providerName,
        int eventId,
        Guid? providerGuid,
        IReadOnlyDictionary<string, string> data,
        string? renderedMessage)
    {
        if (providerName.Contains("Kernel-EventTracing", StringComparison.OrdinalIgnoreCase) &&
            eventId == 28 &&
            providerGuid is not null &&
            TryGetValue(data, "ErrorCode", out string? errorCode) &&
            !string.IsNullOrWhiteSpace(errorCode))
        {
            return $"Error setting traits on Provider {{{providerGuid.Value:D}}}. Error: {NormalizeStatusCode(errorCode!)}";
        }

        if (!string.IsNullOrWhiteSpace(renderedMessage))
        {
            return CollapseWhitespace(renderedMessage, 4_096);
        }

        string fields = string.Join(
            "; ",
            data.OrderBy(pair => pair.Key, StringComparer.OrdinalIgnoreCase)
                .Select(pair => $"{pair.Key}={pair.Value}"));
        return string.IsNullOrWhiteSpace(fields)
            ? $"{providerName} event {eventId}."
            : CollapseWhitespace($"{providerName} event {eventId}: {fields}", 4_096);
    }

    private static bool TryGetValue(
        IReadOnlyDictionary<string, string> data,
        string name,
        out string? value)
    {
        KeyValuePair<string, string> match = data.FirstOrDefault(pair =>
            pair.Key.Equals(name, StringComparison.OrdinalIgnoreCase));
        value = string.IsNullOrWhiteSpace(match.Value) ? null : match.Value;
        return value is not null;
    }

    private static string NormalizeStatusCode(string value)
    {
        string trimmed = value.Trim();
        if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            return "0x" + trimmed[2..].PadLeft(8, '0').ToUpperInvariant();
        }

        return ulong.TryParse(trimmed, NumberStyles.Integer, CultureInfo.InvariantCulture, out ulong number)
            ? $"0x{number:X8}"
            : trimmed;
    }

    private static bool IsRelevantApplicationEvent(DiagnosticEvent item, TargetProfile? targetProfile)
    {
        string searchable = item.ProviderName + " " + item.Message + " " +
            string.Join(' ', item.Data.Values);
        if (DiagnosticSignalClassifier.IsDiagnosticToolSelfSignal(searchable))
        {
            return false;
        }

        return (targetProfile?.MatchesApplicationEvidence(searchable) ?? false) ||
               searchable.Contains("LiveKernelEvent", StringComparison.OrdinalIgnoreCase) ||
               searchable.Contains("BlueScreen", StringComparison.OrdinalIgnoreCase) ||
               searchable.Contains("VIDEO_ENGINE_TIMEOUT", StringComparison.OrdinalIgnoreCase) ||
               searchable.Contains("VIDEO_TDR_TIMEOUT", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsBf6OrEaSignal(string text) =>
        Bf6OrEaRegex().IsMatch(text);

    [GeneratedRegex(
        @"(?i)(?:\bBF6(?:\.exe)?\b|Battlefield\s*6|Battlefield6|Javelin|EA[ .-]?(?:App|Desktop|AntiCheat)|EAAntiCheat|Electronic Arts)",
        RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 1_000)]
    private static partial Regex Bf6OrEaRegex();

    private static string? SafeFormatDescription(EventRecord eventRecord)
    {
        try
        {
            return eventRecord.FormatDescription();
        }
        catch (EventLogException)
        {
            return null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    private static string TimePredicate(DateTimeOffset startUtc, DateTimeOffset endUtc)
    {
        string start = startUtc.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ", CultureInfo.InvariantCulture);
        string end = endUtc.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ", CultureInfo.InvariantCulture);
        return $"TimeCreated[@SystemTime >= '{start}' and @SystemTime <= '{end}']";
    }

    private static string EventIdPredicate(IEnumerable<int> eventIds) =>
        string.Join(" or ", eventIds.Select(eventId => $"EventID={eventId.ToString(CultureInfo.InvariantCulture)}"));

    private static CollectionStatus StatusFromWin32Code(string source, int statusCode)
    {
        CollectionState state = statusCode switch
        {
            2 or 3 or 15007 => CollectionState.Unavailable,
            5 => CollectionState.Denied,
            1460 => CollectionState.TimedOut,
            _ => CollectionState.Error
        };
        return new CollectionStatus(
            source,
            state,
            $"Windows returned status 0x{statusCode:X8} while reading the log.");
    }

    private static LogReadResult Denied(string source) => new(
        [],
        new CollectionStatus(
            source,
            CollectionState.Denied,
            "Windows denied access. The collector did not request elevation."));

    private static Guid? ParseGuid(string? value) =>
        Guid.TryParse(value, out Guid parsed) ? parsed : null;

    private static int ParseInt(string? value) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed)
            ? parsed
            : 0;

    private static byte? ParseByte(string? value) =>
        byte.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out byte parsed)
            ? parsed
            : null;

    private static DateTimeOffset ParseTimestamp(string? value)
    {
        if (!DateTimeOffset.TryParse(
                value,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out DateTimeOffset parsed))
        {
            throw new FormatException("The event does not contain a valid UTC timestamp.");
        }

        return parsed;
    }

    private static string LevelName(byte? level) => level switch
    {
        1 => "Critical",
        2 => "Error",
        3 => "Warning",
        4 => "Information",
        5 => "Verbose",
        null => "Unknown",
        _ => $"Level {level.Value.ToString(CultureInfo.InvariantCulture)}"
    };

    private static XElement? Child(XElement? parent, string localName) =>
        parent?.Elements().FirstOrDefault(element => element.Name.LocalName == localName);

    private static IEnumerable<XElement> Descendants(XElement parent, string localName) =>
        parent.Descendants().Where(element => element.Name.LocalName == localName);

    private static string? Attribute(XElement? element, string localName) =>
        element?.Attributes().FirstOrDefault(attribute => attribute.Name.LocalName == localName)?.Value;

    private static string CollapseWhitespace(string value, int maximumLength)
    {
        var builder = new StringBuilder(Math.Min(value.Length, maximumLength));
        bool previousWasWhitespace = false;
        foreach (char character in value)
        {
            bool isWhitespace = char.IsWhiteSpace(character);
            if (isWhitespace)
            {
                if (previousWasWhitespace || builder.Length == 0)
                {
                    continue;
                }

                builder.Append(' ');
                previousWasWhitespace = true;
            }
            else
            {
                builder.Append(character);
                previousWasWhitespace = false;
            }

            if (builder.Length >= maximumLength)
            {
                break;
            }
        }

        return builder.ToString().Trim();
    }

    private static void ValidateWindow(DateTimeOffset startUtc, DateTimeOffset endUtc)
    {
        if (endUtc < startUtc)
        {
            throw new ArgumentOutOfRangeException(nameof(endUtc), "The end of the event window precedes its start.");
        }
    }

    private static TimeSpan RequirePositive(TimeSpan value, string parameterName) =>
        value > TimeSpan.Zero ? value : throw new ArgumentOutOfRangeException(parameterName);

    private static TimeSpan RequireNonNegative(TimeSpan value, string parameterName) =>
        value >= TimeSpan.Zero ? value : throw new ArgumentOutOfRangeException(parameterName);

    private static DateTimeOffset Min(DateTimeOffset first, DateTimeOffset second) =>
        first <= second ? first : second;

    private sealed record LogSpecification(
        string LogName,
        string SourceName,
        string XPath,
        Func<DiagnosticEvent, bool>? Filter = null);

    private sealed record LogReadResult(
        IReadOnlyList<DiagnosticEvent> Events,
        CollectionStatus Status);

    private sealed record LogReadBatch(
        IReadOnlyList<DiagnosticEvent> Events,
        IReadOnlyList<CollectionStatus> Statuses);
}
