using System.Globalization;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Collectors;

/// <summary>
/// Builds a bounded, local timeline from Windows Update history and privacy-filtered
/// SetupAPI device-install sections. It never searches for updates or exports raw logs.
/// </summary>
public sealed partial class RecentChangeCollector
{
    private readonly IWindowsUpdateHistoryReader _updateReader;
    private readonly ISetupApiTimelineReader _setupReader;
    private readonly TimeProvider _timeProvider;

    public RecentChangeCollector()
        : this(new WindowsUpdateHistoryReader(), new SetupApiTimelineReader(), TimeProvider.System)
    {
    }

    internal RecentChangeCollector(
        IWindowsUpdateHistoryReader updateReader,
        ISetupApiTimelineReader setupReader,
        TimeProvider timeProvider)
    {
        _updateReader = updateReader;
        _setupReader = setupReader;
        _timeProvider = timeProvider;
    }

    public Task<RecentChangeTimeline> CollectAsync(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        CancellationToken cancellationToken = default)
    {
        if (endUtc < startUtc)
        {
            throw new ArgumentOutOfRangeException(nameof(endUtc));
        }

        return Task.Run(
            () => Collect(startUtc.ToUniversalTime(), endUtc.ToUniversalTime(), null, cancellationToken),
            cancellationToken);
    }

    public Task<RecentChangeTimeline> CollectForIncidentAsync(
        DateTimeOffset incidentTimeUtc,
        CancellationToken cancellationToken = default)
    {
        DateTimeOffset incident = incidentTimeUtc.ToUniversalTime();
        DateTimeOffset start = incident.AddDays(-7);
        return Task.Run(
            () => Collect(start, incident, incident, cancellationToken),
            cancellationToken);
    }

    private RecentChangeTimeline Collect(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        DateTimeOffset? incidentTimeUtc,
        CancellationToken cancellationToken)
    {
        RecentChangeSourceResult updates = _updateReader.Read(startUtc, endUtc, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        RecentChangeSourceResult setup = _setupReader.Read(startUtc, endUtc, cancellationToken);

        RecentSystemChange[] records = updates.Records
            .Concat(setup.Records)
            .Where(item => item.TimeUtc >= startUtc && item.TimeUtc <= endUtc)
            .Select(item => incidentTimeUtc is null
                ? item
                : WithIncidentProximity(item, incidentTimeUtc.Value))
            .OrderBy(item => item.TimeUtc)
            .ThenBy(item => item.Kind)
            .Take(512)
            .ToArray();
        return new RecentChangeTimeline(
            _timeProvider.GetUtcNow().ToUniversalTime(),
            startUtc,
            endUtc,
            records,
            [updates.Status, setup.Status]);
    }

    internal static RecentSystemChange WithIncidentProximity(
        RecentSystemChange change,
        DateTimeOffset incidentTimeUtc)
    {
        TimeSpan elapsed = incidentTimeUtc.ToUniversalTime() - change.TimeUtc.ToUniversalTime();
        if (elapsed < TimeSpan.Zero)
        {
            return change with
            {
                TimeBeforeIncident = null,
                Within24Hours = false,
                WithinSevenDays = false
            };
        }

        return change with
        {
            TimeBeforeIncident = elapsed,
            Within24Hours = elapsed <= TimeSpan.FromHours(24),
            WithinSevenDays = elapsed <= TimeSpan.FromDays(7)
        };
    }

    internal static string SanitizeText(string? value, int maximumLength = 256)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        string collapsed = string.Join(' ', value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        string redacted = WindowsPathRegex().Replace(collapsed, "<path>");
        return redacted.Length <= maximumLength ? redacted : redacted[..maximumLength];
    }

    [GeneratedRegex(@"(?i)(?:[A-Z]:\\|\\\\)[^\s""']+")]
    private static partial Regex WindowsPathRegex();
}

internal sealed record RecentChangeSourceResult(
    IReadOnlyList<RecentSystemChange> Records,
    CollectionStatus Status);

internal sealed record RawWindowsUpdateHistoryEntry(
    DateTimeOffset TimeUtc,
    string Title,
    int Operation,
    int ResultCode,
    int HResult);

internal interface IWindowsUpdateHistoryReader
{
    RecentChangeSourceResult Read(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        CancellationToken cancellationToken);
}

internal sealed class WindowsUpdateHistoryReader : IWindowsUpdateHistoryReader
{
    private const int MaximumEntries = 256;

    public RecentChangeSourceResult Read(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        CancellationToken cancellationToken)
    {
        const string source = "Recent changes/Windows Update history";
        object? session = null;
        object? searcher = null;
        object? collection = null;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            Type? sessionType = Type.GetTypeFromProgID("Microsoft.Update.Session", throwOnError: false);
            if (sessionType is null || Activator.CreateInstance(sessionType) is not { } createdSession)
            {
                return Unavailable(source, "The local Windows Update history API was unavailable.");
            }

            session = createdSession;
            dynamic dynamicSession = session;
            searcher = dynamicSession.CreateUpdateSearcher();
            dynamic dynamicSearcher = searcher;
            int total = Convert.ToInt32(dynamicSearcher.GetTotalHistoryCount(), CultureInfo.InvariantCulture);
            int count = Math.Min(Math.Max(total, 0), MaximumEntries);
            if (count == 0)
            {
                return Available(source, [], "Windows Update history contained no entries.");
            }

            collection = dynamicSearcher.QueryHistory(0, count);
            dynamic dynamicCollection = collection;
            var records = new List<RecentSystemChange>();
            for (int index = 0; index < count; index++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                object? entry = null;
                try
                {
                    entry = dynamicCollection.Item(index);
                    dynamic dynamicEntry = entry;
                    DateTime localDate = Convert.ToDateTime(dynamicEntry.Date, CultureInfo.InvariantCulture);
                    DateTimeOffset timestamp = new(localDate.ToUniversalTime(), TimeSpan.Zero);
                    if (timestamp < startUtc || timestamp > endUtc)
                    {
                        continue;
                    }

                    int operation = Convert.ToInt32(dynamicEntry.Operation, CultureInfo.InvariantCulture);
                    int result = Convert.ToInt32(dynamicEntry.ResultCode, CultureInfo.InvariantCulture);
                    int hresult = Convert.ToInt32(dynamicEntry.HResult, CultureInfo.InvariantCulture);
                    records.Add(new RecentSystemChange(
                        timestamp,
                        RecentChangeKind.WindowsUpdate,
                        RecentChangeCollector.SanitizeText(Convert.ToString(dynamicEntry.Title, CultureInfo.InvariantCulture)),
                        OperationName(operation),
                        ResultName(result),
                        hresult == 0 ? string.Empty : $"0x{unchecked((uint)hresult):X8}"));
                }
                finally
                {
                    ReleaseCom(entry);
                }
            }

            string detail = total > MaximumEntries
                ? $"Read the newest {MaximumEntries} local history entries; older entries were not queried."
                : $"Read {total} local Windows Update history {(total == 1 ? "entry" : "entries")}.";
            return Available(source, records, detail);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            return Denied(source);
        }
        catch (SecurityException)
        {
            return Denied(source);
        }
        catch (Exception exception) when (exception is COMException or InvalidCastException or FormatException or OverflowException)
        {
            return new RecentChangeSourceResult(
                [],
                new CollectionStatus(source, CollectionState.Error,
                    $"The local Windows Update history API failed (0x{exception.HResult:X8})."));
        }
        finally
        {
            ReleaseCom(collection);
            ReleaseCom(searcher);
            ReleaseCom(session);
        }
    }

    private static string OperationName(int value) => value switch
    {
        1 => "Installation",
        2 => "Uninstallation",
        _ => "Unknown"
    };

    private static string ResultName(int value) => value switch
    {
        0 => "Not started",
        1 => "In progress",
        2 => "Succeeded",
        3 => "Succeeded with errors",
        4 => "Failed",
        5 => "Aborted",
        _ => "Unknown"
    };

    private static void ReleaseCom(object? value)
    {
        if (value is not null && Marshal.IsComObject(value))
        {
            _ = Marshal.FinalReleaseComObject(value);
        }
    }

    private static RecentChangeSourceResult Available(
        string source,
        IReadOnlyList<RecentSystemChange> records,
        string detail) => new(records, new CollectionStatus(source, CollectionState.Available, detail));

    private static RecentChangeSourceResult Unavailable(string source, string detail) =>
        new([], new CollectionStatus(source, CollectionState.Unavailable, detail));

    private static RecentChangeSourceResult Denied(string source) =>
        new([], new CollectionStatus(source, CollectionState.Denied, "Windows denied access to update history."));
}

internal interface ISetupApiTimelineReader
{
    RecentChangeSourceResult Read(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        CancellationToken cancellationToken);
}

internal sealed partial class SetupApiTimelineReader : ISetupApiTimelineReader
{
    private const int MaximumBytes = 8 * 1024 * 1024;
    private const int MaximumRecords = 256;

    public RecentChangeSourceResult Read(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        CancellationToken cancellationToken)
    {
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string path = Path.Combine(windows, "INF", "setupapi.dev.log");
        return ReadFile(path, startUtc, endUtc, cancellationToken);
    }

    internal static RecentChangeSourceResult ReadFile(
        string path,
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        CancellationToken cancellationToken)
    {
        const string source = "Recent changes/SetupAPI device installation log";
        try
        {
            if (!File.Exists(path))
            {
                return new RecentChangeSourceResult(
                    [],
                    new CollectionStatus(source, CollectionState.Unavailable,
                        "The Windows SetupAPI device-installation log was not present."));
            }

            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                64 * 1024,
                FileOptions.SequentialScan);
            long skipped = Math.Max(0, stream.Length - MaximumBytes);
            stream.Position = skipped;
            using var reader = new StreamReader(stream, new UTF8Encoding(false, true), true, 64 * 1024, leaveOpen: false);
            if (skipped > 0)
            {
                _ = reader.ReadLine();
            }

            var records = Parse(reader, startUtc, endUtc, cancellationToken).Take(MaximumRecords).ToArray();
            string detail = skipped > 0
                ? $"Parsed {records.Length} privacy-filtered sections from the final {MaximumBytes / (1024 * 1024)} MiB of SetupAPI history."
                : $"Parsed {records.Length} privacy-filtered SetupAPI installation {(records.Length == 1 ? "section" : "sections")}.";
            return new RecentChangeSourceResult(
                records,
                new CollectionStatus(source, CollectionState.Available, detail));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            return Denied(source);
        }
        catch (SecurityException)
        {
            return Denied(source);
        }
        catch (Exception exception) when (exception is IOException or DecoderFallbackException or ArgumentException)
        {
            return new RecentChangeSourceResult(
                [],
                new CollectionStatus(source, CollectionState.Error,
                    $"The SetupAPI device-installation log could not be parsed safely (0x{exception.HResult:X8})."));
        }
    }

    internal static IReadOnlyList<RecentSystemChange> Parse(
        TextReader reader,
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        CancellationToken cancellationToken)
    {
        var records = new List<RecentSystemChange>();
        string title = "Driver installation";
        DateTimeOffset? time = null;
        string publishedInf = string.Empty;
        string result = "Unknown";
        bool inSection = false;

        while (reader.ReadLine() is { } line)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (line.Length > 16 * 1024)
            {
                line = line[..(16 * 1024)];
            }

            Match header = SectionHeaderRegex().Match(line);
            if (header.Success)
            {
                Flush();
                inSection = true;
                string rawTitle = header.Groups["title"].Value;
                int identifierSeparator = rawTitle.IndexOf(" - ", StringComparison.Ordinal);
                title = RecentChangeCollector.SanitizeText(
                    identifierSeparator >= 0 ? rawTitle[..identifierSeparator] : rawTitle,
                    128);
                if (title.Length == 0)
                {
                    title = "Driver installation";
                }

                continue;
            }

            if (!inSection)
            {
                continue;
            }

            Match start = SectionStartRegex().Match(line);
            if (start.Success && TryParseLocalTimestamp(start.Groups["time"].Value, out DateTimeOffset parsed))
            {
                time = parsed.ToUniversalTime();
                continue;
            }

            Match inf = PublishedInfRegex().Match(line);
            if (inf.Success)
            {
                string basename = Path.GetFileName(inf.Groups["inf"].Value.Trim());
                publishedInf = SafeInfRegex().IsMatch(basename) ? basename : string.Empty;
                continue;
            }

            Match exit = ExitStatusRegex().Match(line);
            if (exit.Success)
            {
                result = exit.Groups["status"].Value.Contains("SUCCESS", StringComparison.OrdinalIgnoreCase)
                    ? "Succeeded"
                    : "Failed";
            }

            if (line.StartsWith("<<< [", StringComparison.Ordinal))
            {
                Flush();
            }
        }

        Flush();
        return records;

        void Flush()
        {
            if (inSection && time is not null && time >= startUtc && time <= endUtc)
            {
                records.Add(new RecentSystemChange(
                    time.Value,
                    RecentChangeKind.DriverInstallation,
                    title,
                    publishedInf.Length == 0 ? "Plug and Play installation" : $"Published {publishedInf}",
                    result,
                    string.Empty));
            }

            inSection = false;
            title = "Driver installation";
            time = null;
            publishedInf = string.Empty;
            result = "Unknown";
        }
    }

    private static bool TryParseLocalTimestamp(string value, out DateTimeOffset timestamp)
    {
        string[] formats = ["yyyy/MM/dd HH:mm:ss.fff", "yyyy/MM/dd HH:mm:ss"];
        if (DateTime.TryParseExact(
                value.Trim(),
                formats,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeLocal,
                out DateTime local))
        {
            timestamp = new DateTimeOffset(local);
            return true;
        }

        timestamp = default;
        return false;
    }

    private static RecentChangeSourceResult Denied(string source) =>
        new([], new CollectionStatus(source, CollectionState.Denied,
            "Windows denied access to the SetupAPI device-installation log."));

    [GeneratedRegex(@"^>>>\s*\[(?<title>[^\]]{1,1024})\]")]
    private static partial Regex SectionHeaderRegex();

    [GeneratedRegex(@"^>>>\s+Section start\s+(?<time>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{3})?)", RegexOptions.IgnoreCase)]
    private static partial Regex SectionStartRegex();

    [GeneratedRegex(@"(?i)Published\s+(?:Inf\s+)?(?:Name|Path)\s*[:=]\s*(?<inf>[^\r\n]+\.inf)\s*$")]
    private static partial Regex PublishedInfRegex();

    [GeneratedRegex(@"^oem\d+\.inf$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SafeInfRegex();

    [GeneratedRegex(@"^<<<\s*\[Exit status:\s*(?<status>[^\]]{1,128})\]", RegexOptions.IgnoreCase)]
    private static partial Regex ExitStatusRegex();
}
