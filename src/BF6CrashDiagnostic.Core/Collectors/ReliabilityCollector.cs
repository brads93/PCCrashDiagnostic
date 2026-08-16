using System.Globalization;
using System.Management;
using System.Security;
using System.Text;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Collectors;

/// <summary>
/// Reads filtered Reliability Monitor metadata from Win32_ReliabilityRecords.
/// </summary>
public sealed class ReliabilityCollector
{
    private const int MaximumRecords = 512;
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(10);

    public Task<ReliabilityCollection> CollectAsync(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        CancellationToken cancellationToken = default)
        => CollectAsync(startUtc, endUtc, TargetProfile.Battlefield6, cancellationToken);

    public Task<ReliabilityCollection> CollectAsync(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        TargetProfile? targetProfile,
        CancellationToken cancellationToken = default)
    {
        ValidateWindow(startUtc, endUtc);
        return Task.Run(
            () => Collect(startUtc.ToUniversalTime(), endUtc.ToUniversalTime(), targetProfile, cancellationToken),
            cancellationToken);
    }

    private static ReliabilityCollection Collect(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        TargetProfile? targetProfile,
        CancellationToken cancellationToken)
    {
        const string source = "Reliability Monitor/Win32_ReliabilityRecords";
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            string start = ManagementDateTimeConverter.ToDmtfDateTime(startUtc.UtcDateTime);
            string end = ManagementDateTimeConverter.ToDmtfDateTime(endUtc.UtcDateTime);
            string query = "SELECT TimeGenerated, SourceName, ProductName, EventIdentifier, Message " +
                $"FROM Win32_ReliabilityRecords WHERE TimeGenerated >= '{start}' AND TimeGenerated <= '{end}'";

            using var searcher = new ManagementObjectSearcher("root\\cimv2", query);
            searcher.Options.Timeout = QueryTimeout;
            using ManagementObjectCollection results = searcher.Get();
            var records = new List<ReliabilityRecord>();
            bool truncated = false;
            foreach (ManagementBaseObject item in results)
            {
                using (item)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    DateTimeOffset? timestamp = ParseWmiDate(Value(item, "TimeGenerated"));
                    if (timestamp is null || timestamp < startUtc || timestamp > endUtc)
                    {
                        continue;
                    }

                    string sourceName = Value(item, "SourceName") ?? "Unknown";
                    string productName = Value(item, "ProductName") ?? "Unknown";
                    string eventIdentifier = Value(item, "EventIdentifier") ?? "Unknown";
                    string message = CollapseWhitespace(Value(item, "Message") ?? string.Empty, 4_096);
                    if (!IsRelevant(sourceName, productName, eventIdentifier, message, targetProfile))
                    {
                        continue;
                    }

                    if (records.Count >= MaximumRecords)
                    {
                        truncated = true;
                        break;
                    }

                    records.Add(new ReliabilityRecord(
                        timestamp.Value,
                        sourceName,
                        productName,
                        eventIdentifier,
                        message));
                }
            }

            ReliabilityRecord[] ordered = records
                .OrderBy(item => item.TimeUtc)
                .ThenBy(item => item.ProductName, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            string detail = truncated
                ? $"Collected {MaximumRecords} relevant metadata records; additional matches were not read."
                : $"Collected {ordered.Length} relevant metadata {(ordered.Length == 1 ? "record" : "records")}.";
            return new ReliabilityCollection(
                ordered,
                [new CollectionStatus(source, CollectionState.Available, detail)]);
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
        catch (ManagementException exception)
        {
            CollectionState state = exception.ErrorCode switch
            {
                ManagementStatus.InvalidClass or ManagementStatus.NotFound => CollectionState.Unavailable,
                ManagementStatus.Timedout => CollectionState.TimedOut,
                _ => CollectionState.Error
            };
            return new ReliabilityCollection(
                [],
                [new CollectionStatus(
                    source,
                    state,
                    $"Windows Management Instrumentation returned {exception.ErrorCode}.")]);
        }
        catch (PlatformNotSupportedException)
        {
            return new ReliabilityCollection(
                [],
                [new CollectionStatus(
                    source,
                    CollectionState.Unavailable,
                    "Reliability Monitor data is unavailable on this platform.")]);
        }
        catch (InvalidOperationException exception)
        {
            return new ReliabilityCollection(
                [],
                [new CollectionStatus(
                    source,
                    CollectionState.Error,
                    $"Reliability Monitor data could not be read (0x{exception.HResult:X8}).")]);
        }
    }

    private static ReliabilityCollection Denied(string source) => new(
        [],
        [new CollectionStatus(
            source,
            CollectionState.Denied,
            "Windows denied access. The collector did not request elevation.")]);

    private static bool IsRelevant(
        string sourceName,
        string productName,
        string eventIdentifier,
        string message,
        TargetProfile? targetProfile)
    {
        string text = string.Join(' ', sourceName, productName, eventIdentifier, message);
        if (DiagnosticSignalClassifier.IsDiagnosticToolSelfSignal(text))
        {
            return false;
        }

        if (targetProfile?.MatchesReliabilityEvidence(text) == true)
        {
            return true;
        }

        if (ContainsAny(eventIdentifier, "BlueScreen", "LiveKernelEvent", "HardwareError"))
        {
            return true;
        }

        return ContainsAny(
            text,
            "Windows Hardware Error",
            "VIDEO_ENGINE_TIMEOUT",
            "VIDEO_TDR_TIMEOUT",
            "display driver",
            "nvlddmkm",
            "amdwddmg",
            "amdkmdag");
    }

    private static bool ContainsAny(string text, params string[] needles) =>
        needles.Any(needle => text.Contains(needle, StringComparison.OrdinalIgnoreCase));

    private static string? Value(ManagementBaseObject item, string propertyName)
    {
        string? value = Convert.ToString(item[propertyName], CultureInfo.InvariantCulture)?.Trim();
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private static DateTimeOffset? ParseWmiDate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        try
        {
            return new DateTimeOffset(ManagementDateTimeConverter.ToDateTime(value).ToUniversalTime());
        }
        catch (ArgumentOutOfRangeException)
        {
            return null;
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private static string CollapseWhitespace(string value, int maximumLength)
    {
        var builder = new StringBuilder(Math.Min(value.Length, maximumLength));
        bool previousWasWhitespace = false;
        foreach (char character in value)
        {
            bool whitespace = char.IsWhiteSpace(character);
            if (whitespace)
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
            throw new ArgumentOutOfRangeException(nameof(endUtc), "The end of the reliability window precedes its start.");
        }
    }
}
