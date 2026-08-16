using System.Globalization;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Analysis;

public static class BugcheckRecordDecoder
{
    public static bool TryDecode(DiagnosticEvent diagnosticEvent, out BugcheckRecord record)
    {
        ArgumentNullException.ThrowIfNull(diagnosticEvent);

        BugcheckEvidenceSource source = IdentifySource(diagnosticEvent);
        if (source == BugcheckEvidenceSource.Unknown)
        {
            record = null!;
            return false;
        }

        string? rawCode = FirstNonEmpty(
            diagnosticEvent.Data,
            "BugcheckCode",
            "BugCheckCode",
            "param1",
            "P1");
        if (source == BugcheckEvidenceSource.KernelPower && IsZeroLike(rawCode))
        {
            record = null!;
            return false;
        }

        uint? code = TryParseUInt32(rawCode, out uint parsedCode) ? parsedCode : null;
        string normalizedCode = code is null
            ? string.IsNullOrWhiteSpace(rawCode) ? "Unknown" : NormalizeBounded(rawCode!, 64)
            : $"0x{code.Value:X8}";
        ulong?[] parameters = Enumerable.Range(1, 4)
            .Select(index => ParseParameter(diagnosticEvent.Data, index))
            .ToArray();
        string? dumpPath = FirstNonEmpty(diagnosticEvent.Data, "DumpFile", "DumpPath", "param6", "P6");

        record = new BugcheckRecord(
            diagnosticEvent.TimeUtc.ToUniversalTime(),
            source,
            diagnosticEvent.ProviderName,
            diagnosticEvent.EventId,
            string.IsNullOrWhiteSpace(rawCode) ? string.Empty : NormalizeBounded(rawCode!, 64),
            code,
            normalizedCode,
            parameters,
            EvidencePathRedactor.FileName(dumpPath),
            EvidencePathRedactor.Redact(dumpPath),
            dumpPath);
        return true;
    }

    public static IReadOnlyList<BugcheckRecord> Decode(IEnumerable<DiagnosticEvent> events)
    {
        ArgumentNullException.ThrowIfNull(events);
        var records = new List<BugcheckRecord>();
        foreach (DiagnosticEvent diagnosticEvent in events)
        {
            if (TryDecode(diagnosticEvent, out BugcheckRecord record))
            {
                records.Add(record);
            }
        }

        return records
            .OrderBy(record => record.TimeUtc)
            .ThenBy(record => record.EvidenceSource)
            .ToArray();
    }

    private static BugcheckEvidenceSource IdentifySource(DiagnosticEvent item)
    {
        if (item.EventId == 1001 &&
            (item.ProviderName.Contains("SystemErrorReporting", StringComparison.OrdinalIgnoreCase) ||
             item.ProviderName.Contains("BugCheck", StringComparison.OrdinalIgnoreCase) ||
             item.Message.Contains("bugcheck", StringComparison.OrdinalIgnoreCase) ||
             item.Message.Contains("BlueScreen", StringComparison.OrdinalIgnoreCase)))
        {
            return BugcheckEvidenceSource.WindowsErrorReporting;
        }

        return item.EventId == 41 &&
               item.ProviderName.Contains("Kernel-Power", StringComparison.OrdinalIgnoreCase)
            ? BugcheckEvidenceSource.KernelPower
            : BugcheckEvidenceSource.Unknown;
    }

    private static ulong? ParseParameter(IReadOnlyDictionary<string, string> data, int index)
    {
        string? value = FirstNonEmpty(
            data,
            $"BugcheckParameter{index}",
            $"BugCheckParameter{index}",
            $"param{index + 1}",
            $"P{index + 1}");
        return TryParseUInt64(value, out ulong parsed) ? parsed : null;
    }

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

    private static bool TryParseUInt32(string? value, out uint result)
    {
        if (!TryParseUInt64(value, out ulong parsed) || parsed > uint.MaxValue)
        {
            result = 0;
            return false;
        }

        result = (uint)parsed;
        return true;
    }

    private static bool TryParseUInt64(string? value, out ulong result)
    {
        result = 0;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        string trimmed = value.Trim();
        NumberStyles style = NumberStyles.Integer;
        if (trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            trimmed = trimmed[2..];
            style = NumberStyles.AllowHexSpecifier;
        }

        return trimmed.Length > 0 && ulong.TryParse(trimmed, style, CultureInfo.InvariantCulture, out result);
    }

    private static bool IsZeroLike(string? value) =>
        (TryParseUInt64(value, out ulong parsed) && parsed == 0) || string.IsNullOrWhiteSpace(value);

    private static string NormalizeBounded(string value, int maximumLength)
    {
        string collapsed = string.Join(' ', value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return collapsed.Length <= maximumLength ? collapsed : collapsed[..maximumLength];
    }
}
