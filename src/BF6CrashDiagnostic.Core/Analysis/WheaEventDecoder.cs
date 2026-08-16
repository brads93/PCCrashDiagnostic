using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Analysis;

/// <summary>
/// Produces a small, privacy-bounded view of WHEA event data. The rendered event message,
/// unnamed parameters, binary error records, device paths, and all unknown fields are omitted.
/// </summary>
public static class WheaEventDecoder
{
    private const int MaximumLabelLength = 96;
    private const int MaximumNumericLength = 20;

    private static readonly FieldRule[] FieldRules =
    [
        new("ErrorSource", ValueKind.CodeOrLabel),
        new("ErrorType", ValueKind.CodeOrLabel),
        new("OperationType", ValueKind.CodeOrLabel),
        new("TransactionType", ValueKind.CodeOrLabel),
        new("Participation", ValueKind.CodeOrLabel),
        new("RequestType", ValueKind.CodeOrLabel),
        new("MemorIO", ValueKind.CodeOrLabel),
        new("MemoryHierarchyLvl", ValueKind.CodeOrLabel),
        new("ApicId", ValueKind.Numeric),
        new("MCABank", ValueKind.Numeric),
        new("MciStat", ValueKind.Numeric),
        new("MciAddr", ValueKind.Numeric),
        new("MciMisc", ValueKind.Numeric),
        new("Timeout", ValueKind.Numeric),
        new("Channel", ValueKind.Numeric),
        new("Length", ValueKind.Numeric),
        new("CperSectionCategories", ValueKind.CodeOrLabel)
    ];

    public static bool TryDecode(
        DiagnosticEvent diagnosticEvent,
        [NotNullWhen(true)] out DecodedWheaEvent? decoded)
    {
        ArgumentNullException.ThrowIfNull(diagnosticEvent);

        if (!WheaEventCatalog.IsProvider(diagnosticEvent.ProviderName, diagnosticEvent.ProviderGuid))
        {
            decoded = null;
            return false;
        }

        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (FieldRule rule in FieldRules)
        {
            string? value = GetUnambiguousValue(diagnosticEvent.Data, rule.Name);
            string? normalized = Normalize(value, rule.Kind);
            if (normalized is not null)
            {
                fields.Add(rule.Name, normalized);
            }
        }

        decoded = new DecodedWheaEvent(
            diagnosticEvent.EventId,
            WheaEventCatalog.Classify(diagnosticEvent.EventId),
            new ReadOnlyDictionary<string, string>(fields));
        return true;
    }

    private static string? GetUnambiguousValue(
        IReadOnlyDictionary<string, string> data,
        string name)
    {
        string[] values = data
            .Where(pair => pair.Key.Equals(name, StringComparison.OrdinalIgnoreCase))
            .Select(pair => pair.Value)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal)
            .Take(2)
            .ToArray();

        return values.Length == 1 ? values[0] : null;
    }

    private static string? Normalize(string? value, ValueKind kind)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        string collapsed = CollapseWhitespace(value);
        return kind == ValueKind.Numeric
            ? NormalizeNumeric(collapsed)
            : NormalizeCodeOrLabel(collapsed);
    }

    private static string? NormalizeNumeric(string value)
    {
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            string digits = value[2..];
            return digits.Length is > 0 and <= 16 && digits.All(Uri.IsHexDigit)
                ? "0x" + digits.ToUpperInvariant()
                : null;
        }

        return value.Length <= MaximumNumericLength && value.All(char.IsAsciiDigit)
            ? value
            : null;
    }

    private static string? NormalizeCodeOrLabel(string value)
    {
        if (value.Length > MaximumLabelLength || ContainsPrivateLocator(value) || LooksLikeBlob(value))
        {
            return null;
        }

        foreach (char character in value)
        {
            if (char.IsLetterOrDigit(character) || character == ' ' || character is '-' or '_' or '.' or ',' or ':' or '/' or '(' or ')' or '[' or ']')
            {
                continue;
            }

            return null;
        }

        return value;
    }

    private static bool ContainsPrivateLocator(string value)
    {
        if (value.Contains('\\') || value.Contains('@') || value.Contains("://", StringComparison.Ordinal))
        {
            return true;
        }

        return value.Length >= 3 &&
            char.IsAsciiLetter(value[0]) &&
            value[1] == ':' &&
            value[2] == '/';
    }

    private static bool LooksLikeBlob(string value)
    {
        string compact = new(value.Where(character => !char.IsWhiteSpace(character)).ToArray());
        if (compact.Length <= MaximumNumericLength)
        {
            return false;
        }

        string withoutPrefix = compact.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? compact[2..]
            : compact;
        return withoutPrefix.Length > MaximumNumericLength && withoutPrefix.All(Uri.IsHexDigit);
    }

    private static string CollapseWhitespace(string value)
    {
        var result = new char[Math.Min(value.Length, MaximumLabelLength + 1)];
        int written = 0;
        bool pendingSpace = false;

        foreach (char character in value.Trim())
        {
            if (char.IsWhiteSpace(character))
            {
                pendingSpace = written > 0;
                continue;
            }

            if (pendingSpace)
            {
                if (written == result.Length)
                {
                    return new string(result);
                }

                result[written++] = ' ';
                pendingSpace = false;
            }

            if (written == result.Length)
            {
                return new string(result);
            }

            result[written++] = character;
        }

        return new string(result, 0, written);
    }

    private sealed record FieldRule(string Name, ValueKind Kind);

    private enum ValueKind
    {
        Numeric,
        CodeOrLabel
    }
}

public sealed record DecodedWheaEvent(
    int EventId,
    WheaEventClassification Classification,
    IReadOnlyDictionary<string, string> Fields);
