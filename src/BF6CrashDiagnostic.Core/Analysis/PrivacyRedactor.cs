using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Analysis;

public sealed class PrivacyRedactor
{
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromSeconds(1);
    private static readonly Regex SidRegex = new(@"(?i)\bS-1-(?:\d+-){1,14}\d+\b", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex EmailRegex = new(@"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex Ipv4Regex = new(@"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex Ipv6Regex = new(@"(?i)(?<![0-9A-F:])(?:(?:[0-9A-F]{1,4}:){3,7}[0-9A-F]{0,4}|(?:[0-9A-F]{0,4}:){1,7}:[0-9A-F]{0,4})(?![0-9A-F:])", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex MacRegex = new(@"(?i)(?<![0-9A-F])(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}(?![0-9A-F])", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex GuidRegex = new(@"(?i)(?<![0-9A-F])[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}(?![0-9A-F])", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex ProfilePathRegex = new(@"(?i)\b[A-Z]:\\Users\\[^\\\s""']+", RegexOptions.Compiled, RegexTimeout);
    private static readonly Regex WhitespaceRegex = new(@"\s+", RegexOptions.Compiled, RegexTimeout);
    private readonly IReadOnlyList<(string Value, string Replacement, bool TokenBounded)> _literalReplacements;

    public PrivacyRedactor()
        : this(Environment.UserName, Environment.MachineName, Environment.UserDomainName,
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile))
    {
    }

    public PrivacyRedactor(string? userName, string? machineName, string? domainName, string? profilePath)
    {
        var replacements = new List<(string Value, string Replacement, bool TokenBounded)>();
        AddReplacement(replacements, profilePath, "[REDACTED-PROFILE]", tokenBounded: false);
        AddReplacement(replacements, userName, "[REDACTED-USER]", tokenBounded: true);
        AddReplacement(replacements, machineName, "[REDACTED-COMPUTER]", tokenBounded: true);
        if (!string.Equals(domainName, machineName, StringComparison.OrdinalIgnoreCase))
        {
            AddReplacement(replacements, domainName, "[REDACTED-DOMAIN]", tokenBounded: true);
        }

        _literalReplacements = replacements
            .OrderByDescending(item => item.Value.Length)
            .ToArray();
    }

    public string Redact(string? value, bool redactGuids = true)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value ?? string.Empty;
        }

        string safe = ProfilePathRegex.Replace(value, "[REDACTED-PROFILE]");
        safe = SidRegex.Replace(safe, "[REDACTED-SID]");
        safe = EmailRegex.Replace(safe, "[REDACTED-EMAIL]");
        safe = MacRegex.Replace(safe, "[REDACTED-MAC]");
        safe = Ipv4Regex.Replace(safe, "[REDACTED-IP]");
        safe = Ipv6Regex.Replace(safe, "[REDACTED-IP]");
        if (redactGuids)
        {
            safe = GuidRegex.Replace(safe, "[REDACTED-GUID]");
        }

        foreach ((string literal, string replacement, bool tokenBounded) in _literalReplacements)
        {
            string pattern = tokenBounded
                ? $@"(?<![\p{{L}}\p{{M}}\p{{N}}\p{{Pc}}]){Regex.Escape(literal)}(?![\p{{L}}\p{{M}}\p{{N}}\p{{Pc}}])"
                : Regex.Escape(literal);
            safe = Regex.Replace(safe, pattern, replacement,
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, RegexTimeout);
        }

        return safe;
    }

    public string RedactPath(string? path) => Redact(path, redactGuids: true);

    public DiagnosticEvent RedactEvent(DiagnosticEvent diagnosticEvent)
    {
        var safeData = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (KeyValuePair<string, string> pair in diagnosticEvent.Data)
        {
            string safeKey = Redact(pair.Key);
            if (!safeData.TryAdd(safeKey, Redact(pair.Value)))
            {
                safeData[$"{safeKey}_{safeData.Count + 1}"] = Redact(pair.Value);
            }
        }

        return diagnosticEvent with
        {
            LogName = Redact(diagnosticEvent.LogName),
            ProviderName = Redact(diagnosticEvent.ProviderName),
            Message = Redact(diagnosticEvent.Message),
            Data = safeData
        };
    }

    public DuplicateEventGroup RedactGroup(DuplicateEventGroup group)
    {
        string safeProviderName = Redact(group.ProviderName);
        string safeMessage = Redact(group.Message);
        return group with
        {
            Key = CreateRedactedGroupKey(safeProviderName, group.ProviderGuid, group.EventId, safeMessage),
            ProviderName = safeProviderName,
            Message = safeMessage
        };
    }

    public DiagnosticFinding RedactFinding(DiagnosticFinding finding) => finding with
    {
        Category = Redact(finding.Category),
        Title = Redact(finding.Title),
        Evidence = Redact(finding.Evidence),
        Meaning = Redact(finding.Meaning),
        DoesNotProve = Redact(finding.DoesNotProve),
        NextCheck = Redact(finding.NextCheck)
    };

    public ReliabilityRecord RedactReliability(ReliabilityRecord record) => record with
    {
        SourceName = Redact(record.SourceName),
        ProductName = Redact(record.ProductName),
        EventIdentifier = Redact(record.EventIdentifier),
        Message = Redact(record.Message)
    };

    public CollectionStatus RedactStatus(CollectionStatus status) => status with
    {
        Source = Redact(status.Source),
        Detail = Redact(status.Detail)
    };

    public CrashArtifact RedactArtifact(CrashArtifact artifact) => artifact with
    {
        Kind = Redact(artifact.Kind),
        Name = Redact(artifact.Name),
        RedactedPath = RedactPath(artifact.RedactedPath),
        OriginalPath = null
    };

    public CrashAnchor? RedactAnchor(CrashAnchor? anchor) => anchor is null ? null : anchor with
    {
        Source = Redact(anchor.Source),
        Description = Redact(anchor.Description),
        BugCheckCode = Redact(anchor.BugCheckCode),
        DumpPath = string.IsNullOrWhiteSpace(anchor.DumpPath) ? null : RedactPath(anchor.DumpPath)
    };

    private static string CreateRedactedGroupKey(
        string providerName,
        Guid? providerGuid,
        int eventId,
        string message)
    {
        string normalizedMessage = WhitespaceRegex.Replace(message.Trim(), " ").ToUpperInvariant();
        string identity = $"{providerName.ToUpperInvariant()}|{providerGuid}|{eventId}|{normalizedMessage}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity))).ToLowerInvariant();
    }

    private static void AddReplacement(
        List<(string Value, string Replacement, bool TokenBounded)> target,
        string? value,
        string replacement,
        bool tokenBounded)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            string literal = value.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            if (!string.IsNullOrEmpty(literal))
            {
                target.Add((literal, replacement, tokenBounded));
            }
        }
    }

}
