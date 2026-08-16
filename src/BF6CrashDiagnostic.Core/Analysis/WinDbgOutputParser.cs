using System.Text.RegularExpressions;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Analysis;

internal sealed record ParsedDebuggerOutput(
    string BugcheckCode,
    IReadOnlyList<string> BugcheckParameters,
    string FailureBucket,
    string ModuleName,
    string ImageName,
    string ProcessName,
    string SymbolStatus,
    IReadOnlyList<string> StackModules,
    IReadOnlyList<string> BlackboxAvailable,
    DebuggerBlackboxBootStatus? BlackboxBootStatus,
    IReadOnlyList<DebuggerServiceControlRequest> BlackboxServiceControlRequests);

/// <summary>
/// Extracts only the fields explicitly allowed in the standard report. The
/// debugger's original output is never returned by this parser.
/// </summary>
internal static partial class WinDbgOutputParser
{
    internal const string BeginBlackboxBsd = "PCD_BEGIN_BLACKBOXBSD";
    internal const string EndBlackboxBsd = "PCD_END_BLACKBOXBSD";
    internal const string BeginBlackboxScm = "PCD_BEGIN_BLACKBOXSCM";
    internal const string EndBlackboxScm = "PCD_END_BLACKBOXSCM";
    private const int MaximumFieldLength = 256;
    private const int MaximumStackModules = 16;
    private const int MaximumServiceRequests = 16;

    public static ParsedDebuggerOutput Parse(string output)
    {
        output ??= string.Empty;
        string bugcheckCode = string.Empty;
        var parameters = new string[4];
        string failureBucket = string.Empty;
        string moduleName = string.Empty;
        string imageName = string.Empty;
        string processName = string.Empty;
        bool symbolsUnavailable = false;
        bool symbolWarning = false;
        bool inStack = false;
        var stackModules = new List<string>();
        var seenStackModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var blackboxAvailable = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        BlackboxSection blackboxSection = BlackboxSection.None;
        bool sawBootField = false;
        bool? lastBootSucceeded = null;
        bool? lastBootShutdown = null;
        bool? sleepInProgress = null;
        bool? connectedStandbyInProgress = null;
        bool? userShutdownInProgress = null;
        bool? systemShutdownInProgress = null;
        bool? powerButtonShutdownInProgress = null;
        uint? bootAttemptCount = null;
        uint? lastBootId = null;
        uint? lastSuccessfulShutdownBootId = null;
        uint? lastReportedAbnormalShutdownBootId = null;
        var serviceRequests = new List<DebuggerServiceControlRequest>();
        string pendingServiceName = string.Empty;

        using var reader = new StringReader(output);
        while (reader.ReadLine() is { } line)
        {
            if (line.Length > 16 * 1024)
            {
                line = line[..(16 * 1024)];
            }

            string trimmed = line.Trim();
            if (trimmed.Contains(BeginBlackboxBsd, StringComparison.Ordinal))
            {
                blackboxSection = BlackboxSection.BootStatus;
                continue;
            }

            if (trimmed.Contains(EndBlackboxBsd, StringComparison.Ordinal))
            {
                blackboxSection = BlackboxSection.None;
                continue;
            }

            if (trimmed.Contains(BeginBlackboxScm, StringComparison.Ordinal))
            {
                blackboxSection = BlackboxSection.ServiceControlManager;
                continue;
            }

            if (trimmed.Contains(EndBlackboxScm, StringComparison.Ordinal))
            {
                FlushServiceRequest();
                blackboxSection = BlackboxSection.None;
                continue;
            }

            Match availability = BlackboxAvailabilityRegex().Match(trimmed);
            if (availability.Success && availability.Groups["value"].Value == "1")
            {
                blackboxAvailable.Add(availability.Groups["name"].Value.ToUpperInvariant());
            }

            if (blackboxSection == BlackboxSection.BootStatus)
            {
                if (TryReadField(trimmed, "Last boot succeeded", out string bootValue))
                {
                    lastBootSucceeded = ParseBoolean(bootValue);
                    sawBootField = true;
                }
                else if (TryReadField(trimmed, "Last boot shutdown", out bootValue))
                {
                    lastBootShutdown = ParseBoolean(bootValue);
                    sawBootField = true;
                }
                else if (TryReadField(trimmed, "Sleep in progress", out bootValue))
                {
                    sleepInProgress = ParseBoolean(bootValue);
                    sawBootField = true;
                }
                else if (TryReadField(trimmed, "Connected standby in progress", out bootValue))
                {
                    connectedStandbyInProgress = ParseBoolean(bootValue);
                    sawBootField = true;
                }
                else if (TryReadField(trimmed, "User shutdown in progress", out bootValue))
                {
                    userShutdownInProgress = ParseBoolean(bootValue);
                    sawBootField = true;
                }
                else if (TryReadField(trimmed, "System shutdown in progress", out bootValue))
                {
                    systemShutdownInProgress = ParseBoolean(bootValue);
                    sawBootField = true;
                }
                else if (TryReadField(trimmed, "Power button shutdown in progress", out bootValue))
                {
                    powerButtonShutdownInProgress = ParseBoolean(bootValue);
                    sawBootField = true;
                }
                else if (TryReadField(trimmed, "Boot attempt count", out bootValue))
                {
                    bootAttemptCount = ParseUInt32(bootValue);
                    sawBootField = true;
                }
                else if (TryReadField(trimmed, "Last boot id", out bootValue))
                {
                    lastBootId = ParseUInt32(bootValue);
                    sawBootField = true;
                }
                else if (TryReadField(trimmed, "Last successful shutdown boot id", out bootValue))
                {
                    lastSuccessfulShutdownBootId = ParseUInt32(bootValue);
                    sawBootField = true;
                }
                else if (TryReadField(trimmed, "Last reported abnormal shutdown boot id", out bootValue))
                {
                    lastReportedAbnormalShutdownBootId = ParseUInt32(bootValue);
                    sawBootField = true;
                }

                continue;
            }

            if (blackboxSection == BlackboxSection.ServiceControlManager)
            {
                if (TryReadField(trimmed, "Name", out string serviceValue))
                {
                    FlushServiceRequest();
                    pendingServiceName = SanitizeServiceName(serviceValue);
                }
                else if (TryReadField(trimmed, "Code", out serviceValue) && pendingServiceName.Length > 0)
                {
                    if (serviceRequests.Count < MaximumServiceRequests)
                    {
                        serviceRequests.Add(new DebuggerServiceControlRequest(
                            pendingServiceName,
                            ParseUInt32(serviceValue)));
                    }

                    pendingServiceName = string.Empty;
                }

                continue;
            }

            if (trimmed.StartsWith("BugCheck ", StringComparison.OrdinalIgnoreCase))
            {
                Match match = BugCheckLineRegex().Match(trimmed);
                if (match.Success)
                {
                    bugcheckCode = NormalizeHex(match.Groups["code"].Value);
                    string[] inlineParameters = match.Groups["parameters"].Value.Split(',');
                    for (int index = 0; index < Math.Min(4, inlineParameters.Length); index++)
                    {
                        parameters[index] = NormalizeHex(inlineParameters[index]);
                    }
                }
            }
            else if (TryReadField(trimmed, "BUGCHECK_CODE", out string value))
            {
                bugcheckCode = NormalizeHex(value);
            }
            else if (TryReadIndexedField(trimmed, "BUGCHECK_P", out int parameterIndex, out value))
            {
                parameters[parameterIndex] = NormalizeHex(value);
            }
            else if (TryReadField(trimmed, "FAILURE_BUCKET_ID", out value))
            {
                failureBucket = SanitizeIdentifier(value, allowBang: true);
            }
            else if (TryReadField(trimmed, "MODULE_NAME", out value))
            {
                moduleName = SanitizeBasename(value, removeExtension: false);
            }
            else if (TryReadField(trimmed, "IMAGE_NAME", out value))
            {
                imageName = SanitizeBasename(value, removeExtension: false);
            }
            else if (TryReadField(trimmed, "PROCESS_NAME", out value))
            {
                processName = SanitizeBasename(value, removeExtension: false);
            }

            if (trimmed.Equals("STACK_TEXT:", StringComparison.OrdinalIgnoreCase))
            {
                inStack = true;
                continue;
            }

            if (inStack)
            {
                if (trimmed.Length == 0 || ReportFieldRegex().IsMatch(trimmed))
                {
                    inStack = false;
                }
                else
                {
                    foreach (Match match in StackModuleRegex().Matches(trimmed))
                    {
                        string name = SanitizeBasename(match.Groups["module"].Value, removeExtension: true);
                        if (name.Length > 0 && seenStackModules.Add(name))
                        {
                            stackModules.Add(name);
                            if (stackModules.Count == MaximumStackModules)
                            {
                                inStack = false;
                                break;
                            }
                        }
                    }
                }
            }

            if (trimmed.Contains("Unable to load image", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Contains("symbols could not be loaded", StringComparison.OrdinalIgnoreCase) ||
                trimmed.Contains("symbol file could not be found", StringComparison.OrdinalIgnoreCase))
            {
                symbolsUnavailable = true;
            }
            else if (trimmed.Contains("Unable to verify timestamp", StringComparison.OrdinalIgnoreCase) ||
                     trimmed.Contains("mismatched", StringComparison.OrdinalIgnoreCase))
            {
                symbolWarning = true;
            }
        }

        FlushServiceRequest();

        string symbolStatus = symbolsUnavailable
            ? "Unavailable"
            : symbolWarning
                ? "Incomplete"
                : (!string.IsNullOrEmpty(moduleName) || stackModules.Count > 0)
                    ? "Loaded"
                    : "Not reported";

        DebuggerBlackboxBootStatus? bootStatus = sawBootField
            ? new DebuggerBlackboxBootStatus(
                lastBootSucceeded,
                lastBootShutdown,
                sleepInProgress,
                connectedStandbyInProgress,
                userShutdownInProgress,
                systemShutdownInProgress,
                powerButtonShutdownInProgress,
                bootAttemptCount,
                lastBootId,
                lastSuccessfulShutdownBootId,
                lastReportedAbnormalShutdownBootId)
            : null;
        if (bootStatus is not null)
        {
            blackboxAvailable.Add("BSD");
        }

        if (serviceRequests.Count > 0)
        {
            blackboxAvailable.Add("SCM");
        }

        return new ParsedDebuggerOutput(
            bugcheckCode,
            parameters.Where(parameter => !string.IsNullOrEmpty(parameter)).ToArray(),
            failureBucket,
            moduleName,
            imageName,
            processName,
            symbolStatus,
            stackModules,
            blackboxAvailable.OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToArray(),
            bootStatus,
            serviceRequests);

        void FlushServiceRequest()
        {
            if (pendingServiceName.Length > 0 && serviceRequests.Count < MaximumServiceRequests)
            {
                serviceRequests.Add(new DebuggerServiceControlRequest(pendingServiceName, null));
            }

            pendingServiceName = string.Empty;
        }
    }

    private static bool? ParseBoolean(string value)
    {
        string candidate = value.Trim();
        if (candidate.Equals("TRUE", StringComparison.OrdinalIgnoreCase) || candidate == "1")
        {
            return true;
        }

        if (candidate.Equals("FALSE", StringComparison.OrdinalIgnoreCase) || candidate == "0")
        {
            return false;
        }

        return null;
    }

    private static uint? ParseUInt32(string value)
    {
        string candidate = value.Trim();
        System.Globalization.NumberStyles style = System.Globalization.NumberStyles.Integer;
        if (candidate.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            candidate = candidate[2..];
            style = System.Globalization.NumberStyles.AllowHexSpecifier;
        }

        return uint.TryParse(
            candidate,
            style,
            System.Globalization.CultureInfo.InvariantCulture,
            out uint parsed)
            ? parsed
            : null;
    }

    private static string SanitizeServiceName(string value)
    {
        string candidate = value.Trim().Trim('"', '\'');
        if (candidate.Length == 0 || candidate.Length > 128)
        {
            return string.Empty;
        }

        return candidate.All(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '-' or '.')
            ? candidate
            : string.Empty;
    }

    private static bool TryReadField(string line, string name, out string value)
    {
        value = string.Empty;
        if (!line.StartsWith(name, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        int colon = line.IndexOf(':');
        if (colon != name.Length)
        {
            return false;
        }

        value = line[(colon + 1)..].Trim();
        return true;
    }

    private static bool TryReadIndexedField(string line, string prefix, out int index, out string value)
    {
        index = -1;
        value = string.Empty;
        if (line.Length < prefix.Length + 2 ||
            !line.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
            line[prefix.Length] is < '1' or > '4' ||
            line[prefix.Length + 1] != ':')
        {
            return false;
        }

        index = line[prefix.Length] - '1';
        value = line[(prefix.Length + 2)..].Trim();
        return true;
    }

    private static string NormalizeHex(string value)
    {
        string candidate = value.Trim().Trim('{', '}', ',', ';');
        if (candidate.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            candidate = candidate[2..];
        }

        candidate = new string(candidate.TakeWhile(Uri.IsHexDigit).ToArray());
        if (candidate.Length == 0 || candidate.Length > 16)
        {
            return string.Empty;
        }

        candidate = candidate.TrimStart('0');
        return "0x" + (candidate.Length == 0 ? "0" : candidate.ToUpperInvariant());
    }

    private static string SanitizeBasename(string value, bool removeExtension)
    {
        string candidate = value.Trim().Trim('"', '\'');
        candidate = candidate.Replace('\\', '/');
        candidate = candidate[(candidate.LastIndexOf('/') + 1)..];
        candidate = SanitizeIdentifier(candidate, allowBang: false);
        return removeExtension ? Path.GetFileNameWithoutExtension(candidate) : candidate;
    }

    private static string SanitizeIdentifier(string value, bool allowBang)
    {
        IEnumerable<char> characters = value.Trim().Take(MaximumFieldLength).Where(character =>
            char.IsAsciiLetterOrDigit(character) ||
            character is '_' or '-' or '.' or '+' ||
            (allowBang && character == '!'));
        return new string(characters.ToArray());
    }

    [GeneratedRegex(@"^BugCheck\s+(?<code>(?:0x)?[0-9a-fA-F]+)\s*,\s*\{(?<parameters>[^}]*)\}", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BugCheckLineRegex();

    [GeneratedRegex(@"^(?:[A-Z][A-Z0-9_]{2,40}):", RegexOptions.CultureInvariant)]
    private static partial Regex ReportFieldRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9_.-])(?<module>[A-Za-z0-9_.-]{1,128})!", RegexOptions.CultureInvariant)]
    private static partial Regex StackModuleRegex();

    [GeneratedRegex(@"^BLACKBOX(?<name>BSD|SCM|PNP|NTFS|WINLOGON)\s*:\s*(?<value>[01])\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex BlackboxAvailabilityRegex();

    private enum BlackboxSection
    {
        None,
        BootStatus,
        ServiceControlManager
    }
}
