using System.ComponentModel;
using System.Text.RegularExpressions;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Collectors;

/// <summary>
/// Queries existing Driver Verifier settings with the documented /querysettings
/// operation. It never enables, changes, or resets Driver Verifier.
/// </summary>
public sealed partial class DriverVerifierCollector
{
    private readonly IBoundedCommandRunner _runner;
    private readonly IDriverVerifierExecutableValidator _validator;
    private readonly TimeProvider _timeProvider;
    private readonly string _executablePath;

    public DriverVerifierCollector()
        : this(
            new BoundedCommandRunner(),
            new DriverVerifierExecutableValidator(),
            TimeProvider.System,
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "verifier.exe"))
    {
    }

    internal DriverVerifierCollector(
        IBoundedCommandRunner runner,
        IDriverVerifierExecutableValidator validator,
        TimeProvider timeProvider,
        string executablePath)
    {
        _runner = runner;
        _validator = validator;
        _timeProvider = timeProvider;
        _executablePath = executablePath;
    }

    public async Task<DriverVerifierState> CollectAsync(CancellationToken cancellationToken = default)
    {
        DateTimeOffset captured = _timeProvider.GetUtcNow().ToUniversalTime();
        if (!File.Exists(_executablePath))
        {
            return new DriverVerifierState(
                captured,
                DriverVerifierStatusKind.Unavailable,
                string.Empty,
                [],
                "Windows Driver Verifier was unavailable.");
        }

        if (!_validator.IsAllowed(_executablePath))
        {
            return new DriverVerifierState(
                captured,
                DriverVerifierStatusKind.Rejected,
                string.Empty,
                [],
                "The Driver Verifier executable did not pass the fixed-path Microsoft signature check.");
        }

        try
        {
            BoundedCommandResult result = await _runner.RunAsync(
                new BoundedCommandRequest(
                    _executablePath,
                    ["/querysettings"],
                    TimeSpan.FromSeconds(15),
                    MaximumCharactersPerStream: 256 * 1024),
                cancellationToken).ConfigureAwait(false);
            if (result.Cancelled)
            {
                return CreateStatus(DriverVerifierStatusKind.Cancelled, string.Empty, [],
                    "The read-only Driver Verifier query was cancelled.");
            }

            if (result.TimedOut)
            {
                return CreateStatus(DriverVerifierStatusKind.TimedOut, string.Empty, [],
                    "The read-only Driver Verifier query timed out and its process tree was stopped.");
            }

            if (result.ExitCode != 0)
            {
                return CreateStatus(DriverVerifierStatusKind.Failed, string.Empty, [],
                    "Driver Verifier did not return its current settings.");
            }

            string output = result.StandardOutput + "\n" + result.StandardError;
            (DriverVerifierStatusKind status, string flags, IReadOnlyList<string> drivers) = Parse(output);
            string detail = status switch
            {
                DriverVerifierStatusKind.Enabled =>
                    "Windows reports existing Driver Verifier settings. This app did not change them.",
                DriverVerifierStatusKind.Disabled =>
                    "Windows reports that Driver Verifier is not currently verifying drivers.",
                _ => "Driver Verifier returned settings, but the bounded parser could not determine whether verification is active."
            };
            if (result.OutputTruncated)
            {
                detail += " Command output exceeded the local capture limit, so the driver list may be incomplete.";
            }

            return CreateStatus(status, flags, drivers, detail);
        }
        catch (OperationCanceledException)
        {
            return CreateStatus(DriverVerifierStatusKind.Cancelled, string.Empty, [],
                "The read-only Driver Verifier query was cancelled.");
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or Win32Exception)
        {
            return CreateStatus(DriverVerifierStatusKind.Failed, string.Empty, [],
                "The read-only Driver Verifier query could not be started or contained safely.");
        }

        DriverVerifierState CreateStatus(
            DriverVerifierStatusKind status,
            string flags,
            IReadOnlyList<string> drivers,
            string detail) => new(captured, status, flags, drivers, detail);
    }

    internal static (DriverVerifierStatusKind Status, string Flags, IReadOnlyList<string> Drivers) Parse(string output)
    {
        output ??= string.Empty;
        Match flagsMatch = FlagsRegex().Match(output);
        string flags = flagsMatch.Success
            ? NormalizeHex(flagsMatch.Groups["flags"].Value)
            : string.Empty;
        string[] drivers = DriverBasenameRegex().Matches(output)
            .Select(match => match.Groups["driver"].Value)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(value => value, StringComparer.OrdinalIgnoreCase)
            .Take(64)
            .ToArray();

        bool explicitDisabled = output.Contains("No drivers are currently verified", StringComparison.OrdinalIgnoreCase) ||
                                output.Contains("No drivers are currently being verified", StringComparison.OrdinalIgnoreCase);
        bool flagsEnabled = flags.Length > 0 && flags != "0x0";
        DriverVerifierStatusKind status = drivers.Length > 0 || flagsEnabled
            ? DriverVerifierStatusKind.Enabled
            : explicitDisabled || flags == "0x0"
                ? DriverVerifierStatusKind.Disabled
                : DriverVerifierStatusKind.Indeterminate;
        return (status, flags, drivers);
    }

    private static string NormalizeHex(string value)
    {
        string candidate = value.Trim();
        if (candidate.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            candidate = candidate[2..];
        }

        candidate = new(candidate.TakeWhile(Uri.IsHexDigit).ToArray());
        if (candidate.Length == 0 || candidate.Length > 16)
        {
            return string.Empty;
        }

        candidate = candidate.TrimStart('0');
        return "0x" + (candidate.Length == 0 ? "0" : candidate.ToUpperInvariant());
    }

    [GeneratedRegex(@"(?im)^\s*(?:Verifier\s+)?Flags\s*:\s*(?<flags>(?:0x)?[0-9a-f]+)\b", RegexOptions.CultureInvariant)]
    private static partial Regex FlagsRegex();

    [GeneratedRegex(@"(?i)(?<![A-Za-z0-9_.-])(?<driver>[A-Za-z0-9_.-]{1,120}\.sys)\b", RegexOptions.CultureInvariant)]
    private static partial Regex DriverBasenameRegex();
}

internal interface IDriverVerifierExecutableValidator
{
    bool IsAllowed(string path);
}

internal sealed class DriverVerifierExecutableValidator : IDriverVerifierExecutableValidator
{
    public bool IsAllowed(string path)
    {
        try
        {
            string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string expected = Path.GetFullPath(Path.Combine(windows, "System32", "verifier.exe"));
            string fullPath = Path.GetFullPath(path);
            if (!string.Equals(fullPath, expected, StringComparison.OrdinalIgnoreCase) ||
                FileSystemInfoHelpers.HasReparseComponent(Path.GetDirectoryName(expected)!, fullPath) ||
                !PeFileInspector.IsX64(fullPath))
            {
                return false;
            }

            return AuthenticodeTrust.TryGetTrustedSigner(fullPath, out string signer) &&
                   (signer.Contains("O=Microsoft Corporation", StringComparison.OrdinalIgnoreCase) ||
                    signer.Contains("CN=Microsoft Windows", StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            return false;
        }
    }
}
