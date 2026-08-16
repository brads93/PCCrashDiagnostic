using System.Diagnostics;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;

namespace PCCrashDiagnostic.LocalTools;

public sealed record DumpCheckerAvailability(
    bool IsAvailable,
    string Version,
    string Source,
    string Detail);

/// <summary>
/// Standard-user boundary for optional, locally installed Microsoft diagnostic
/// tools. It never installs a tool, elevates, stages a protected dump, or starts
/// a debugger while BF6, EA AntiCheat, Javelin, or the selected protected target
/// is running.
/// </summary>
public interface ILocalDebuggerService
{
    DebuggerAvailability InspectDebuggerAvailability();

    DumpCheckerAvailability InspectDumpCheckerAvailability();

    Task<DumpQuality> InspectDumpQualityAsync(
        DumpCandidate dump,
        bool runInstalledDumpChk,
        TargetProfile? targetProfile = null,
        CancellationToken cancellationToken = default);

    Task<DebuggerAnalysis> RunWinDbgAnalysisAsync(
        DumpCandidate dump,
        string reportSessionId,
        bool allowMicrosoftSymbolDownload,
        TargetProfile? targetProfile = null,
        CancellationToken cancellationToken = default);
}

public sealed class LocalDebuggerService : ILocalDebuggerService
{
    private readonly string _dataRoot;
    private readonly Func<IReadOnlyList<CdbInstallation>> _discoverDebuggers;
    private readonly Func<IReadOnlyList<DumpChkInstallation>> _discoverDumpCheckers;
    private readonly WinDbgRunner _winDbg;
    private readonly DumpQualityCollector _dumpQuality;
    private readonly Func<string, bool> _isProcessRunning;

    public LocalDebuggerService(string dataRoot)
        : this(
            dataRoot,
            static () => new CdbDiscovery().Discover(),
            static () => new DumpChkDiscovery().Discover(),
            new WinDbgRunner(),
            new DumpQualityCollector(),
            IsProcessRunningFailClosed)
    {
    }

    internal LocalDebuggerService(
        string dataRoot,
        Func<IReadOnlyList<CdbInstallation>> discoverDebuggers,
        Func<IReadOnlyList<DumpChkInstallation>> discoverDumpCheckers,
        WinDbgRunner winDbg,
        DumpQualityCollector dumpQuality,
        Func<string, bool> isProcessRunning)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        if (!Path.IsPathFullyQualified(dataRoot))
        {
            throw new ArgumentException("The local-tools data root must be absolute.", nameof(dataRoot));
        }

        _dataRoot = Path.GetFullPath(dataRoot);
        _discoverDebuggers = discoverDebuggers ?? throw new ArgumentNullException(nameof(discoverDebuggers));
        _discoverDumpCheckers = discoverDumpCheckers ?? throw new ArgumentNullException(nameof(discoverDumpCheckers));
        _winDbg = winDbg ?? throw new ArgumentNullException(nameof(winDbg));
        _dumpQuality = dumpQuality ?? throw new ArgumentNullException(nameof(dumpQuality));
        _isProcessRunning = isProcessRunning ?? throw new ArgumentNullException(nameof(isProcessRunning));
    }

    public DebuggerAvailability InspectDebuggerAvailability()
    {
        CdbInstallation? debugger = DiscoverDebugger();
        return debugger is null
            ? new DebuggerAvailability(
                DebuggerAvailabilityState.NotFound,
                string.Empty,
                "Microsoft WinDbg",
                "No Microsoft-signed x64 cdb.exe was found in WinDbg or the Windows SDK. WinDbg is optional and is never installed automatically.")
            : new DebuggerAvailability(
                DebuggerAvailabilityState.Available,
                debugger.Version,
                debugger.Source,
                "A Microsoft-signed x64 WinDbg command-line tool is available for optional local analysis.");
    }

    public DumpCheckerAvailability InspectDumpCheckerAvailability()
    {
        DumpChkInstallation? dumpChk = DiscoverDumpChecker();
        return dumpChk is null
            ? new DumpCheckerAvailability(
                false,
                string.Empty,
                "Windows SDK",
                "Microsoft DumpChk was not found in an approved Windows SDK directory. The built-in bounded header check remains available.")
            : new DumpCheckerAvailability(
                true,
                dumpChk.Version,
                dumpChk.Source,
                "A Microsoft-signed x64 DumpChk tool is available for optional offline validation.");
    }

    public Task<DumpQuality> InspectDumpQualityAsync(
        DumpCandidate dump,
        bool runInstalledDumpChk,
        TargetProfile? targetProfile = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(dump);
        bool IsBlocked() => IsProtectedTargetRunning(targetProfile);
        if (IsBlocked())
        {
            throw new InvalidOperationException(
                "Dump inspection is unavailable while BF6, EA AntiCheat, Javelin, or the selected protected target is running.");
        }

        DumpChkInstallation? dumpChk = runInstalledDumpChk ? DiscoverDumpChecker() : null;
        return _dumpQuality.InspectAsync(
            new DumpQualityRequest(
                dump,
                RunDumpChk: runInstalledDumpChk,
                DumpChk: dumpChk,
                Timeout: TimeSpan.FromMinutes(1)),
            cancellationToken,
            IsBlocked);
    }

    public Task<DebuggerAnalysis> RunWinDbgAnalysisAsync(
        DumpCandidate dump,
        string reportSessionId,
        bool allowMicrosoftSymbolDownload,
        TargetProfile? targetProfile = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(dump);
        if (!SessionIdValidator.IsValid(reportSessionId))
        {
            throw new ArgumentException("The report session identity is invalid.", nameof(reportSessionId));
        }

        bool IsBlocked() => IsProtectedTargetRunning(targetProfile);
        if (IsBlocked())
        {
            throw new InvalidOperationException(
                "WinDbg analysis is unavailable while BF6, EA AntiCheat, Javelin, or the selected protected target is running.");
        }

        // Discovery verifies an approved path, x64 PE architecture and a trusted
        // Microsoft signature. WinDbgRunner independently repeats that validation
        // immediately before launch.
        CdbInstallation? debugger = DiscoverDebugger();
        if (debugger is null)
        {
            return Task.FromResult(new DebuggerAnalysis(
                DebuggerAnalysisState.DebuggerNotFound,
                null,
                DateTimeOffset.UtcNow,
                SymbolAccessMode.LocalOnly,
                string.Empty,
                string.Empty,
                string.Empty,
                [],
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                [],
                "No Microsoft-signed x64 cdb.exe was found. WinDbg is optional and was not installed automatically."));
        }

        SymbolAccessMode symbolAccess = allowMicrosoftSymbolDownload
            ? SymbolAccessMode.MicrosoftPublicServer
            : SymbolAccessMode.LocalOnly;
        string symbolCache = Path.Combine(_dataRoot, "Symbols", "Microsoft");
        string rawLogs = Path.Combine(_dataRoot, "DebuggerLogs", reportSessionId);
        return _winDbg.AnalyzeAsync(
            new WinDbgAnalysisRequest(
                dump,
                debugger,
                symbolAccess,
                symbolCache,
                rawLogs,
                allowMicrosoftSymbolDownload,
                TimeSpan.FromMinutes(2),
                IsBlocked),
            cancellationToken);
    }

    private CdbInstallation? DiscoverDebugger() => _discoverDebuggers()
        .Where(item => item.IsMicrosoftSigned && item.IsX64)
        .OrderByDescending(item => ParseVersion(item.Version))
        .ThenBy(item => item.Source, StringComparer.OrdinalIgnoreCase)
        .FirstOrDefault();

    private DumpChkInstallation? DiscoverDumpChecker() => _discoverDumpCheckers()
        .Where(item => item.IsMicrosoftSigned && item.IsX64)
        .OrderByDescending(item => ParseVersion(item.Version))
        .ThenBy(item => item.Source, StringComparer.OrdinalIgnoreCase)
        .FirstOrDefault();

    private bool IsProtectedTargetRunning(TargetProfile? targetProfile) =>
        ProtectedProcessGuard.IsBlocked(targetProfile, _isProcessRunning);

    private static Version ParseVersion(string value) =>
        Version.TryParse(value, out Version? parsed) ? parsed : new Version(0, 0);

    private static bool IsProcessRunningFailClosed(string processName)
    {
        Process[] matches = Process.GetProcessesByName(ProtectedProcessGuard.NormalizeProcessName(processName));
        try
        {
            return matches.Any(process =>
            {
                try
                {
                    return !process.HasExited;
                }
                catch
                {
                    return true;
                }
            });
        }
        finally
        {
            foreach (Process process in matches)
            {
                process.Dispose();
            }
        }
    }
}
