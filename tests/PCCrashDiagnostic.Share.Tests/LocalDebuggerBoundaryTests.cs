using System.ComponentModel;
using System.Diagnostics;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;
using PCCrashDiagnostic.LocalTools;

namespace PCCrashDiagnostic.Share.Tests;

public sealed class LocalDebuggerBoundaryTests
{
    [Fact]
    public async Task BoundedCommandRunnerTerminatesChildWhenJobAssignmentFails()
    {
        string powershell = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.System),
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe");
        Assert.True(File.Exists(powershell), $"Required Windows test process was not found: {powershell}");

        Process? observedChild = null;
        var runner = new BoundedCommandRunner((_, process) =>
        {
            observedChild = Process.GetProcessById(process.Id);
            throw new Win32Exception(5, "Synthetic job-assignment failure.");
        });

        try
        {
            await Assert.ThrowsAsync<Win32Exception>(() => runner.RunAsync(
                new BoundedCommandRequest(
                    powershell,
                    ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30"],
                    TimeSpan.FromMinutes(1)),
                CancellationToken.None));

            Assert.NotNull(observedChild);
            await observedChild.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(observedChild.HasExited);
        }
        finally
        {
            if (observedChild is not null)
            {
                try
                {
                    if (!observedChild.HasExited)
                    {
                        observedChild.Kill(entireProcessTree: true);
                    }
                }
                catch (InvalidOperationException)
                {
                }
                catch (Win32Exception)
                {
                }

                observedChild.Dispose();
            }
        }
    }

    [Theory]
    [InlineData("BF6")]
    [InlineData("EAAntiCheat")]
    [InlineData("EAAntiCheat.GameService")]
    [InlineData("EAAntiCheat.GameServiceLauncher")]
    [InlineData("EAAntiCheatService")]
    [InlineData("Javelin")]
    public async Task DumpInspectionFailsClosedForEveryProtectedAlias(string runningProcess)
    {
        using var directory = new BF6CrashDiagnostic.Tests.TestDirectory();
        LocalDebuggerService service = CreateService(
            directory.Path,
            processName => processName.Equals(runningProcess, StringComparison.OrdinalIgnoreCase));

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.InspectDumpQualityAsync(Candidate(directory.Path), runInstalledDumpChk: false));

        Assert.Contains("unavailable while", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task LocalToolBoundaryFailsClosedWhenProcessPredicateThrows()
    {
        using var directory = new BF6CrashDiagnostic.Tests.TestDirectory();
        LocalDebuggerService service = CreateService(
            directory.Path,
            _ => throw new InvalidOperationException("Synthetic process-query failure."));
        DumpCandidate dump = Candidate(directory.Path);

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.InspectDumpQualityAsync(dump, runInstalledDumpChk: false));
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => service.RunWinDbgAnalysisAsync(dump, "share-boundary-test", allowMicrosoftSymbolDownload: false));
    }

    [Fact]
    public async Task DumpInspectionStopsWhenProtectedProcessAppearsAfterInitialCheck()
    {
        using var directory = new BF6CrashDiagnostic.Tests.TestDirectory();
        int completedSweeps = 0;
        LocalDebuggerService service = CreateService(directory.Path, processName =>
        {
            if (processName.Equals("Javelin", StringComparison.OrdinalIgnoreCase))
            {
                Interlocked.Increment(ref completedSweeps);
                return false;
            }

            return Volatile.Read(ref completedSweeps) > 0 &&
                   processName.Equals("BF6", StringComparison.OrdinalIgnoreCase);
        });

        DumpQuality result = await service.InspectDumpQualityAsync(
            Candidate(directory.Path),
            runInstalledDumpChk: false);

        Assert.Equal(DumpQualityClassification.AnalysisUnavailable, result.Classification);
        Assert.Equal(DumpInternalQualityState.Unavailable, result.InternalState);
        Assert.Contains("protected target", result.Detail, StringComparison.OrdinalIgnoreCase);
        Assert.True(Volatile.Read(ref completedSweeps) >= 1);
    }

    [Fact]
    public async Task WinDbgIsBlockedBeforeDebuggerDiscoveryForProtectedAlias()
    {
        using var directory = new BF6CrashDiagnostic.Tests.TestDirectory();
        int discoveryCalls = 0;
        var service = new LocalDebuggerService(
            directory.Path,
            () =>
            {
                Interlocked.Increment(ref discoveryCalls);
                return [];
            },
            static () => [],
            new WinDbgRunner(),
            new DumpQualityCollector(),
            processName => processName.Equals("EAAntiCheat.GameService", StringComparison.OrdinalIgnoreCase));

        await Assert.ThrowsAsync<InvalidOperationException>(() => service.RunWinDbgAnalysisAsync(
            Candidate(directory.Path),
            "share-boundary-test",
            allowMicrosoftSymbolDownload: false));

        Assert.Equal(0, Volatile.Read(ref discoveryCalls));
    }

    private static LocalDebuggerService CreateService(string root, Func<string, bool> isProcessRunning) => new(
        root,
        static () => [],
        static () => [],
        new WinDbgRunner(),
        new DumpQualityCollector(),
        isProcessRunning);

    private static DumpCandidate Candidate(string root) => new(
        DumpKind.WindowsMinidump,
        "Test fixture",
        "test.dmp",
        "<dump-root>\\test.dmp",
        32,
        DateTimeOffset.UtcNow,
        DumpFormat.MiniDump,
        DumpInspectionState.Recognized,
        32,
        true,
        "Synthetic boundary-only candidate.",
        Path.Combine(root, "test.dmp"));
}
