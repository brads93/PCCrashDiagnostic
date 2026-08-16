using System.Buffers.Binary;
using System.Text.Json;
using BF6CrashDiagnostic.Core;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class DumpQualityCollectorTests
{
    [Beta2Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task InspectAsync_AcceptsBoundedMdmpDirectoryAndDoesNotNeedDebugger()
    {
        using var directory = new TestDirectory();
        DumpCandidate candidate = await WriteMiniDumpAsync(directory.Path, directoryRva: 32);
        var collector = new DumpQualityCollector(
            new FakeCommandRunner(new BoundedCommandResult(0, string.Empty, string.Empty, false, false, false)),
            new AllowDumpChkValidator(),
            TimeProvider.System);

        DumpQuality result = await collector.InspectAsync(new DumpQualityRequest(candidate));

        Assert.Equal(DumpFormat.MiniDump, result.Format);
        Assert.Equal(DumpQualityClassification.Valid, result.Classification);
        Assert.Equal(DumpInternalQualityState.Valid, result.InternalState);
        Assert.True(result.SignatureRecognized);
        Assert.True(result.SizePlausible);
        Assert.True(result.MiniDumpDirectoryBoundsValid);
        Assert.Equal(DumpChkState.NotRequested, result.DumpChkState);
    }

    [Beta2Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task InspectAsync_RejectsMdmpDirectoryOutsideFile()
    {
        using var directory = new TestDirectory();
        DumpCandidate candidate = await WriteMiniDumpAsync(directory.Path, directoryRva: 4_096);
        var collector = new DumpQualityCollector(
            new FakeCommandRunner(new BoundedCommandResult(0, string.Empty, string.Empty, false, false, false)),
            new AllowDumpChkValidator(),
            TimeProvider.System);

        DumpQuality result = await collector.InspectAsync(new DumpQualityRequest(candidate));

        Assert.Equal(DumpInternalQualityState.Invalid, result.InternalState);
        Assert.Equal(DumpQualityClassification.Truncated, result.Classification);
        Assert.False(result.MiniDumpDirectoryBoundsValid);
    }

    [Beta2Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task InspectAsync_ExposesEveryFriendlyQualityClassification()
    {
        using var directory = new TestDirectory();
        var collector = new DumpQualityCollector(
            new FakeCommandRunner(new BoundedCommandResult(0, string.Empty, string.Empty, false, false, false)),
            new AllowDumpChkValidator(),
            TimeProvider.System);

        string kernelPath = Path.Combine(directory.Path, "kernel.dmp");
        byte[] kernel = new byte[4_096];
        "PAGEDU64"u8.CopyTo(kernel);
        await File.WriteAllBytesAsync(kernelPath, kernel);
        DumpQuality recognized = await collector.InspectAsync(new DumpQualityRequest(CandidateForPath(kernelPath)));

        string corruptPath = Path.Combine(directory.Path, "corrupt.dmp");
        await File.WriteAllBytesAsync(corruptPath, new byte[32]);
        DumpQuality corrupt = await collector.InspectAsync(new DumpQualityRequest(CandidateForPath(corruptPath)));

        string missingPath = Path.Combine(directory.Path, "missing.dmp");
        DumpQuality inaccessible = await collector.InspectAsync(new DumpQualityRequest(CandidateForPath(missingPath)));

        var invalidPathCandidate = new DumpCandidate(
            DumpKind.WindowsMemoryDump,
            "test",
            "invalid.dmp",
            "<redacted>",
            0,
            DateTimeOffset.MinValue,
            DumpFormat.Unknown,
            DumpInspectionState.Unavailable,
            0,
            false,
            "test",
            "\0");
        DumpQuality unavailable = await collector.InspectAsync(new DumpQualityRequest(invalidPathCandidate));

        Assert.Equal(DumpQualityClassification.Recognized, recognized.Classification);
        Assert.Equal(DumpQualityClassification.Corrupt, corrupt.Classification);
        Assert.Equal(DumpQualityClassification.Inaccessible, inaccessible.Classification);
        Assert.Equal(DumpQualityClassification.AnalysisUnavailable, unavailable.Classification);
    }

    [Beta2Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task InspectAsync_RunsOnlySelectedDumpThroughDumpChkAndDropsRawOutput()
    {
        using var directory = new TestDirectory();
        DumpCandidate candidate = await WriteMiniDumpAsync(directory.Path, directoryRva: 32);
        var runner = new FakeCommandRunner(new BoundedCommandResult(
            0,
            "Opened C:\\Users\\Alice\\private.dmp\nFinished dump check",
            "private debugger text",
            false,
            false,
            false));
        var collector = new DumpQualityCollector(runner, new AllowDumpChkValidator(), TimeProvider.System);
        var installation = new DumpChkInstallation(
            "C:\\Windows Kits\\10\\Debuggers\\x64\\dumpchk.exe",
            "10.0.1",
            "Windows SDK",
            true,
            true,
            "Microsoft");

        DumpQuality result = await collector.InspectAsync(
            new DumpQualityRequest(candidate, RunDumpChk: true, DumpChk: installation));

        Assert.Equal(DumpChkState.Passed, result.DumpChkState);
        Assert.NotNull(runner.Request);
        Assert.Equal([Path.GetFullPath(candidate.OriginalPath!)], runner.Request.Arguments);
        Assert.DoesNotContain("http", string.Join(' ', runner.Request.Arguments), StringComparison.OrdinalIgnoreCase);
        string json = JsonSerializer.Serialize(result);
        Assert.DoesNotContain("Alice", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("private debugger text", json, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [Trait("Category", "SyntheticScenario")]
    public async Task InspectAsync_RefusesDumpChkUnlessTokenIsConfirmedStandardUser(
        bool elevated)
    {
        UserTokenElevationState tokenState = elevated
            ? UserTokenElevationState.Elevated
            : UserTokenElevationState.Unavailable;
        using var directory = new TestDirectory();
        DumpCandidate candidate = await WriteMiniDumpAsync(directory.Path, directoryRva: 32);
        var runner = new FakeCommandRunner(new BoundedCommandResult(
            0,
            "Finished dump check",
            string.Empty,
            false,
            false,
            false));
        var collector = new DumpQualityCollector(
            runner,
            new AllowDumpChkValidator(),
            TimeProvider.System,
            new FixedTokenInspector(tokenState));

        DumpQuality result = await collector.InspectAsync(new DumpQualityRequest(
            candidate,
            RunDumpChk: true,
            new DumpChkInstallation("C:\\approved\\dumpchk.exe", "10.0.1", "Windows SDK", true, true, "Microsoft")));

        Assert.Equal(DumpChkState.Rejected, result.DumpChkState);
        Assert.Contains(
            tokenState == UserTokenElevationState.Elevated ? "elevated" : "standard-user",
            result.Detail,
            StringComparison.OrdinalIgnoreCase);
        Assert.Null(runner.Request);
    }

    [Beta2Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task Coordinator_DumpChkRefreshesBoundReportWithoutExportingRawOutput()
    {
        using var directory = new TestDirectory();
        DumpCandidate candidate = await WriteMiniDumpAsync(directory.Path, directoryRva: 32);
        var runner = new FakeCommandRunner(new BoundedCommandResult(
            0,
            "Opened C:\\Users\\Alice\\private.dmp\nFinished dump check",
            "private debugger text",
            false,
            false,
            false));
        var collector = new DumpQualityCollector(runner, new AllowDumpChkValidator(), TimeProvider.System);
        var installation = new DumpChkInstallation(
            "C:\\approved\\dumpchk.exe",
            "10.0.1",
            "Windows SDK",
            true,
            true,
            "Microsoft");
        using var coordinator = new PCCrashDiagnosticCoordinator(
            directory.Path,
            static (_, _) => Task.CompletedTask,
            elevatedHelperClient: null,
            protectedEvidenceHelper: null,
            helperRequestStore: null,
            isBf6RunningFailClosed: () => false,
            protectedDumpPathValidator: null,
            dumpQualityCollector: collector,
            discoverInstalledDumpCheckers: () => [installation]);
        DiagnosticOperationResultV3 prior = CreateBoundReport(directory.Path, candidate);

        DiagnosticOperationResultV3 result = await coordinator.RunOptionalDumpCheckAsync(prior, candidate);

        Assert.Equal(DumpChkState.Passed, result.Package.Report.DumpQuality?.DumpChkState);
        Assert.Same(candidate, result.Package.Report.CrashCorrelation?.SelectedDump);
        Assert.False(result.DumpSelectionRequired);
        Assert.NotNull(runner.Request);
        Assert.True(File.Exists(Path.Combine(result.Package.SessionFolder, "Dump-Quality.json")));
        string serialized = JsonSerializer.Serialize(result.Package.Report);
        Assert.DoesNotContain("Alice", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("private debugger text", serialized, StringComparison.OrdinalIgnoreCase);
    }

    [Beta2Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task InspectAsync_MapsDumpChkTimeoutWithoutRetainingOutput()
    {
        using var directory = new TestDirectory();
        DumpCandidate candidate = await WriteMiniDumpAsync(directory.Path, directoryRva: 32);
        var collector = new DumpQualityCollector(
            new FakeCommandRunner(new BoundedCommandResult(null, "partial", "partial", true, false, false)),
            new AllowDumpChkValidator(),
            TimeProvider.System);

        DumpQuality result = await collector.InspectAsync(new DumpQualityRequest(
            candidate,
            RunDumpChk: true,
            new DumpChkInstallation("C:\\approved\\dumpchk.exe", "10.0.1", "Windows SDK", true, true, "Microsoft")));

        Assert.Equal(DumpChkState.TimedOut, result.DumpChkState);
        Assert.DoesNotContain("partial", JsonSerializer.Serialize(result), StringComparison.OrdinalIgnoreCase);
    }

    [Beta2Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task InspectAsync_CancelsDumpChkWhenProtectedTargetStarts()
    {
        using var directory = new TestDirectory();
        DumpCandidate candidate = await WriteMiniDumpAsync(directory.Path, directoryRva: 32);
        var runner = new CancellationObservingRunner();
        var collector = new DumpQualityCollector(runner, new AllowDumpChkValidator(), TimeProvider.System);
        int protectedTargetRunning = 0;

        Task<DumpQuality> inspection = collector.InspectAsync(
            new DumpQualityRequest(
                candidate,
                RunDumpChk: true,
                new DumpChkInstallation("C:\\approved\\dumpchk.exe", "10.0.1", "Windows SDK", true, true, "Microsoft"),
                TimeSpan.FromMinutes(1)),
            CancellationToken.None,
            () => Volatile.Read(ref protectedTargetRunning) != 0);

        await runner.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Interlocked.Exchange(ref protectedTargetRunning, 1);
        DumpQuality result = await inspection.WaitAsync(TimeSpan.FromSeconds(5));

        Assert.True(runner.CancellationObserved);
        Assert.Equal(DumpQualityClassification.AnalysisUnavailable, result.Classification);
        Assert.Contains("protected target", result.Detail, StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<DumpCandidate> WriteMiniDumpAsync(string root, uint directoryRva)
    {
        string path = Path.Combine(root, "fixture.dmp");
        byte[] bytes = new byte[44];
        "MDMP"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(8, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(12, 4), directoryRva);
        await File.WriteAllBytesAsync(path, bytes);
        var info = new FileInfo(path);
        return new DumpCandidate(
            DumpKind.ApplicationDump,
            "test",
            info.Name,
            "<redacted>",
            info.Length,
            info.LastWriteTimeUtc,
            DumpFormat.MiniDump,
            DumpInspectionState.Recognized,
            32,
            true,
            "test",
            path);
    }

    private static DumpCandidate CandidateForPath(string path)
    {
        var info = new FileInfo(path);
        return new DumpCandidate(
            DumpKind.WindowsMemoryDump,
            "test",
            info.Name,
            "<redacted>",
            info.Exists ? info.Length : 0,
            info.Exists ? info.LastWriteTimeUtc : DateTimeOffset.MinValue,
            DumpFormat.Unknown,
            DumpInspectionState.Recognized,
            0,
            false,
            "test",
            path);
    }

    private static DiagnosticOperationResultV3 CreateBoundReport(string root, DumpCandidate candidate)
    {
        DateTimeOffset time = candidate.LastWriteUtc;
        IncidentFingerprint fingerprint = IncidentFingerprint.Create(
            IncidentKind.Bugcheck,
            time,
            "Microsoft-Windows-WER-SystemErrorReporting",
            1001);
        var correlation = new CrashCorrelation(
            fingerprint,
            null,
            candidate,
            CrashCorrelationBasis.TimestampProximity,
            TimeSpan.Zero,
            [candidate],
            "Synthetic correlation.");
        var report = new DiagnosticReportV3(
            3,
            PCCrashDiagnosticCoordinator.ToolVersion,
            PCCrashDiagnosticCoordinator.ProductName,
            "dumpchk-test-session",
            DiagnosticMode.Retrospective,
            time.AddMinutes(-1),
            time.AddMinutes(1),
            "SelectedIncidentAnalyzed",
            null,
            null,
            null,
            null,
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            null,
            new DumpInventory([candidate], []),
            null,
            correlation,
            null,
            fingerprint,
            "Synthetic report.");
        var package = new ReportPackageV3(
            report,
            Path.Combine(root, "Sessions", "dumpchk-test-session"),
            Path.Combine(root, "Reports", "dumpchk-test.zip"),
            Path.Combine(root, "Reports", "dumpchk-test.zip.sha256"),
            new string('a', 64));
        return new DiagnosticOperationResultV3(package, [candidate], false, []);
    }

    private sealed class FakeCommandRunner(BoundedCommandResult result) : IBoundedCommandRunner
    {
        public BoundedCommandRequest? Request { get; private set; }

        public Task<BoundedCommandResult> RunAsync(
            BoundedCommandRequest request,
            CancellationToken cancellationToken)
        {
            Request = request;
            return Task.FromResult(result);
        }
    }

    private sealed class CancellationObservingRunner : IBoundedCommandRunner
    {
        public TaskCompletionSource Started { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool CancellationObserved { get; private set; }

        public async Task<BoundedCommandResult> RunAsync(
            BoundedCommandRequest request,
            CancellationToken cancellationToken)
        {
            Started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
                throw new InvalidOperationException("The test command should only finish by cancellation.");
            }
            catch (OperationCanceledException)
            {
                CancellationObserved = true;
                return new BoundedCommandResult(null, string.Empty, string.Empty, false, true, false);
            }
        }
    }

    private sealed class AllowDumpChkValidator : IDumpChkRequestValidator
    {
        public bool IsAllowed(DumpChkInstallation installation) => true;
    }

    private sealed class FixedTokenInspector(UserTokenElevationState state) : IUserTokenInspector
    {
        public UserTokenElevationState GetElevationState() => state;
    }
}
