using System.Text.Json;
using BF6CrashDiagnostic.Core;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class AdvancedDebuggerTests
{
    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public void OutputParser_ExtractsOnlyAllowlistedNormalizedFields()
    {
        const string output = """
            opened C:\Users\Alice\private\memory.dmp
            BugCheck 1a, {0000000000061941, ffff9, 0, deadbeef}
            BUGCHECK_CODE:  1a
            FAILURE_BUCKET_ID:  MEMORY_CORRUPTION_ONE_BIT
            MODULE_NAME: nvlddmkm
            IMAGE_NAME: C:\Windows\System32\DriverStore\nvlddmkm.sys
            PROCESS_NAME: C:\Games\BF6.exe
            STACK_TEXT:
            ffff0000 ffff1111 : nt!KeBugCheckEx
            ffff1111 ffff2222 : nvlddmkm!SomeFunction

            *** WARNING: Unable to verify timestamp for nvlddmkm.sys
            """;

        ParsedDebuggerOutput parsed = WinDbgOutputParser.Parse(output);

        Assert.Equal("0x1A", parsed.BugcheckCode);
        Assert.Equal(["0x61941", "0xFFFF9", "0x0", "0xDEADBEEF"], parsed.BugcheckParameters);
        Assert.Equal("MEMORY_CORRUPTION_ONE_BIT", parsed.FailureBucket);
        Assert.Equal("nvlddmkm", parsed.ModuleName);
        Assert.Equal("nvlddmkm.sys", parsed.ImageName);
        Assert.Equal("BF6.exe", parsed.ProcessName);
        Assert.Equal("Incomplete", parsed.SymbolStatus);
        Assert.Equal(["nt", "nvlddmkm"], parsed.StackModules);
        Assert.DoesNotContain("Alice", JsonSerializer.Serialize(parsed), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public void Discovery_RequiresExactApprovedCdbPathAndVerifiedX64MicrosoftBinary()
    {
        using var directory = new TestDirectory();
        string approvedRoot = Path.Combine(directory.Path, "Debuggers", "x64");
        Directory.CreateDirectory(approvedRoot);
        string approved = Path.Combine(approvedRoot, "cdb.exe");
        string nested = Path.Combine(approvedRoot, "nested", "cdb.exe");
        Directory.CreateDirectory(Path.GetDirectoryName(nested)!);
        WriteX64Pe(approved);
        WriteX64Pe(nested);

        var discovery = new CdbDiscovery(new FakeCdbVerifier(
            new CdbVerificationResult(true, true, "O=Microsoft Corporation", "10.0.1")));
        IReadOnlyList<CdbInstallation> result = discovery.DiscoverCandidates([
            new CdbCandidate(approved, approvedRoot, "Windows SDK"),
            new CdbCandidate(nested, approvedRoot, "Windows SDK")
        ]);

        CdbInstallation installation = Assert.Single(result);
        Assert.Equal(approved, installation.Path);
        Assert.True(installation.IsMicrosoftSigned);
        Assert.True(installation.IsX64);
    }

    [Fact]
    public void PeInspector_RejectsX86AndAcceptsAmd64()
    {
        using var directory = new TestDirectory();
        string x64 = Path.Combine(directory.Path, "x64.exe");
        string x86 = Path.Combine(directory.Path, "x86.exe");
        WritePe(x64, 0x8664);
        WritePe(x86, 0x014c);

        Assert.True(PeFileInspector.IsX64(x64));
        Assert.False(PeFileInspector.IsX64(x86));
    }

    [Fact]
    public void AuthenticodeTrust_ValidatesAndExtractsTrustedMicrosoftSigner()
    {
        string signedSystemBinary = Path.GetFullPath(Path.Combine(
            System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory(),
            "..",
            "..",
            "..",
            "dotnet.exe"));

        bool trusted = AuthenticodeTrust.TryGetTrustedSigner(signedSystemBinary, out string signer);

        Assert.True(trusted, signer);
        Assert.Contains("O=Microsoft Corporation", signer, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task Runner_UsesOfflineSymbolPathAndExcludesRawLogFromSerialization()
    {
        using var directory = new TestDirectory();
        DumpCandidate dump = await CreateDumpCandidateAsync(directory.Path);
        var host = new FakeProcessHost(new DebuggerProcessResult(
            0,
            "BUGCHECK_CODE: 1a\nMODULE_NAME: nt\nIMAGE_NAME: ntkrnlmp.exe\nPROCESS_NAME: game.exe",
            string.Empty,
            false,
            false,
            false));
        var runner = new WinDbgRunner(host, new AllowDebuggerValidator(), new StandardTokenInspector());
        WinDbgAnalysisRequest request = Request(directory.Path, dump, SymbolAccessMode.LocalOnly, consent: false);

        DebuggerAnalysis result = await runner.AnalyzeAsync(request, CancellationToken.None);

        Assert.Equal(DebuggerAnalysisState.Completed, result.State);
        Assert.NotNull(host.Invocation);
        Assert.DoesNotContain("http", host.Invocation.SymbolPath, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("!analyze -v", host.Invocation.CommandList, StringComparison.Ordinal);
        if (ReleaseStage.Beta2FeaturesEnabled)
        {
            Assert.Contains("!blackboxbsd", host.Invocation.CommandList, StringComparison.Ordinal);
            Assert.Contains("!blackboxscm", host.Invocation.CommandList, StringComparison.Ordinal);
        }
        else
        {
            Assert.DoesNotContain("!blackboxbsd", host.Invocation.CommandList, StringComparison.Ordinal);
            Assert.DoesNotContain("!blackboxscm", host.Invocation.CommandList, StringComparison.Ordinal);
        }
        Assert.DoesNotContain("!blackboxpnp", host.Invocation.CommandList, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("!blackboxntfs", host.Invocation.CommandList, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("!blackboxwinlogon", host.Invocation.CommandList, StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(result.LocalRawLogPath));
        string serialized = JsonSerializer.Serialize(result);
        Assert.DoesNotContain("LocalRawLogPath", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(result.LocalRawLogPath!, serialized, StringComparison.OrdinalIgnoreCase);
    }

    [Beta2Fact]
    [Trait("Category", "SyntheticScenario")]
    public void OutputParser_ExtractsOnlyBoundedDocumentedBlackboxFields()
    {
        const string output = """
            BLACKBOXBSD: 1 (!blackboxbsd)
            BLACKBOXPNP: 1 (!blackboxpnp)
            BLACKBOXNTFS: 1 (!blackboxntfs)
            PCD_BEGIN_BLACKBOXBSD
            Last boot succeeded: FALSE
            Last boot shutdown: TRUE
            Sleep in progress: 0
            Boot attempt count: 3
            Last boot id: 0x2A
            Private path: C:\Users\Alice\secret.txt
            PCD_END_BLACKBOXBSD
            PCD_BEGIN_BLACKBOXSCM
            Name: Safe_Service-1
            Code: 0x5
            Name: bad service C:\Users\Alice
            Code: 7
            PCD_END_BLACKBOXSCM
            """;

        ParsedDebuggerOutput parsed = WinDbgOutputParser.Parse(output);

        Assert.Equal(["BSD", "NTFS", "PNP", "SCM"], parsed.BlackboxAvailable);
        Assert.NotNull(parsed.BlackboxBootStatus);
        Assert.False(parsed.BlackboxBootStatus.LastBootSucceeded);
        Assert.True(parsed.BlackboxBootStatus.LastBootShutdown);
        Assert.False(parsed.BlackboxBootStatus.SleepInProgress);
        Assert.Equal((uint)3, parsed.BlackboxBootStatus.BootAttemptCount);
        Assert.Equal((uint)42, parsed.BlackboxBootStatus.LastBootId);
        DebuggerServiceControlRequest request = Assert.Single(parsed.BlackboxServiceControlRequests);
        Assert.Equal("Safe_Service-1", request.ServiceName);
        Assert.Equal((uint)5, request.ControlCode);
        string json = JsonSerializer.Serialize(parsed);
        Assert.DoesNotContain("Alice", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("secret.txt", json, StringComparison.OrdinalIgnoreCase);
    }

    [Beta2Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task Runner_ReportsCanonicalDebuggerBlackboxSummary()
    {
        using var directory = new TestDirectory();
        DumpCandidate dump = await CreateDumpCandidateAsync(directory.Path);
        const string output = """
            BLACKBOXBSD: 1 (!blackboxbsd)
            PCD_BEGIN_BLACKBOXBSD
            Last boot succeeded: TRUE
            Boot attempt count: 2
            PCD_END_BLACKBOXBSD
            """;
        var runner = new WinDbgRunner(
            new FakeProcessHost(new DebuggerProcessResult(0, output, string.Empty, false, false, false)),
            new AllowDebuggerValidator(),
            new StandardTokenInspector());

        DebuggerAnalysis result = await runner.AnalyzeAsync(
            Request(directory.Path, dump, SymbolAccessMode.LocalOnly, consent: false),
            CancellationToken.None);

        Assert.NotNull(result.Blackbox);
        Assert.Equal(["BSD"], result.Blackbox.AvailableSources);
        Assert.True(result.Blackbox.BootStatus?.LastBootSucceeded);
        string json = JsonSerializer.Serialize(result);
        Assert.Contains("\"Blackbox\"", json, StringComparison.Ordinal);
        Assert.Contains("\"AvailableSources\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("BlackboxAvailable", json, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task BoundedTextReader_RetainsLimitAndDrainsRemainingText()
    {
        const int limit = 64;
        string input = new('A', limit + 37);
        using var reader = new StringReader(input);

        BoundedTextReadResult result = await BoundedTextStreamReader.ReadAndDrainAsync(
            reader,
            limit,
            CancellationToken.None);

        Assert.Equal(limit, result.Text.Length);
        Assert.Equal(input[..limit], result.Text);
        Assert.True(result.Truncated);
        Assert.Equal(string.Empty, reader.ReadToEnd());
    }

    [Fact]
    public async Task BoundedTextReader_DoesNotMarkExactBoundaryAsTruncated()
    {
        const int limit = 64;
        string input = new('B', limit);
        using var reader = new StringReader(input);

        BoundedTextReadResult result = await BoundedTextStreamReader.ReadAndDrainAsync(
            reader,
            limit,
            CancellationToken.None);

        Assert.Equal(input, result.Text);
        Assert.False(result.Truncated);
        Assert.Equal(string.Empty, reader.ReadToEnd());
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task Runner_ReportsTruncatedDebuggerOutputInResultAndLocalLog()
    {
        using var directory = new TestDirectory();
        DumpCandidate dump = await CreateDumpCandidateAsync(directory.Path);
        var host = new FakeProcessHost(new DebuggerProcessResult(
            0,
            "BUGCHECK_CODE: 1a",
            "partial diagnostic text",
            false,
            false,
            false,
            StandardOutputTruncated: true,
            StandardErrorTruncated: true));
        var runner = new WinDbgRunner(host, new AllowDebuggerValidator(), new StandardTokenInspector());

        DebuggerAnalysis result = await runner.AnalyzeAsync(
            Request(directory.Path, dump, SymbolAccessMode.LocalOnly, consent: false),
            CancellationToken.None);

        Assert.Contains("output exceeded the local capture limit", result.Limitation, StringComparison.OrdinalIgnoreCase);
        string localLog = await File.ReadAllTextAsync(result.LocalRawLogPath!, CancellationToken.None);
        Assert.Contains("standard output exceeded", localLog, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("standard error exceeded", localLog, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("remaining output was discarded while the stream was drained", localLog, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task Runner_RequiresExplicitConsentBeforeMicrosoftSymbolEndpoint()
    {
        using var directory = new TestDirectory();
        DumpCandidate dump = await CreateDumpCandidateAsync(directory.Path);
        var host = new FakeProcessHost(new DebuggerProcessResult(0, string.Empty, string.Empty, false, false, false));
        var runner = new WinDbgRunner(host, new AllowDebuggerValidator(), new StandardTokenInspector());

        DebuggerAnalysis denied = await runner.AnalyzeAsync(
            Request(directory.Path, dump, SymbolAccessMode.MicrosoftPublicServer, consent: false),
            CancellationToken.None);

        Assert.Equal(DebuggerAnalysisState.Failed, denied.State);
        Assert.Null(host.Invocation);

        DebuggerAnalysis allowed = await runner.AnalyzeAsync(
            Request(directory.Path, dump, SymbolAccessMode.MicrosoftPublicServer, consent: true),
            CancellationToken.None);

        Assert.Equal(DebuggerAnalysisState.Completed, allowed.State);
        Assert.Contains("https://msdl.microsoft.com/download/symbols", host.Invocation!.SymbolPath, StringComparison.Ordinal);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task Runner_BlocksBeforeLaunchWhenProtectedTargetIsRunning()
    {
        using var directory = new TestDirectory();
        DumpCandidate dump = await CreateDumpCandidateAsync(directory.Path);
        var host = new FakeProcessHost(new DebuggerProcessResult(0, string.Empty, string.Empty, false, false, false));
        var runner = new WinDbgRunner(host, new AllowDebuggerValidator(), new StandardTokenInspector());
        WinDbgAnalysisRequest request = Request(directory.Path, dump, SymbolAccessMode.LocalOnly, consent: false) with
        {
            IsProtectedTargetRunning = () => true
        };

        DebuggerAnalysis result = await runner.AnalyzeAsync(request, CancellationToken.None);

        Assert.Equal(DebuggerAnalysisState.BlockedWhileProtectedTargetRunning, result.State);
        Assert.Null(host.Invocation);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task Runner_RefusesToRunFromElevatedToken()
    {
        using var directory = new TestDirectory();
        DumpCandidate dump = await CreateDumpCandidateAsync(directory.Path);
        var host = new FakeProcessHost(new DebuggerProcessResult(0, string.Empty, string.Empty, false, false, false));
        var runner = new WinDbgRunner(host, new AllowDebuggerValidator(), new ElevatedTokenInspector());

        DebuggerAnalysis result = await runner.AnalyzeAsync(
            Request(directory.Path, dump, SymbolAccessMode.LocalOnly, consent: false),
            CancellationToken.None);

        Assert.Equal(DebuggerAnalysisState.Failed, result.State);
        Assert.Contains("never run from an elevated process", result.Limitation, StringComparison.OrdinalIgnoreCase);
        Assert.Null(host.Invocation);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task Runner_RefusesToRunWhenStandardUserTokenCannotBeVerified()
    {
        using var directory = new TestDirectory();
        DumpCandidate dump = await CreateDumpCandidateAsync(directory.Path);
        var host = new FakeProcessHost(new DebuggerProcessResult(0, string.Empty, string.Empty, false, false, false));
        var runner = new WinDbgRunner(host, new AllowDebuggerValidator(), new UnavailableTokenInspector());

        DebuggerAnalysis result = await runner.AnalyzeAsync(
            Request(directory.Path, dump, SymbolAccessMode.LocalOnly, consent: false),
            CancellationToken.None);

        Assert.Equal(DebuggerAnalysisState.Failed, result.State);
        Assert.Contains("could not verify", result.Limitation, StringComparison.OrdinalIgnoreCase);
        Assert.Null(host.Invocation);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task Runner_MapsTimeoutAndKeepsPartialFieldsInformational()
    {
        using var directory = new TestDirectory();
        DumpCandidate dump = await CreateDumpCandidateAsync(directory.Path);
        var host = new FakeProcessHost(new DebuggerProcessResult(
            null,
            "BUGCHECK_CODE: 119\nMODULE_NAME: partialdriver",
            string.Empty,
            TimedOut: true,
            Cancelled: false,
            ProtectedTargetStarted: false));
        var runner = new WinDbgRunner(host, new AllowDebuggerValidator(), new StandardTokenInspector());

        DebuggerAnalysis result = await runner.AnalyzeAsync(
            Request(directory.Path, dump, SymbolAccessMode.LocalOnly, consent: false),
            CancellationToken.None);

        Assert.Equal(DebuggerAnalysisState.TimedOut, result.State);
        Assert.Equal("0x119", result.BugcheckCode);
        Assert.Equal("partialdriver", result.ModuleName);
        Assert.Contains("time limit", result.Limitation, StringComparison.OrdinalIgnoreCase);
        Assert.True(File.Exists(result.LocalRawLogPath));
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task Runner_RejectsInvalidDebuggerSignatureBeforeHostLaunch()
    {
        using var directory = new TestDirectory();
        DumpCandidate dump = await CreateDumpCandidateAsync(directory.Path);
        var host = new FakeProcessHost(new DebuggerProcessResult(0, string.Empty, string.Empty, false, false, false));
        var runner = new WinDbgRunner(host, new DenyDebuggerValidator(), new StandardTokenInspector());

        DebuggerAnalysis result = await runner.AnalyzeAsync(
            Request(directory.Path, dump, SymbolAccessMode.LocalOnly, consent: false),
            CancellationToken.None);

        Assert.Equal(DebuggerAnalysisState.InvalidDebuggerSignature, result.State);
        Assert.Null(host.Invocation);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task Runner_MapsContainedHostCancellationWithoutDebuggerFields()
    {
        using var directory = new TestDirectory();
        DumpCandidate dump = await CreateDumpCandidateAsync(directory.Path);
        var runner = new WinDbgRunner(
            new CancellingProcessHost(),
            new AllowDebuggerValidator(),
            new StandardTokenInspector());

        DebuggerAnalysis result = await runner.AnalyzeAsync(
            Request(directory.Path, dump, SymbolAccessMode.LocalOnly, consent: false),
            CancellationToken.None);

        Assert.Equal(DebuggerAnalysisState.Cancelled, result.State);
        Assert.Empty(result.BugcheckCode);
        Assert.Empty(result.StackModules);
        Assert.Contains("process tree was stopped", result.Limitation, StringComparison.OrdinalIgnoreCase);
        Assert.Null(result.LocalRawLogPath);
    }

    private static WinDbgAnalysisRequest Request(
        string root,
        DumpCandidate dump,
        SymbolAccessMode mode,
        bool consent) =>
        new(
            dump,
            new CdbInstallation("C:\\approved\\cdb.exe", "10.0.1", "Windows SDK", true, true, "Microsoft"),
            mode,
            Path.Combine(root, "symbols"),
            Path.Combine(root, "logs"),
            consent,
            TimeSpan.FromSeconds(30),
            () => false);

    private static async Task<DumpCandidate> CreateDumpCandidateAsync(string root)
    {
        string path = Path.Combine(root, "fixture.dmp");
        await File.WriteAllBytesAsync(path, "MDMP"u8.ToArray(), CancellationToken.None);
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
            4,
            true,
            "test",
            path);
    }

    private static void WriteX64Pe(string path) => WritePe(path, 0x8664);

    private static void WritePe(string path, ushort machine)
    {
        byte[] bytes = new byte[512];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        BitConverter.GetBytes(0x80).CopyTo(bytes, 0x3c);
        bytes[0x80] = (byte)'P';
        bytes[0x81] = (byte)'E';
        BitConverter.GetBytes(machine).CopyTo(bytes, 0x84);
        File.WriteAllBytes(path, bytes);
    }

    private sealed class FakeCdbVerifier(CdbVerificationResult result) : ICdbExecutableVerifier
    {
        public CdbVerificationResult Verify(string path) => result;
    }

    private sealed class FakeProcessHost(DebuggerProcessResult result) : IDebuggerProcessHost
    {
        public DebuggerInvocation? Invocation { get; private set; }

        public Task<DebuggerProcessResult> RunAsync(DebuggerInvocation invocation, CancellationToken cancellationToken)
        {
            Invocation = invocation;
            return Task.FromResult(result);
        }
    }

    private sealed class AllowDebuggerValidator : IDebuggerRequestValidator
    {
        public bool IsAllowedDebugger(CdbInstallation installation) => true;
    }

    private sealed class DenyDebuggerValidator : IDebuggerRequestValidator
    {
        public bool IsAllowedDebugger(CdbInstallation installation) => false;
    }

    private sealed class CancellingProcessHost : IDebuggerProcessHost
    {
        public Task<DebuggerProcessResult> RunAsync(
            DebuggerInvocation invocation,
            CancellationToken cancellationToken) =>
            throw new OperationCanceledException("Synthetic contained-process cancellation.");
    }

    private sealed class StandardTokenInspector : IUserTokenInspector
    {
        public UserTokenElevationState GetElevationState() => UserTokenElevationState.StandardUser;
    }

    private sealed class ElevatedTokenInspector : IUserTokenInspector
    {
        public UserTokenElevationState GetElevationState() => UserTokenElevationState.Elevated;
    }

    private sealed class UnavailableTokenInspector : IUserTokenInspector
    {
        public UserTokenElevationState GetElevationState() => UserTokenElevationState.Unavailable;
    }
}
