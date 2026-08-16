using System.Text.Json;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class DriverVerifierCollectorTests
{
    [Beta2Fact]
    [Trait("Category", "SyntheticScenario")]
    public void Parser_ReturnsOnlyFlagsAndDriverBasenames()
    {
        const string output = """
            Verifier Flags: 0x00000009
            C:\Windows\System32\drivers\example.sys
            D:\private\other-driver.sys
            """;

        (DriverVerifierStatusKind status, string flags, IReadOnlyList<string> drivers) =
            DriverVerifierCollector.Parse(output);

        Assert.Equal(DriverVerifierStatusKind.Enabled, status);
        Assert.Equal("0x9", flags);
        Assert.Equal(["example.sys", "other-driver.sys"], drivers);
        string json = JsonSerializer.Serialize(new { flags, drivers });
        Assert.DoesNotContain("System32", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("private", json, StringComparison.OrdinalIgnoreCase);
    }

    [Beta2Fact]
    public void Parser_RecognizesExplicitDisabledState()
    {
        (DriverVerifierStatusKind status, string flags, IReadOnlyList<string> drivers) =
            DriverVerifierCollector.Parse("No drivers are currently being verified.\nVerifier Flags: 0x00000000");

        Assert.Equal(DriverVerifierStatusKind.Disabled, status);
        Assert.Equal("0x0", flags);
        Assert.Empty(drivers);
    }

    [Beta2Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task Collector_UsesOnlyReadOnlyQuerySettingsOperation()
    {
        using var directory = new TestDirectory();
        string executable = Path.Combine(directory.Path, "verifier.exe");
        await File.WriteAllBytesAsync(executable, [0]);
        var runner = new FakeCommandRunner(new BoundedCommandResult(
            0,
            "Verifier Flags: 0x1\nexample.sys",
            string.Empty,
            false,
            false,
            false));
        var collector = new DriverVerifierCollector(
            runner,
            new AllowVerifierValidator(),
            TimeProvider.System,
            executable);

        DriverVerifierState result = await collector.CollectAsync();

        Assert.Equal(DriverVerifierStatusKind.Enabled, result.Status);
        Assert.Equal(["example.sys"], result.VerifiedDriverBasenames);
        Assert.NotNull(runner.Request);
        Assert.Equal(["/querysettings"], runner.Request.Arguments);
        Assert.DoesNotContain("/standard", runner.Request.Arguments);
        Assert.DoesNotContain("/reset", runner.Request.Arguments);
    }

    [Beta2Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task Collector_MapsContainedTimeout()
    {
        using var directory = new TestDirectory();
        string executable = Path.Combine(directory.Path, "verifier.exe");
        await File.WriteAllBytesAsync(executable, [0]);
        var collector = new DriverVerifierCollector(
            new FakeCommandRunner(new BoundedCommandResult(null, "partial", string.Empty, true, false, false)),
            new AllowVerifierValidator(),
            TimeProvider.System,
            executable);

        DriverVerifierState result = await collector.CollectAsync();

        Assert.Equal(DriverVerifierStatusKind.TimedOut, result.Status);
        Assert.Empty(result.VerifiedDriverBasenames);
        Assert.DoesNotContain("partial", JsonSerializer.Serialize(result), StringComparison.OrdinalIgnoreCase);
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

    private sealed class AllowVerifierValidator : IDriverVerifierExecutableValidator
    {
        public bool IsAllowed(string path) => true;
    }
}
