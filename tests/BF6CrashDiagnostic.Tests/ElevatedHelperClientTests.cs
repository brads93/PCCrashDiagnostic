using System.Diagnostics;
using System.Security.Cryptography;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class ElevatedHelperClientTests
{
    [Fact]
    public async Task VerifyBinding_ValidatesExactHelperWithoutLaunchingIt()
    {
        using var directory = new TestDirectory();
        string helperPath = CopyX64HostAsHelper(directory.Path);
        string sha256 = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(helperPath)))
            .ToLowerInvariant();
        bool launched = false;
        var client = new ElevatedHelperClient(
            helperPath,
            new ElevatedHelperRequestStore(Path.Combine(directory.Path, "Requests")),
            sha256,
            requireHashBinding: true,
            allowDevelopmentPath: true,
            _ =>
            {
                launched = true;
                return null;
            });

        (bool succeeded, string message) = await client.VerifyBindingAsync();

        Assert.True(succeeded);
        Assert.Contains("matches", message, StringComparison.OrdinalIgnoreCase);
        Assert.False(launched);
        Assert.False(Directory.Exists(Path.Combine(directory.Path, "Requests")));
    }

    [Fact]
    public async Task Execute_FailsClosedWhenPackagedBindingHashIsMissing()
    {
        using var directory = new TestDirectory();
        string helperPath = CopyX64HostAsHelper(directory.Path);
        var client = new ElevatedHelperClient(
            helperPath,
            new ElevatedHelperRequestStore(Path.Combine(directory.Path, "Requests")),
            expectedSha256: null,
            requireHashBinding: true,
            allowDevelopmentPath: true);

        ProtectedEvidenceResponse response = await client.ExecuteAsync(
            RetryRequest(),
            () => false,
            TimeSpan.FromSeconds(30),
            CancellationToken.None);

        Assert.False(response.Succeeded);
        Assert.Contains("integrity binding", response.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Execute_RejectsSubstitutedHelperBeforeCreatingRequestOrLaunching()
    {
        using var directory = new TestDirectory();
        string helperPath = CopyX64HostAsHelper(directory.Path);
        bool launched = false;
        string requestRoot = Path.Combine(directory.Path, "Requests");
        var client = new ElevatedHelperClient(
            helperPath,
            new ElevatedHelperRequestStore(requestRoot),
            new string('0', 64),
            requireHashBinding: true,
            allowDevelopmentPath: true,
            _ =>
            {
                launched = true;
                return null;
            });

        ProtectedEvidenceResponse response = await client.ExecuteAsync(
            RetryRequest(),
            () => false,
            TimeSpan.FromSeconds(30),
            CancellationToken.None);

        Assert.False(response.Succeeded);
        Assert.Contains("SHA-256", response.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(launched);
        Assert.False(Directory.Exists(requestRoot));
    }

    [Fact]
    public async Task Execute_HoldsValidatedHelperOpenAgainstReplacementThroughLaunch()
    {
        using var directory = new TestDirectory();
        string helperPath = CopyX64HostAsHelper(directory.Path);
        string sha256 = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(helperPath)))
            .ToLowerInvariant();
        bool replacementBlocked = false;
        var client = new ElevatedHelperClient(
            helperPath,
            new ElevatedHelperRequestStore(Path.Combine(directory.Path, "Requests")),
            sha256,
            requireHashBinding: true,
            allowDevelopmentPath: true,
            _ =>
            {
                try
                {
                    File.WriteAllBytes(helperPath, "MZ-substitution"u8.ToArray());
                }
                catch (IOException)
                {
                    replacementBlocked = true;
                }
                catch (UnauthorizedAccessException)
                {
                    replacementBlocked = true;
                }

                // This seam deliberately avoids an actual UAC launch.
                return null;
            });

        ProtectedEvidenceResponse response = await client.ExecuteAsync(
            RetryRequest(),
            () => false,
            TimeSpan.FromSeconds(30),
            CancellationToken.None);

        Assert.True(replacementBlocked);
        Assert.False(response.Succeeded);
        Assert.Contains("did not start", response.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(sha256, Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(helperPath))).ToLowerInvariant());
    }

    private static string CopyX64HostAsHelper(string root)
    {
        string source = Environment.ProcessPath
            ?? throw new InvalidOperationException("The test host executable path was unavailable.");
        string path = Path.Combine(root, "PCCrashDiagnostic.ElevatedHelper.exe");
        File.Copy(source, path);
        Assert.True(PeFileInspector.IsX64(path));
        return path;
    }

    private static ProtectedEvidenceRequest RetryRequest()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        return new ProtectedEvidenceRequest(
            ProtectedEvidenceOperation.RetryNamedSource,
            ProtectedEvidenceSource.SystemEventLog,
            null,
            null,
            null,
            false,
            false,
            false,
            "test-session",
            new string('a', 64),
            now.AddMinutes(-1),
            now,
            null);
    }
}
