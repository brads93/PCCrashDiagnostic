using System.IO.Compression;
using System.Security.Cryptography;
using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Tests;

public sealed class DumpPackagerTests
{
    [Fact]
    public async Task PackageAsync_RefusesWhileBf6IsRunning()
    {
        using var directory = new TestDirectory();
        string dumpPath = Path.Combine(directory.Path, "fixture.dmp");
        await File.WriteAllBytesAsync(dumpPath, [0x4D, 0x44, 0x4D, 0x50], CancellationToken.None);
        var packager = new DumpPackager();
        DumpArtifactIdentity identity = Capture(dumpPath);

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            packager.PackageAsync(
                identity,
                Path.Combine(directory.Path, "output"),
                () => true,
                cancellationToken: CancellationToken.None));

        Assert.Contains("unavailable while BF6 is running", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(Directory.Exists(Path.Combine(directory.Path, "output")));
    }

    [Fact]
    public async Task PackageAsync_CreatesSeparateArchiveWithPrivacyWarningAndChecksum()
    {
        using var directory = new TestDirectory();
        string dumpPath = Path.Combine(directory.Path, "fixture.dmp");
        byte[] dumpBytes = [0x4D, 0x44, 0x4D, 0x50, 0x01, 0x02, 0x03];
        await File.WriteAllBytesAsync(dumpPath, dumpBytes, CancellationToken.None);
        var packager = new DumpPackager();
        DumpArtifactIdentity identity = Capture(dumpPath);

        string packagePath = await packager.PackageAsync(
            identity,
            Path.Combine(directory.Path, "output"),
            () => false,
            cancellationToken: CancellationToken.None);

        Assert.True(File.Exists(packagePath));
        Assert.StartsWith("PCCrashDiagnostic-Dump-Package-", Path.GetFileName(packagePath), StringComparison.Ordinal);
        Assert.True(File.Exists(packagePath + ".sha256"));
        Assert.False(File.Exists(packagePath + ".partial"));
        string checksum = await File.ReadAllTextAsync(packagePath + ".sha256", CancellationToken.None);
        string actualSha = Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(packagePath, CancellationToken.None))).ToLowerInvariant();
        Assert.Equal($"{actualSha} *{Path.GetFileName(packagePath)}{Environment.NewLine}", checksum);
        using ZipArchive archive = ZipFile.OpenRead(packagePath);
        Assert.Contains(archive.Entries, entry => entry.FullName == "PRIVACY-WARNING.txt");
        Assert.Contains(archive.Entries, entry => entry.FullName == "Manifest.json");
        ZipArchiveEntry dumpEntry = Assert.Single(archive.Entries, entry => entry.FullName == "fixture.dmp");
        await using Stream dumpStream = dumpEntry.Open();
        using var copied = new MemoryStream();
        await dumpStream.CopyToAsync(copied, CancellationToken.None);
        Assert.Equal(dumpBytes, copied.ToArray());
    }

    [Fact]
    public async Task PackageAsync_CancellationRemovesSensitivePartialAndPublishesNothing()
    {
        using var directory = new TestDirectory();
        string dumpPath = Path.Combine(directory.Path, "fixture.dmp");
        await WriteValidDumpAsync(dumpPath, 2 * 1024 * 1024);
        string outputPath = Path.Combine(directory.Path, "output");
        using var cancellation = new CancellationTokenSource();
        var progress = new InlineProgress<double>(_ => cancellation.Cancel());
        var packager = new DumpPackager();
        DumpArtifactIdentity identity = Capture(dumpPath);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            packager.PackageAsync(
                identity,
                outputPath,
                () => false,
                progress,
                cancellation.Token));

        Assert.Empty(Directory.EnumerateFiles(outputPath, "*.partial", SearchOption.TopDirectoryOnly));
        Assert.Empty(Directory.EnumerateFiles(outputPath, "*.zip", SearchOption.TopDirectoryOnly));
        Assert.Empty(Directory.EnumerateFiles(outputPath, "*.sha256", SearchOption.TopDirectoryOnly));
    }

    [Fact]
    public async Task PackageAsync_CopyFailureRemovesSensitivePartialAndPublishesNothing()
    {
        using var directory = new TestDirectory();
        string dumpPath = Path.Combine(directory.Path, "fixture.dmp");
        await WriteValidDumpAsync(dumpPath, 512 * 1024);
        string outputPath = Path.Combine(directory.Path, "output");
        var packager = new DumpPackager();
        DumpArtifactIdentity identity = Capture(dumpPath);

        await Assert.ThrowsAsync<ExpectedProgressException>(() =>
            packager.PackageAsync(
                identity,
                outputPath,
                () => false,
                new InlineProgress<double>(_ => throw new ExpectedProgressException()),
                CancellationToken.None));

        Assert.Empty(Directory.EnumerateFiles(outputPath, "*.partial", SearchOption.TopDirectoryOnly));
        Assert.Empty(Directory.EnumerateFiles(outputPath, "*.zip", SearchOption.TopDirectoryOnly));
        Assert.Empty(Directory.EnumerateFiles(outputPath, "*.sha256", SearchOption.TopDirectoryOnly));
    }

    [Fact]
    public async Task PackageAsync_ConcurrentCallsUseUniqueNamesWithoutOverwriting()
    {
        using var directory = new TestDirectory();
        string dumpPath = Path.Combine(directory.Path, "fixture.dmp");
        await WriteValidDumpAsync(dumpPath, 256 * 1024);
        string outputPath = Path.Combine(directory.Path, "output");
        var packager = new DumpPackager();
        DumpArtifactIdentity identity = Capture(dumpPath);

        string[] packagePaths = await Task.WhenAll(Enumerable.Range(0, 4).Select(_ =>
            packager.PackageAsync(
                identity,
                outputPath,
                () => false,
                cancellationToken: CancellationToken.None)));

        Assert.Equal(packagePaths.Length, packagePaths.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.All(packagePaths, packagePath =>
        {
            Assert.True(File.Exists(packagePath));
            Assert.True(File.Exists(packagePath + ".sha256"));
        });
        Assert.Empty(Directory.EnumerateFiles(outputPath, "*.partial", SearchOption.TopDirectoryOnly));
        Assert.Equal(4, Directory.EnumerateFiles(outputPath, "*.zip", SearchOption.TopDirectoryOnly).Count());
        Assert.Equal(4, Directory.EnumerateFiles(outputPath, "*.sha256", SearchOption.TopDirectoryOnly).Count());
    }

    [Fact]
    public async Task PackageAsync_RejectsFileSubstitutionAfterAnalysisEvenWithMatchingSizeTimeAndHeader()
    {
        using var directory = new TestDirectory();
        string dumpPath = Path.Combine(directory.Path, "fixture.dmp");
        await WriteValidDumpAsync(dumpPath, 256 * 1024, fill: 0x11);
        DumpArtifactIdentity identity = Capture(dumpPath);

        File.Move(dumpPath, Path.Combine(directory.Path, "analyzed-original.dmp"));
        await WriteValidDumpAsync(dumpPath, 256 * 1024, fill: 0x22);
        File.SetLastWriteTimeUtc(dumpPath, identity.LastWriteTimeUtc);
        var packager = new DumpPackager();
        string outputPath = Path.Combine(directory.Path, "output");

        IOException exception = await Assert.ThrowsAsync<IOException>(() =>
            packager.PackageAsync(identity, outputPath, () => false, cancellationToken: CancellationToken.None));

        Assert.Contains("changed after analysis", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.False(Directory.Exists(outputPath) && Directory.EnumerateFiles(outputPath).Any());
    }

    [Fact]
    public async Task PackageAsync_RejectsReparseSubstitutionAfterAnalysis()
    {
        using var directory = new TestDirectory();
        string dumpPath = Path.Combine(directory.Path, "fixture.dmp");
        string replacementPath = Path.Combine(directory.Path, "replacement.dmp");
        await WriteValidDumpAsync(dumpPath, 64 * 1024, fill: 0x11);
        await WriteValidDumpAsync(replacementPath, 64 * 1024, fill: 0x22);
        DumpArtifactIdentity identity = Capture(dumpPath);
        File.Move(dumpPath, Path.Combine(directory.Path, "fixture.original.dmp"));
        if (!TryCreateFileSymbolicLink(dumpPath, replacementPath))
        {
            return;
        }

        var packager = new DumpPackager();
        await Assert.ThrowsAsync<IOException>(() =>
            packager.PackageAsync(
                identity,
                Path.Combine(directory.Path, "output"),
                () => false,
                cancellationToken: CancellationToken.None));
    }

    [Fact]
    public async Task PackageAsync_StopsAndPublishesNothingWhenBf6StartsMidCopy()
    {
        using var directory = new TestDirectory();
        string dumpPath = Path.Combine(directory.Path, "fixture.dmp");
        await WriteValidDumpAsync(dumpPath, 2 * 1024 * 1024);
        DumpArtifactIdentity identity = Capture(dumpPath);
        string outputPath = Path.Combine(directory.Path, "output");
        bool bf6Running = false;
        var progress = new InlineProgress<double>(_ => bf6Running = true);
        var packager = new DumpPackager();

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            packager.PackageAsync(identity, outputPath, () => bf6Running, progress, CancellationToken.None));

        Assert.Empty(Directory.EnumerateFiles(outputPath, "*.partial", SearchOption.TopDirectoryOnly));
        Assert.Empty(Directory.EnumerateFiles(outputPath, "*.zip", SearchOption.TopDirectoryOnly));
        Assert.Empty(Directory.EnumerateFiles(outputPath, "*.sha256", SearchOption.TopDirectoryOnly));
    }

    [Fact]
    public async Task PackageAsync_RechecksBf6ImmediatelyBeforeFinalArchivePublish()
    {
        using var directory = new TestDirectory();
        string dumpPath = Path.Combine(directory.Path, "fixture.dmp");
        await WriteValidDumpAsync(dumpPath, 64 * 1024);
        DumpArtifactIdentity identity = Capture(dumpPath);
        string outputPath = Path.Combine(directory.Path, "output");
        bool copyComplete = false;
        int checksAfterCopy = 0;
        var progress = new InlineProgress<double>(value => copyComplete |= value >= 1);
        bool IsRunning()
        {
            if (!copyComplete)
            {
                return false;
            }

            return Interlocked.Increment(ref checksAfterCopy) >= 6;
        }

        var packager = new DumpPackager();
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            packager.PackageAsync(identity, outputPath, IsRunning, progress, CancellationToken.None));

        Assert.Equal(6, checksAfterCopy);
        Assert.Empty(Directory.EnumerateFiles(outputPath, "*.partial", SearchOption.TopDirectoryOnly));
        Assert.Empty(Directory.EnumerateFiles(outputPath, "*.zip", SearchOption.TopDirectoryOnly));
        Assert.Empty(Directory.EnumerateFiles(outputPath, "*.sha256", SearchOption.TopDirectoryOnly));
    }

    [Theory]
    [InlineData("fixture.bin", true)]
    [InlineData("fixture.dmp", false)]
    public async Task CaptureIdentity_RequiresDmpExtensionAndRecognizedSignature(
        string fileName,
        bool validSignature)
    {
        using var directory = new TestDirectory();
        string path = Path.Combine(directory.Path, fileName);
        byte[] bytes = validSignature ? [0x4D, 0x44, 0x4D, 0x50] : [0x00, 0x01, 0x02, 0x03];
        await File.WriteAllBytesAsync(path, bytes, CancellationToken.None);
        var info = new FileInfo(path);

        Assert.Throws<InvalidDataException>(() => DumpPackager.CaptureIdentity(
            path,
            info.Length,
            info.LastWriteTimeUtc));
    }

    private static DumpArtifactIdentity Capture(string dumpPath)
    {
        var info = new FileInfo(dumpPath);
        info.Refresh();
        return DumpPackager.CaptureIdentity(dumpPath, info.Length, info.LastWriteTimeUtc);
    }

    private static Task WriteValidDumpAsync(string path, int length, byte fill = 0x5A)
    {
        byte[] bytes = Enumerable.Repeat(fill, Math.Max(length, 4)).ToArray();
        "MDMP"u8.CopyTo(bytes);
        return File.WriteAllBytesAsync(path, bytes, CancellationToken.None);
    }

    private static bool TryCreateFileSymbolicLink(string linkPath, string targetPath)
    {
        try
        {
            File.CreateSymbolicLink(linkPath, targetPath);
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
    }

    private sealed class InlineProgress<T>(Action<T> report) : IProgress<T>
    {
        public void Report(T value) => report(value);
    }

    private sealed class ExpectedProgressException : Exception;
}
