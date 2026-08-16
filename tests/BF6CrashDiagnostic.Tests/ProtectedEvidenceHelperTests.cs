using System.Security.Cryptography;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class ProtectedEvidenceHelperTests
{
    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task CopySelectedDump_StagesApprovedDumpWithPrivateHashThenDeletesIt()
    {
        using var directory = new TestDirectory();
        (ProtectedEvidenceHelper helper, ProtectedEvidenceRoots roots, string stagingRoot) = CreateHelper(directory.Path);
        Directory.CreateDirectory(roots.MinidumpRoot);
        string dumpPath = Path.Combine(roots.MinidumpRoot, "080326-1234-01.dmp");
        byte[] bytes = new byte[8192];
        "MDMP"u8.CopyTo(bytes);
        await File.WriteAllBytesAsync(dumpPath, bytes, CancellationToken.None);
        var info = new FileInfo(dumpPath);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            CopyRequest(dumpPath, info),
            CancellationToken.None);

        Assert.True(response.Succeeded, response.Message);
        StagedDump staged = Assert.IsType<StagedDump>(response.StagedDump);
        Assert.True(File.Exists(staged.Path));
        Assert.StartsWith(Path.GetFullPath(stagingRoot), Path.GetFullPath(staged.Path), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(bytes.Length, staged.SizeBytes);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(), staged.Sha256);
        Assert.Equal("Windows minidump", staged.SourceType);

        Assert.True(helper.DeleteStagedCopy(staged));
        Assert.False(Directory.Exists(staged.StagingDirectory));
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task CopySelectedDump_RejectsTraversalAndMissingConfirmations()
    {
        using var directory = new TestDirectory();
        (ProtectedEvidenceHelper helper, _, _) = CreateHelper(directory.Path);
        string outside = Path.Combine(directory.Path, "outside.dmp");
        await File.WriteAllBytesAsync(outside, "MDMP"u8.ToArray(), CancellationToken.None);
        var info = new FileInfo(outside);

        ProtectedEvidenceResponse outsideResponse = await helper.ExecuteAsync(
            CopyRequest(outside, info),
            CancellationToken.None);
        Assert.False(outsideResponse.Succeeded);
        Assert.Contains("outside", outsideResponse.Message, StringComparison.OrdinalIgnoreCase);

        ProtectedEvidenceRequest unconfirmed = CopyRequest(outside, info) with { PrivacyConfirmed = false };
        ProtectedEvidenceResponse unconfirmedResponse = await helper.ExecuteAsync(unconfirmed, CancellationToken.None);
        Assert.False(unconfirmedResponse.Succeeded);
        Assert.Contains("confirmation", unconfirmedResponse.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task CopySelectedDump_RejectsOver64GiBBeforeOpeningAndInsufficientCapacityBeforeStaging()
    {
        using var directory = new TestDirectory();
        (ProtectedEvidenceHelper helper, ProtectedEvidenceRoots roots, string stagingRoot) =
            CreateHelper(directory.Path, _ => 0);
        Directory.CreateDirectory(roots.MinidumpRoot);
        string path = Path.Combine(roots.MinidumpRoot, "small.dmp");
        await File.WriteAllBytesAsync(path, "MDMP"u8.ToArray(), CancellationToken.None);
        var info = new FileInfo(path);

        ProtectedEvidenceRequest oversized = CopyRequest(path, info) with
        {
            ExpectedSizeBytes = ProtectedEvidenceHelper.MaximumDumpBytes + 1
        };
        ProtectedEvidenceResponse oversizedResponse = await helper.ExecuteAsync(oversized, CancellationToken.None);
        Assert.False(oversizedResponse.Succeeded);
        Assert.Contains("64 GiB", oversizedResponse.Message, StringComparison.OrdinalIgnoreCase);

        ProtectedEvidenceResponse noCapacity = await helper.ExecuteAsync(CopyRequest(path, info), CancellationToken.None);
        Assert.False(noCapacity.Succeeded);
        Assert.Contains("free space", noCapacity.Message, StringComparison.OrdinalIgnoreCase);
        Assert.True(Directory.Exists(stagingRoot));
        Assert.Empty(Directory.EnumerateDirectories(stagingRoot));
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task CopySelectedDump_RejectsChangedIdentityAndReparseSource()
    {
        using var directory = new TestDirectory();
        (ProtectedEvidenceHelper helper, ProtectedEvidenceRoots roots, _) = CreateHelper(directory.Path);
        Directory.CreateDirectory(roots.MinidumpRoot);
        string path = Path.Combine(roots.MinidumpRoot, "changed.dmp");
        await File.WriteAllBytesAsync(path, "MDMP"u8.ToArray(), CancellationToken.None);
        var original = new FileInfo(path);
        ProtectedEvidenceRequest request = CopyRequest(path, original);
        await File.WriteAllBytesAsync(path, "MDMP1234"u8.ToArray(), CancellationToken.None);

        ProtectedEvidenceResponse changed = await helper.ExecuteAsync(request, CancellationToken.None);
        Assert.False(changed.Succeeded);
        Assert.Contains("identity", changed.Message, StringComparison.OrdinalIgnoreCase);

        string outside = Path.Combine(directory.Path, "actual.dmp");
        await File.WriteAllBytesAsync(outside, "MDMP"u8.ToArray(), CancellationToken.None);
        string link = Path.Combine(roots.MinidumpRoot, "link.dmp");
        if (!TryCreateFileSymbolicLink(link, outside))
        {
            return;
        }

        var linked = new FileInfo(link);
        ProtectedEvidenceResponse reparse = await helper.ExecuteAsync(
            CopyRequest(link, linked),
            CancellationToken.None);
        Assert.False(reparse.Succeeded);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task CopySelectedDump_CancellationLeavesNoStagedData()
    {
        using var directory = new TestDirectory();
        (ProtectedEvidenceHelper helper, ProtectedEvidenceRoots roots, string stagingRoot) = CreateHelper(directory.Path);
        Directory.CreateDirectory(roots.MinidumpRoot);
        string path = Path.Combine(roots.MinidumpRoot, "cancel.dmp");
        await File.WriteAllBytesAsync(path, "MDMP"u8.ToArray(), CancellationToken.None);
        var info = new FileInfo(path);
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            helper.ExecuteAsync(CopyRequest(path, info), cancellation.Token));

        Assert.False(Directory.Exists(stagingRoot) && Directory.EnumerateFileSystemEntries(stagingRoot).Any());
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public void CleanupStaleStagingDirectories_RemovesOnlyValidatedOldDirectories()
    {
        using var directory = new TestDirectory();
        (ProtectedEvidenceHelper helper, _, string stagingRoot) = CreateHelper(directory.Path);
        Directory.CreateDirectory(stagingRoot);
        string old = Path.Combine(stagingRoot, "stage-old");
        string recent = Path.Combine(stagingRoot, "stage-recent");
        string unrelated = Path.Combine(stagingRoot, "other-old");
        Directory.CreateDirectory(old);
        Directory.CreateDirectory(recent);
        Directory.CreateDirectory(unrelated);
        string oldMarker = Path.Combine(old, ".pc-crash-diagnostic-staging");
        string recentMarker = Path.Combine(recent, ".pc-crash-diagnostic-staging");
        File.WriteAllText(oldMarker, "old");
        File.WriteAllText(recentMarker, "recent");
        File.SetCreationTimeUtc(oldMarker, DateTime.UtcNow.AddHours(-25));

        int removed = helper.CleanupStaleStagingDirectories(DateTimeOffset.UtcNow);

        Assert.Equal(1, removed);
        Assert.False(Directory.Exists(old));
        Assert.True(Directory.Exists(recent));
        Assert.True(Directory.Exists(unrelated));
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task RetryNamedSource_AcceptsOnlyFixedSourceWithoutPathParameters()
    {
        using var directory = new TestDirectory();
        (ProtectedEvidenceHelper helper, ProtectedEvidenceRoots roots, _) = CreateHelper(directory.Path);
        Directory.CreateDirectory(roots.MinidumpRoot);
        await File.WriteAllBytesAsync(
            Path.Combine(roots.MinidumpRoot, "one.dmp"),
            "MDMP"u8.ToArray(),
            CancellationToken.None);

        DateTimeOffset now = DateTimeOffset.UtcNow;
        ProtectedEvidenceRequest request = RetryRequest(
            ProtectedEvidenceSource.WindowsMinidumps,
            now.AddMinutes(-1),
            now.AddMinutes(1));
        ProtectedEvidenceResponse response = await helper.ExecuteAsync(request, CancellationToken.None);

        Assert.True(response.Succeeded);
        ProtectedEvidenceBatch batch = Assert.IsType<ProtectedEvidenceBatch>(response.EvidenceBatch);
        Assert.Single(batch.Dumps);
        Assert.Null(response.Probe);
        Assert.Equal(request.ReportSessionId, batch.ReportSessionId);
        Assert.Equal(request.ReportSha256, batch.ReportSha256);

        ProtectedEvidenceResponse confusedDeputy = await helper.ExecuteAsync(
            request with { DumpPath = "C:\\arbitrary" },
            CancellationToken.None);
        Assert.False(confusedDeputy.Succeeded);
    }

    [Fact]
    public async Task RetryNamedSource_RejectsMissingReportBindingBeforeReadingSource()
    {
        using var directory = new TestDirectory();
        (ProtectedEvidenceHelper helper, ProtectedEvidenceRoots roots, _) = CreateHelper(directory.Path);
        Directory.CreateDirectory(roots.MinidumpRoot);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            new ProtectedEvidenceRequest(
                ProtectedEvidenceOperation.RetryNamedSource,
                ProtectedEvidenceSource.WindowsMinidumps,
                null,
                null,
                null,
                false,
                false,
                false),
            CancellationToken.None);

        Assert.False(response.Succeeded);
        Assert.Contains("report", response.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Null(response.EvidenceBatch);
    }

    [Fact]
    public async Task RetryNamedSource_StopsIfBattlefieldStartsDuringDumpEnumeration()
    {
        using var directory = new TestDirectory();
        string windows = Path.Combine(directory.Path, "Windows");
        var roots = new ProtectedEvidenceRoots(
            Path.Combine(windows, "MEMORY.DMP"),
            Path.Combine(windows, "Minidump"),
            Path.Combine(windows, "LiveKernelReports"));
        Directory.CreateDirectory(roots.MinidumpRoot);
        for (int index = 0; index < 4; index++)
        {
            byte[] bytes = new byte[4096];
            "MDMP"u8.CopyTo(bytes);
            await File.WriteAllBytesAsync(
                Path.Combine(roots.MinidumpRoot, $"fixture-{index}.dmp"),
                bytes,
                CancellationToken.None);
        }

        int checks = 0;
        var helper = new ProtectedEvidenceHelper(
            Path.Combine(directory.Path, "Staging"),
            roots,
            _ => long.MaxValue,
            () => Interlocked.Increment(ref checks) >= 5);
        DateTimeOffset now = DateTimeOffset.UtcNow;

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            RetryRequest(ProtectedEvidenceSource.WindowsMinidumps, now.AddMinutes(-1), now.AddMinutes(1)),
            CancellationToken.None);

        Assert.False(response.Succeeded);
        Assert.Contains("protected target", response.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Null(response.EvidenceBatch);
        Assert.True(checks >= 5);
    }

    [Fact]
    public async Task RetryNamedSource_ResponseIsPrivacyFilteredAndFitsBoundedChannel()
    {
        using var directory = new TestDirectory();
        (ProtectedEvidenceHelper helper, ProtectedEvidenceRoots roots, _) = CreateHelper(directory.Path);
        Directory.CreateDirectory(roots.MinidumpRoot);
        string privateGuid = "8444a4fb-d8d3-4f38-84f8-89960a1ef12f";
        for (int index = 0; index < ProtectedEvidenceHelper.MaximumRetryDumps; index++)
        {
            byte[] bytes = new byte[4096];
            "MDMP"u8.CopyTo(bytes);
            await File.WriteAllBytesAsync(
                Path.Combine(roots.MinidumpRoot, $"{privateGuid}-{index:D2}.dmp"),
                bytes,
                CancellationToken.None);
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;
        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            RetryRequest(ProtectedEvidenceSource.WindowsMinidumps, now.AddMinutes(-1), now.AddMinutes(1)),
            CancellationToken.None);

        Assert.True(response.Succeeded, response.Message);
        ProtectedEvidenceBatch batch = Assert.IsType<ProtectedEvidenceBatch>(response.EvidenceBatch);
        Assert.Equal(ProtectedEvidenceHelper.MaximumRetryDumps, batch.Dumps.Count);
        Assert.All(batch.Dumps, item =>
        {
            Assert.DoesNotContain(privateGuid, item.Name, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(privateGuid, item.RedactedPath, StringComparison.OrdinalIgnoreCase);
            Assert.InRange(item.HeaderBytesRead, 0, SafeDumpInspector.MaximumHeaderBytesRead);
        });

        string requestRoot = Path.Combine(directory.Path, "Requests");
        var store = new ElevatedHelperRequestStore(requestRoot);
        ProtectedEvidenceRequest request = RetryRequest(
            ProtectedEvidenceSource.WindowsMinidumps,
            now.AddMinutes(-1),
            now.AddMinutes(1));
        ElevatedHelperTicket ticket = await store.CreateRequestAsync(request, CancellationToken.None);
        await store.PublishResponseAsync(ticket.RequestId, response, CancellationToken.None);
        Assert.InRange(new FileInfo(ticket.ResponsePath).Length, 1, (64 * 1024) - 1);
    }

    [Fact]
    [Trait("Category", "SyntheticScenario")]
    public async Task Execute_BlocksEveryHelperOperationWhileBattlefield6IsRunning()
    {
        using var directory = new TestDirectory();
        string windows = Path.Combine(directory.Path, "Windows");
        var roots = new ProtectedEvidenceRoots(
            Path.Combine(windows, "MEMORY.DMP"),
            Path.Combine(windows, "Minidump"),
            Path.Combine(windows, "LiveKernelReports"));
        var helper = new ProtectedEvidenceHelper(
            Path.Combine(directory.Path, "Staging"),
            roots,
            _ => long.MaxValue,
            () => true);

        ProtectedEvidenceResponse response = await helper.ExecuteAsync(
            new ProtectedEvidenceRequest(
                ProtectedEvidenceOperation.RetryNamedSource,
                ProtectedEvidenceSource.WindowsMinidumps,
                null,
                null,
                null,
                false,
                false,
                false),
            CancellationToken.None);

        Assert.False(response.Succeeded);
        Assert.Contains("Battlefield 6", response.Message, StringComparison.OrdinalIgnoreCase);
    }

    private static (ProtectedEvidenceHelper Helper, ProtectedEvidenceRoots Roots, string StagingRoot) CreateHelper(
        string root,
        Func<string, long>? freeSpace = null)
    {
        string windows = Path.Combine(root, "Windows");
        var roots = new ProtectedEvidenceRoots(
            Path.Combine(windows, "MEMORY.DMP"),
            Path.Combine(windows, "Minidump"),
            Path.Combine(windows, "LiveKernelReports"));
        string staging = Path.Combine(root, "Staging");
        return (new ProtectedEvidenceHelper(staging, roots, freeSpace ?? (_ => long.MaxValue)), roots, staging);
    }

    private static ProtectedEvidenceRequest CopyRequest(string path, FileInfo info) =>
        new(
            ProtectedEvidenceOperation.CopySelectedDump,
            null,
            path,
            info.Length,
            info.LastWriteTimeUtc,
            true,
            true,
            true);

    private static ProtectedEvidenceRequest RetryRequest(
        ProtectedEvidenceSource source,
        DateTimeOffset startUtc,
        DateTimeOffset endUtc) => new(
            ProtectedEvidenceOperation.RetryNamedSource,
            source,
            null,
            null,
            null,
            false,
            false,
            false,
            "test-session",
            new string('a', 64),
            startUtc,
            endUtc,
            null);

    private static bool TryCreateFileSymbolicLink(string linkPath, string targetPath)
    {
        try
        {
            File.CreateSymbolicLink(linkPath, targetPath);
            return true;
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException or PlatformNotSupportedException)
        {
            return false;
        }
    }
}
