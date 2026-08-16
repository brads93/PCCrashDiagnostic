using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;
using System.Text.Json;

namespace BF6CrashDiagnostic.Tests;

public sealed class ActiveSessionStoreTests
{
    [Fact]
    public async Task FindStaleAsync_ClassifiesInterruptedToolOnSameBoot()
    {
        using var directory = new TestDirectory();
        var store = new ActiveSessionStore();
        DateTimeOffset boot = DateTimeOffset.Parse("2026-08-02T03:00:00Z");
        string sessionFolder = Path.Combine(directory.Path, "Sessions", "same-boot");
        var marker = Marker(sessionFolder, boot, boot.AddHours(1));
        await store.WriteAsync(marker, Path.Combine(directory.Path, "Sessions"), CancellationToken.None);

        RecoveryCandidate candidate = Assert.Single(await store.FindStaleAsync(
            Path.Combine(directory.Path, "Sessions"),
            boot,
            CancellationToken.None));

        Assert.False(candidate.BootChanged);
        Assert.Equal("RecoveredAfterToolInterruption", candidate.CompletionReason);
        Assert.Equal(marker.LastSampleUtc, candidate.EvidenceEndUtc);
    }

    [Fact]
    public async Task FindStaleAsync_ClassifiesSystemRestartWithoutExtendingToRelaunchTime()
    {
        using var directory = new TestDirectory();
        var store = new ActiveSessionStore();
        DateTimeOffset originalBoot = DateTimeOffset.Parse("2026-08-02T03:00:00Z");
        string sessionFolder = Path.Combine(directory.Path, "Sessions", "rebooted");
        var marker = Marker(sessionFolder, originalBoot, originalBoot.AddHours(1));
        await store.WriteAsync(marker, Path.Combine(directory.Path, "Sessions"), CancellationToken.None);

        RecoveryCandidate candidate = Assert.Single(await store.FindStaleAsync(
            Path.Combine(directory.Path, "Sessions"),
            DateTimeOffset.Parse("2026-08-02T04:30:00Z"),
            CancellationToken.None));

        Assert.True(candidate.BootChanged);
        Assert.Equal("RecoveredAfterSystemRestart", candidate.CompletionReason);
        Assert.Equal(marker.LastSampleUtc, candidate.EvidenceEndUtc);
        Assert.NotEqual(DateTimeOffset.Parse("2026-08-02T04:30:00Z"), candidate.EvidenceEndUtc);
    }

    [Fact]
    public async Task FindStaleAsync_IgnoresLiveOwner_AndCompleteRemovesMarker()
    {
        using var directory = new TestDirectory();
        var store = new ActiveSessionStore();
        string sessionFolder = Path.Combine(directory.Path, "Sessions", "live");
        using System.Diagnostics.Process current = System.Diagnostics.Process.GetCurrentProcess();
        DateTimeOffset boot = new(current.StartTime.ToUniversalTime().AddHours(-1));
        var marker = new ActiveSessionMarker(
            1,
            "live",
            current.Id,
            DateTimeOffset.UtcNow,
            boot,
            DateTimeOffset.UtcNow,
            sessionFolder,
            "BF6",
            DiagnosticMode.Monitor);
        await store.WriteAsync(marker, Path.Combine(directory.Path, "Sessions"), CancellationToken.None);

        Assert.Empty(await store.FindStaleAsync(
            Path.Combine(directory.Path, "Sessions"),
            boot,
            CancellationToken.None));

        store.Complete(sessionFolder, Path.Combine(directory.Path, "Sessions"));
        Assert.False(File.Exists(Path.Combine(sessionFolder, "ACTIVE.json")));
    }

    [Fact]
    public async Task FindStaleAsync_LeavesCorruptMarkerForManualReview()
    {
        using var directory = new TestDirectory();
        var store = new ActiveSessionStore();
        string sessionFolder = Path.Combine(directory.Path, "Sessions", "corrupt");
        Directory.CreateDirectory(sessionFolder);
        string markerPath = Path.Combine(sessionFolder, "ACTIVE.json");
        await File.WriteAllTextAsync(markerPath, "{not-json", CancellationToken.None);

        Assert.Empty(await store.FindStaleAsync(
            Path.Combine(directory.Path, "Sessions"),
            DateTimeOffset.UtcNow,
            CancellationToken.None));
        Assert.True(File.Exists(markerPath));
    }

    [Fact]
    public async Task FindStaleAsync_DerivesSessionFolderFromMarkerLocation()
    {
        using var directory = new TestDirectory();
        var store = new ActiveSessionStore();
        DateTimeOffset boot = DateTimeOffset.Parse("2026-08-02T03:00:00Z");
        string sessionFolder = Path.Combine(directory.Path, "Sessions", "derived-folder");
        string outsideFolder = Path.Combine(directory.Path, "outside");
        Directory.CreateDirectory(outsideFolder);
        string outsideSentinel = Path.Combine(outsideFolder, "ACTIVE.json");
        await File.WriteAllTextAsync(outsideSentinel, "do not delete");
        ActiveSessionMarker marker = Marker(sessionFolder, boot, boot.AddHours(1)) with
        {
            SessionFolder = outsideFolder
        };
        await WriteRawMarkerAsync(sessionFolder, marker);

        RecoveryCandidate candidate = Assert.Single(await store.FindStaleAsync(
            Path.Combine(directory.Path, "Sessions"),
            boot,
            CancellationToken.None));

        Assert.Equal(Path.GetFullPath(sessionFolder), candidate.Marker.SessionFolder);
        store.Complete(candidate.Marker.SessionFolder, Path.Combine(directory.Path, "Sessions"));
        Assert.False(File.Exists(Path.Combine(sessionFolder, "ACTIVE.json")));
        Assert.True(File.Exists(outsideSentinel));
    }

    [Theory]
    [InlineData(2, "bad-schema", "bad-schema")]
    [InlineData(1, "actual-folder", "mismatched")]
    public async Task FindStaleAsync_IgnoresInvalidSchemaOrSessionId(
        int schemaVersion,
        string folderName,
        string serializedSessionId)
    {
        using var directory = new TestDirectory();
        var store = new ActiveSessionStore();
        DateTimeOffset boot = DateTimeOffset.Parse("2026-08-02T03:00:00Z");
        string sessionFolder = Path.Combine(directory.Path, "Sessions", folderName);
        ActiveSessionMarker marker = Marker(sessionFolder, boot, boot.AddHours(1)) with
        {
            MarkerSchemaVersion = schemaVersion,
            SessionId = serializedSessionId
        };
        await WriteRawMarkerAsync(sessionFolder, marker);

        Assert.Empty(await store.FindStaleAsync(
            Path.Combine(directory.Path, "Sessions"),
            boot,
            CancellationToken.None));
        Assert.True(File.Exists(Path.Combine(sessionFolder, "ACTIVE.json")));
    }

    [Fact]
    public async Task FindStaleAsync_IgnoresInvalidTimestampRangeAndNestedMarkers()
    {
        using var directory = new TestDirectory();
        var store = new ActiveSessionStore();
        DateTimeOffset boot = DateTimeOffset.Parse("2026-08-02T03:00:00Z");
        string invalidFolder = Path.Combine(directory.Path, "Sessions", "invalid-time");
        ActiveSessionMarker invalid = Marker(invalidFolder, boot, boot.AddMinutes(1)) with
        {
            StartedUtc = boot.AddHours(2)
        };
        await WriteRawMarkerAsync(invalidFolder, invalid);

        string nestedFolder = Path.Combine(directory.Path, "Sessions", "outer", "nested");
        await WriteRawMarkerAsync(nestedFolder, Marker(nestedFolder, boot, boot.AddHours(1)));

        Assert.Empty(await store.FindStaleAsync(
            Path.Combine(directory.Path, "Sessions"),
            boot,
            CancellationToken.None));
    }

    [Fact]
    public async Task WriteAsync_RejectsSessionFolderOutsideExplicitSessionsRoot()
    {
        using var directory = new TestDirectory();
        var store = new ActiveSessionStore();
        DateTimeOffset boot = DateTimeOffset.Parse("2026-08-02T03:00:00Z");
        string sessionsRoot = Path.Combine(directory.Path, "Sessions");
        string outsideFolder = Path.Combine(directory.Path, "outside-session");
        ActiveSessionMarker marker = Marker(outsideFolder, boot, boot.AddHours(1));

        await Assert.ThrowsAsync<UnauthorizedAccessException>(() =>
            store.WriteAsync(marker, sessionsRoot, CancellationToken.None));

        Assert.False(File.Exists(Path.Combine(outsideFolder, "ACTIVE.json")));
    }

    [Fact]
    public async Task WriteAsync_UsesFreshRandomTempAndDoesNotTouchPredictablePartial()
    {
        using var directory = new TestDirectory();
        var store = new ActiveSessionStore();
        DateTimeOffset boot = DateTimeOffset.Parse("2026-08-02T03:00:00Z");
        string sessionsRoot = Path.Combine(directory.Path, "Sessions");
        string sessionFolder = Path.Combine(sessionsRoot, "random-temp");
        Directory.CreateDirectory(sessionFolder);
        string predictablePartial = Path.Combine(sessionFolder, "ACTIVE.json.partial");
        await File.WriteAllTextAsync(predictablePartial, "planted", CancellationToken.None);

        await store.WriteAsync(
            Marker(sessionFolder, boot, boot.AddHours(1)),
            sessionsRoot,
            CancellationToken.None);

        Assert.Equal("planted", await File.ReadAllTextAsync(predictablePartial, CancellationToken.None));
        Assert.True(File.Exists(Path.Combine(sessionFolder, "ACTIVE.json")));
        Assert.Empty(Directory.EnumerateFiles(sessionFolder, ".active-marker.*.partial", SearchOption.TopDirectoryOnly));
    }

    [Fact]
    public async Task Complete_RejectsPlantedMarkerReparseLinkAndPreservesOutsideFile()
    {
        using var directory = new TestDirectory();
        var store = new ActiveSessionStore();
        string sessionsRoot = Path.Combine(directory.Path, "Sessions");
        string sessionFolder = Path.Combine(sessionsRoot, "linked-marker");
        Directory.CreateDirectory(sessionFolder);
        string outsideSentinel = Path.Combine(directory.Path, "outside-active.json");
        await File.WriteAllTextAsync(outsideSentinel, "unchanged", CancellationToken.None);
        string markerPath = Path.Combine(sessionFolder, "ACTIVE.json");
        if (!TryCreateFileSymbolicLink(markerPath, outsideSentinel))
        {
            return;
        }

        Assert.Throws<IOException>(() => store.Complete(sessionFolder, sessionsRoot));
        Assert.Equal("unchanged", await File.ReadAllTextAsync(outsideSentinel, CancellationToken.None));
    }

    private static async Task WriteRawMarkerAsync(string sessionFolder, ActiveSessionMarker marker)
    {
        Directory.CreateDirectory(sessionFolder);
        await File.WriteAllTextAsync(
            Path.Combine(sessionFolder, "ACTIVE.json"),
            JsonSerializer.Serialize(marker));
    }

    private static ActiveSessionMarker Marker(
        string sessionFolder,
        DateTimeOffset boot,
        DateTimeOffset lastSample) =>
        new(
            1,
            Path.GetFileName(sessionFolder),
            int.MaxValue,
            boot.AddMinutes(10),
            boot,
            lastSample,
            sessionFolder,
            "BF6",
            DiagnosticMode.Monitor);

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
}
