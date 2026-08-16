using BF6CrashDiagnostic.Core;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Tests;

public sealed class DiagnosticCoordinatorTests
{
    [Fact]
    public void Constructor_RequiresAbsoluteDataRoot()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(() =>
            new DiagnosticCoordinator("relative-data-root"));

        Assert.Contains("absolute", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task RecoverInterruptedSessionsAsync_WithNoSessionRoot_IsEmptyAndNonDestructive()
    {
        using var directory = new TestDirectory();
        string dataRoot = Path.Combine(directory.Path, "data");
        using var coordinator = new DiagnosticCoordinator(dataRoot);

        var actual = await coordinator.RecoverInterruptedSessionsAsync(cancellationToken: CancellationToken.None);

        Assert.Empty(actual);
        Assert.False(Directory.Exists(dataRoot));
    }

    [Fact]
    public async Task DisposedCoordinator_RejectsFurtherCollection()
    {
        using var directory = new TestDirectory();
        var coordinator = new DiagnosticCoordinator(Path.Combine(directory.Path, "data"));
        coordinator.Dispose();

        await Assert.ThrowsAsync<ObjectDisposedException>(() => coordinator.GetSystemSnapshotAsync());
        await Assert.ThrowsAsync<ObjectDisposedException>(() => coordinator.AnalyzeLatestAsync());
        await Assert.ThrowsAsync<ObjectDisposedException>(() => coordinator.MonitorNextSessionAsync());
    }

    [Fact]
    public async Task PackageDumpAsync_RejectsPathNotBoundToCompletedAnalysis()
    {
        using var directory = new TestDirectory();
        string dumpPath = Path.Combine(directory.Path, "unbound.dmp");
        await File.WriteAllBytesAsync(dumpPath, "MDMP"u8.ToArray(), CancellationToken.None);
        using var coordinator = new DiagnosticCoordinator(Path.Combine(directory.Path, "data"));

        InvalidOperationException exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            coordinator.PackageDumpAsync(dumpPath, cancellationToken: CancellationToken.None));

        Assert.Contains("not bound", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task MonitorCancellation_BeforeBf6Observation_RemovesActiveMarker()
    {
        using var directory = new TestDirectory();
        string dataRoot = Path.Combine(directory.Path, "data");
        var delayEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();
        using var coordinator = new DiagnosticCoordinator(
            dataRoot,
            _ => Task.FromResult(Sample(bf6Running: false)),
            (_, token) =>
            {
                delayEntered.TrySetResult();
                return Task.Delay(Timeout.InfiniteTimeSpan, token);
            });

        Task operation = coordinator.MonitorNextSessionAsync(cancellationToken: cancellation.Token);
        await delayEntered.Task.WaitAsync(TimeSpan.FromSeconds(30));
        string sessionFolder = Assert.Single(Directory.EnumerateDirectories(Path.Combine(dataRoot, "Sessions")));
        Assert.True(File.Exists(Path.Combine(sessionFolder, "ACTIVE.json")));

        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation);

        Assert.False(File.Exists(Path.Combine(sessionFolder, "ACTIVE.json")));
    }

    [Fact]
    public async Task MonitorCancellation_AfterBf6Observation_PreservesActiveMarkerAndJournal()
    {
        using var directory = new TestDirectory();
        string dataRoot = Path.Combine(directory.Path, "data");
        var delayEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();
        using var coordinator = new DiagnosticCoordinator(
            dataRoot,
            _ => Task.FromResult(Sample(bf6Running: true)),
            (_, token) =>
            {
                delayEntered.TrySetResult();
                return Task.Delay(Timeout.InfiniteTimeSpan, token);
            });

        Task operation = coordinator.MonitorNextSessionAsync(cancellationToken: cancellation.Token);
        await delayEntered.Task.WaitAsync(TimeSpan.FromSeconds(30));
        string sessionFolder = Assert.Single(Directory.EnumerateDirectories(Path.Combine(dataRoot, "Sessions")));

        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation);

        Assert.True(File.Exists(Path.Combine(sessionFolder, "ACTIVE.json")));
        string journal = Path.Combine(sessionFolder, "Performance-Samples.journal.jsonl");
        Assert.True(File.Exists(journal));
        Assert.Contains("\"BF6Running\":true", await File.ReadAllTextAsync(journal), StringComparison.Ordinal);
    }

    [Fact]
    public async Task MonitorCancellation_DuringFinalization_PreservesActiveMarker()
    {
        using var directory = new TestDirectory();
        string dataRoot = Path.Combine(directory.Path, "data");
        int sampleNumber = 0;
        var finalizationDelayEntered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        using var cancellation = new CancellationTokenSource();
        using var coordinator = new DiagnosticCoordinator(
            dataRoot,
            _ => Task.FromResult(Sample(bf6Running: Interlocked.Increment(ref sampleNumber) == 1)),
            (delay, token) =>
            {
                if (delay == TimeSpan.FromSeconds(30))
                {
                    finalizationDelayEntered.TrySetResult();
                    return Task.Delay(Timeout.InfiniteTimeSpan, token);
                }

                return Task.CompletedTask;
            });

        Task operation = coordinator.MonitorNextSessionAsync(cancellationToken: cancellation.Token);
        await finalizationDelayEntered.Task.WaitAsync(TimeSpan.FromSeconds(30));
        string sessionFolder = Assert.Single(Directory.EnumerateDirectories(Path.Combine(dataRoot, "Sessions")));

        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => operation);

        Assert.True(File.Exists(Path.Combine(sessionFolder, "ACTIVE.json")));
    }

    private static PerformanceSample Sample(bool bf6Running) =>
        new(
            DateTimeOffset.UtcNow,
            bf6Running,
            bf6Running ? 1234 : null,
            bf6Running ? "BF6" : string.Empty,
            20,
            16,
            16,
            20,
            40,
            50,
            bf6Running ? 4096 : null,
            bf6Running ? 3072 : null,
            bf6Running ? 50 : null,
            bf6Running ? 70 : null,
            bf6Running ? 80 : null,
            bf6Running ? 8192 : null,
            bf6Running ? 256 : null,
            5);
}
