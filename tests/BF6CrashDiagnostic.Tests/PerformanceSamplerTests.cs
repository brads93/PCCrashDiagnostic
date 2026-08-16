using BF6CrashDiagnostic.Core.Collectors;

namespace BF6CrashDiagnostic.Tests;

public sealed class PerformanceSamplerTests
{
    [Fact]
    public void Sample_ForMissingTarget_ReturnsSystemMetricsWithoutInventingProcessData()
    {
        string missingName = "BF6DiagMissing" + Guid.NewGuid().ToString("N");
        using var sampler = new PerformanceSampler(missingName + ".exe");

        var sample = sampler.Sample();

        Assert.False(sample.BF6Running);
        Assert.Null(sample.BF6Pid);
        Assert.Equal(missingName, sample.BF6ProcessName);
        Assert.True(sample.SystemMemoryUsedGB >= 0);
        Assert.True(sample.SystemMemoryAvailableGB >= 0);
        Assert.True(sample.SystemCommitLimitGB > 0);
        Assert.InRange(sample.SystemCommitPct, 0, 100);
        Assert.Null(sample.BF6WorkingSetMB);
        Assert.Null(sample.BF6PrivateMB);
        Assert.Null(sample.BF6Gpu3DPct);
        Assert.True(sample.SampleCollectionMs < 5_000);
    }

    [Fact]
    public void ResetAndDispose_KeepLifecycleExplicit()
    {
        var sampler = new PerformanceSampler("BF6DiagMissing" + Guid.NewGuid().ToString("N"));

        sampler.Reset();
        sampler.Dispose();
        sampler.Dispose();

        Assert.Throws<ObjectDisposedException>(() => sampler.Sample());
        Assert.Throws<ObjectDisposedException>(() => sampler.Reset());
    }

    [Fact]
    public void ReadGpuEngineCounterValues_ReadsEachCounterOnceAndKeepsThreeDimensionalBelowOverallMaximum()
    {
        int[] counters = [1, 2, 3];
        var reads = counters.ToDictionary(counter => counter, _ => 0);
        var values = new Dictionary<int, float?>
        {
            [1] = 72,
            [2] = 51,
            [3] = 18
        };

        (double? maximum, double? threeDimensional) = PerformanceSampler.ReadGpuEngineCounterValues(
            counters,
            counter => counter is 2 or 3,
            counter =>
            {
                reads[counter]++;
                return values[counter];
            });

        Assert.Equal(72, maximum);
        Assert.Equal(51, threeDimensional);
        Assert.True(maximum >= threeDimensional);
        Assert.All(reads.Values, count => Assert.Equal(1, count));
    }
}
