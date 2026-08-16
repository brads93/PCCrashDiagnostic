using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Collectors;

/// <summary>
/// Samples Windows counters and public Process properties. It never reads process
/// memory, modules, handles, command lines, or anti-cheat state.
/// </summary>
public sealed class PerformanceSampler : IDisposable
{
    private const double BytesPerMegabyte = 1024d * 1024d;
    private const double BytesPerGigabyte = 1024d * 1024d * 1024d;

    private readonly object _sync = new();
    private readonly string _processName;
    private readonly string[] _processNames;
    private readonly TimeProvider _timeProvider;
    private readonly List<PerformanceCounter> _gpuEngineCounters = [];
    private readonly List<PerformanceCounter> _gpuThreeDimensionalCounters = [];
    private readonly List<PerformanceCounter> _gpuDedicatedCounters = [];
    private readonly List<PerformanceCounter> _gpuSharedCounters = [];
    private SystemCpuBaseline? _systemCpuBaseline;
    private readonly Dictionary<int, ProcessCpuBaseline> _processCpuBaselines = [];
    private readonly HashSet<int> _gpuCounterPids = [];
    private DateTimeOffset _gpuCountersLastRefreshedUtc;
    private bool _disposed;

    public PerformanceSampler(string processName = "BF6", TimeProvider? timeProvider = null)
        : this([processName], timeProvider)
    {
    }

    public PerformanceSampler(IReadOnlyList<string> processNames, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(processNames);
        _processNames = processNames
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Select(name => Path.GetFileNameWithoutExtension(name.Trim()))
            .Where(name => !string.IsNullOrWhiteSpace(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (_processNames.Length == 0)
        {
            throw new ArgumentException("At least one executable name is required.", nameof(processNames));
        }

        _processName = string.Join(";", _processNames);
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public Task<PerformanceSample> SampleAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => Sample(cancellationToken), cancellationToken);

    public Task<TargetPerformanceSample> SampleTargetAsync(CancellationToken cancellationToken = default) =>
        Task.Run(() => SampleTarget(cancellationToken), cancellationToken);

    public PerformanceSample Sample(CancellationToken cancellationToken = default)
    {
        lock (_sync)
        {
            TargetSampleData data = CollectSample(cancellationToken);
            return new PerformanceSample(
                data.TimestampUtc,
                data.Process.ProcessCount > 0,
                data.Process.PrimaryProcessId,
                _processName,
                data.SystemCpuPercent,
                data.SystemMemoryUsedGb,
                data.SystemMemoryAvailableGb,
                data.SystemCommittedGb,
                data.SystemCommitLimitGb,
                data.SystemCommitPercent,
                data.Process.WorkingSetBytes / BytesPerMegabyte,
                data.Process.PrivateBytes / BytesPerMegabyte,
                data.Process.CpuPercent,
                data.Gpu.ThreeDimensionalPercent,
                data.Gpu.MaximumEnginePercent,
                data.Gpu.DedicatedBytes / BytesPerMegabyte,
                data.Gpu.SharedBytes / BytesPerMegabyte,
                data.CollectionMilliseconds);
        }
    }

    public TargetPerformanceSample SampleTarget(CancellationToken cancellationToken = default)
    {
        lock (_sync)
        {
            TargetSampleData data = CollectSample(cancellationToken);
            return new TargetPerformanceSample(
                data.TimestampUtc,
                data.Process.ProcessCount > 0,
                data.Process.ProcessCount,
                data.SystemCpuPercent,
                data.SystemMemoryUsedGb,
                data.SystemMemoryAvailableGb,
                data.SystemCommittedGb,
                data.SystemCommitLimitGb,
                data.SystemCommitPercent,
                data.Process.WorkingSetBytes / BytesPerMegabyte,
                data.Process.PrivateBytes / BytesPerMegabyte,
                data.Process.CpuPercent,
                data.Gpu.ThreeDimensionalPercent,
                data.Gpu.MaximumEnginePercent,
                data.Gpu.DedicatedBytes / BytesPerMegabyte,
                data.Gpu.SharedBytes / BytesPerMegabyte,
                data.CollectionMilliseconds);
        }
    }

    private TargetSampleData CollectSample(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        cancellationToken.ThrowIfCancellationRequested();
        long sampleStarted = Stopwatch.GetTimestamp();
        DateTimeOffset timestampUtc = _timeProvider.GetUtcNow();
        MemoryStatus memory = GetMemoryStatus();
        double? systemCpu = SampleSystemCpu();
        ProcessSnapshot process = GetProcessSnapshot(timestampUtc, cancellationToken);
        GpuSnapshot gpu = process.ProcessIds.Count == 0
            ? GpuSnapshot.Unavailable
            : SampleGpu(process.ProcessIds, timestampUtc);
        double totalMemory = memory.TotalPhysicalBytes / BytesPerGigabyte;
        double availableMemory = memory.AvailablePhysicalBytes / BytesPerGigabyte;
        double commitLimit = memory.CommitLimitBytes / BytesPerGigabyte;
        double committed = memory.CommittedBytes / BytesPerGigabyte;
        double commitPercent = memory.CommitLimitBytes == 0
            ? 0
            : 100d * memory.CommittedBytes / memory.CommitLimitBytes;
        return new TargetSampleData(
            timestampUtc,
            systemCpu,
            Math.Max(0, totalMemory - availableMemory),
            availableMemory,
            committed,
            commitLimit,
            Math.Clamp(commitPercent, 0, 100),
            process,
            gpu,
            Stopwatch.GetElapsedTime(sampleStarted).TotalMilliseconds);
    }

    public void Reset()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _systemCpuBaseline = null;
            _processCpuBaselines.Clear();
            ResetGpuCounters();
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            ResetGpuCounters();
            _disposed = true;
        }
    }

    private ProcessSnapshot GetProcessSnapshot(
        DateTimeOffset timestampUtc,
        CancellationToken cancellationToken)
    {
        Process[] matches;
        try
        {
            matches = _processNames
                .SelectMany(Process.GetProcessesByName)
                .GroupBy(process => process.Id)
                .Select(group =>
                {
                    Process selected = group.First();
                    foreach (Process duplicate in group.Skip(1))
                    {
                        duplicate.Dispose();
                    }

                    return selected;
                })
                .OrderBy(process => process.Id)
                .ToArray();
        }
        catch (InvalidOperationException)
        {
            ResetProcessBaseline();
            return ProcessSnapshot.NotRunning;
        }

        var liveIds = new HashSet<int>();
        long workingSet = 0;
        long privateBytes = 0;
        double cpu = 0;
        bool hasCpu = false;
        try
        {
            foreach (Process candidate in matches)
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    if (candidate.HasExited)
                    {
                        continue;
                    }

                    candidate.Refresh();
                    int processId = candidate.Id;
                    liveIds.Add(processId);
                    workingSet = checked(workingSet + Math.Max(0, candidate.WorkingSet64));
                    privateBytes = checked(privateBytes + Math.Max(0, candidate.PrivateMemorySize64));
                    double? processCpu = CalculateProcessCpu(processId, candidate.TotalProcessorTime, timestampUtc);
                    if (processCpu is not null)
                    {
                        cpu += processCpu.Value;
                        hasCpu = true;
                    }
                }
                catch (InvalidOperationException)
                {
                    _processCpuBaselines.Remove(SafeProcessId(candidate));
                }
                catch (Win32Exception)
                {
                    _processCpuBaselines.Remove(SafeProcessId(candidate));
                }
            }

            foreach (int staleProcessId in _processCpuBaselines.Keys.Where(id => !liveIds.Contains(id)).ToArray())
            {
                _processCpuBaselines.Remove(staleProcessId);
            }

            if (liveIds.Count == 0)
            {
                ResetProcessBaseline();
                return ProcessSnapshot.NotRunning;
            }

            int[] processIds = liveIds.Order().ToArray();
            return new ProcessSnapshot(
                processIds.Length,
                processIds[0],
                processIds,
                workingSet,
                privateBytes,
                hasCpu ? Math.Clamp(cpu, 0, 100) : null);
        }
        catch (InvalidOperationException)
        {
            ResetProcessBaseline();
            return ProcessSnapshot.NotRunning;
        }
        catch (OverflowException)
        {
            ResetProcessBaseline();
            return ProcessSnapshot.NotRunning;
        }
        catch (Win32Exception)
        {
            ResetProcessBaseline();
            return ProcessSnapshot.NotRunning;
        }
        finally
        {
            foreach (Process process in matches)
            {
                process.Dispose();
            }
        }
    }

    private double? CalculateProcessCpu(
        int processId,
        TimeSpan totalProcessorTime,
        DateTimeOffset timestampUtc)
    {
        _processCpuBaselines.TryGetValue(processId, out ProcessCpuBaseline? previous);
        _processCpuBaselines[processId] = new ProcessCpuBaseline(processId, totalProcessorTime, timestampUtc);
        if (previous is null)
        {
            return null;
        }

        double elapsedMilliseconds = (timestampUtc - previous.TimestampUtc).TotalMilliseconds;
        double processMilliseconds = (totalProcessorTime - previous.TotalProcessorTime).TotalMilliseconds;
        if (elapsedMilliseconds <= 0 || processMilliseconds < 0)
        {
            return null;
        }

        double normalized = 100d * processMilliseconds /
            (elapsedMilliseconds * Math.Max(1, Environment.ProcessorCount));
        return Math.Clamp(normalized, 0, 100);
    }

    private void ResetProcessBaseline()
    {
        _processCpuBaselines.Clear();
        ResetGpuCounters();
    }

    private static int SafeProcessId(Process process)
    {
        try
        {
            return process.Id;
        }
        catch (InvalidOperationException)
        {
            return -1;
        }
    }

    private double? SampleSystemCpu()
    {
        if (!GetSystemTimes(out FileTime idle, out FileTime kernel, out FileTime user))
        {
            _systemCpuBaseline = null;
            return null;
        }

        var current = new SystemCpuBaseline(
            idle.ToUInt64(),
            kernel.ToUInt64(),
            user.ToUInt64());
        SystemCpuBaseline? previous = _systemCpuBaseline;
        _systemCpuBaseline = current;
        if (previous is null)
        {
            return null;
        }

        ulong idleDelta = SubtractWithoutUnderflow(current.Idle, previous.Idle);
        ulong kernelDelta = SubtractWithoutUnderflow(current.Kernel, previous.Kernel);
        ulong userDelta = SubtractWithoutUnderflow(current.User, previous.User);
        ulong totalDelta = kernelDelta + userDelta;
        if (totalDelta == 0 || idleDelta > totalDelta)
        {
            return null;
        }

        return Math.Clamp(100d * (totalDelta - idleDelta) / totalDelta, 0, 100);
    }

    private GpuSnapshot SampleGpu(IReadOnlyList<int> processIds, DateTimeOffset timestampUtc)
    {
        if (!_gpuCounterPids.SetEquals(processIds) ||
            timestampUtc - _gpuCountersLastRefreshedUtc >= TimeSpan.FromSeconds(30))
        {
            LoadGpuCounters(processIds, timestampUtc);
        }

        (double? maximumEngine, double? threeDimensional) = ReadGpuEngineCounterValues();
        double? dedicated = SumCounterValues(_gpuDedicatedCounters);
        double? shared = SumCounterValues(_gpuSharedCounters);
        return new GpuSnapshot(
            threeDimensional is null ? null : Math.Clamp(threeDimensional.Value, 0, 100),
            maximumEngine is null ? null : Math.Clamp(maximumEngine.Value, 0, 100),
            dedicated,
            shared);
    }

    private (double? MaximumEngine, double? ThreeDimensional) ReadGpuEngineCounterValues() =>
        ReadGpuEngineCounterValues(
            _gpuEngineCounters,
            counter => _gpuThreeDimensionalCounters.Contains(counter),
            TryNextValue);

    internal static (double? MaximumEngine, double? ThreeDimensional) ReadGpuEngineCounterValues<T>(
        IEnumerable<T> counters,
        Func<T, bool> isThreeDimensional,
        Func<T, float?> readValue)
    {
        ArgumentNullException.ThrowIfNull(counters);
        ArgumentNullException.ThrowIfNull(isThreeDimensional);
        ArgumentNullException.ThrowIfNull(readValue);

        double? maximumEngine = null;
        double? threeDimensional = null;
        foreach (T counter in counters)
        {
            float? value = readValue(counter);
            if (value is null || !double.IsFinite(value.Value))
            {
                continue;
            }

            maximumEngine = maximumEngine is null
                ? value.Value
                : Math.Max(maximumEngine.Value, value.Value);
            if (isThreeDimensional(counter))
            {
                threeDimensional = threeDimensional is null
                    ? value.Value
                    : Math.Max(threeDimensional.Value, value.Value);
            }
        }

        return (maximumEngine, threeDimensional);
    }

    private void LoadGpuCounters(IReadOnlyList<int> processIds, DateTimeOffset timestampUtc)
    {
        ResetGpuCounters();
        _gpuCounterPids.UnionWith(processIds);
        _gpuCountersLastRefreshedUtc = timestampUtc;
        string[] markers = processIds
            .Select(processId => $"pid_{processId.ToString(CultureInfo.InvariantCulture)}_")
            .ToArray();

        TryLoadCategoryCounters(
            "GPU Engine",
            "Utilization Percentage",
            markers,
            _gpuEngineCounters,
            (instance, counter) =>
            {
                if (instance.Contains("engtype_3D", StringComparison.OrdinalIgnoreCase))
                {
                    _gpuThreeDimensionalCounters.Add(counter);
                }
            });
        TryLoadCategoryCounters(
            "GPU Process Memory",
            "Dedicated Usage",
            markers,
            _gpuDedicatedCounters);
        TryLoadCategoryCounters(
            "GPU Process Memory",
            "Shared Usage",
            markers,
            _gpuSharedCounters);
    }

    private static void TryLoadCategoryCounters(
        string categoryName,
        string counterName,
        IReadOnlyList<string> processMarkers,
        ICollection<PerformanceCounter> destination,
        Action<string, PerformanceCounter>? added = null)
    {
        try
        {
            var category = new PerformanceCounterCategory(categoryName);
            foreach (string instance in category.GetInstanceNames()
                         .Where(instance => processMarkers.Any(marker =>
                             instance.Contains(marker, StringComparison.OrdinalIgnoreCase))))
            {
                var counter = new PerformanceCounter(categoryName, counterName, instance, readOnly: true);
                destination.Add(counter);
                added?.Invoke(instance, counter);
                _ = TryNextValue(counter);
            }
        }
        catch (InvalidOperationException)
        {
            // Optional counter category is unavailable or disabled.
        }
        catch (UnauthorizedAccessException)
        {
            // Optional counter category is not readable as the current user.
        }
        catch (Win32Exception)
        {
            // Optional counter category is unavailable or rebuilding.
        }
        catch (PlatformNotSupportedException)
        {
            // Optional counter category is unavailable on this platform.
        }
    }

    private static double? SumCounterValues(IEnumerable<PerformanceCounter> counters)
    {
        double sum = 0;
        bool found = false;
        foreach (PerformanceCounter counter in counters)
        {
            float? value = TryNextValue(counter);
            if (value is not null && double.IsFinite(value.Value))
            {
                sum += Math.Max(0, value.Value);
                found = true;
            }
        }

        return found ? sum : null;
    }

    private static float? TryNextValue(PerformanceCounter counter)
    {
        try
        {
            return counter.NextValue();
        }
        catch (InvalidOperationException)
        {
            return null;
        }
        catch (Win32Exception)
        {
            return null;
        }
    }

    private void ResetGpuCounters()
    {
        var unique = _gpuEngineCounters
            .Concat(_gpuDedicatedCounters)
            .Concat(_gpuSharedCounters)
            .Distinct()
            .ToArray();
        foreach (PerformanceCounter counter in unique)
        {
            counter.Dispose();
        }

        _gpuEngineCounters.Clear();
        _gpuThreeDimensionalCounters.Clear();
        _gpuDedicatedCounters.Clear();
        _gpuSharedCounters.Clear();
        _gpuCounterPids.Clear();
        _gpuCountersLastRefreshedUtc = default;
    }

    private static MemoryStatus GetMemoryStatus()
    {
        var native = new MemoryStatusEx();
        if (!GlobalMemoryStatusEx(native))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        ulong committed = native.TotalPageFile >= native.AvailablePageFile
            ? native.TotalPageFile - native.AvailablePageFile
            : 0;
        return new MemoryStatus(
            native.TotalPhysical,
            native.AvailablePhysical,
            committed,
            native.TotalPageFile);
    }

    private static ulong SubtractWithoutUnderflow(ulong value, ulong previous) =>
        value >= previous ? value - previous : 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx([In, Out] MemoryStatusEx buffer);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetSystemTimes(out FileTime idleTime, out FileTime kernelTime, out FileTime userTime);

    [StructLayout(LayoutKind.Sequential)]
    private sealed class MemoryStatusEx
    {
        public uint Length = checked((uint)Marshal.SizeOf<MemoryStatusEx>());
        public uint MemoryLoad;
        public ulong TotalPhysical;
        public ulong AvailablePhysical;
        public ulong TotalPageFile;
        public ulong AvailablePageFile;
        public ulong TotalVirtual;
        public ulong AvailableVirtual;
        public ulong AvailableExtendedVirtual;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct FileTime
    {
        private readonly uint _low;
        private readonly uint _high;

        public ulong ToUInt64() => ((ulong)_high << 32) | _low;
    }

    private sealed record SystemCpuBaseline(ulong Idle, ulong Kernel, ulong User);

    private sealed record ProcessCpuBaseline(
        int ProcessId,
        TimeSpan TotalProcessorTime,
        DateTimeOffset TimestampUtc);

    private sealed record ProcessSnapshot(
        int ProcessCount,
        int? PrimaryProcessId,
        IReadOnlyList<int> ProcessIds,
        double? WorkingSetBytes,
        double? PrivateBytes,
        double? CpuPercent)
    {
        public static ProcessSnapshot NotRunning { get; } = new(0, null, [], null, null, null);
    }

    private sealed record MemoryStatus(
        ulong TotalPhysicalBytes,
        ulong AvailablePhysicalBytes,
        ulong CommittedBytes,
        ulong CommitLimitBytes);

    private sealed record GpuSnapshot(
        double? ThreeDimensionalPercent,
        double? MaximumEnginePercent,
        double? DedicatedBytes,
        double? SharedBytes)
    {
        public static GpuSnapshot Unavailable { get; } = new(null, null, null, null);
    }

    private sealed record TargetSampleData(
        DateTimeOffset TimestampUtc,
        double? SystemCpuPercent,
        double SystemMemoryUsedGb,
        double SystemMemoryAvailableGb,
        double SystemCommittedGb,
        double SystemCommitLimitGb,
        double SystemCommitPercent,
        ProcessSnapshot Process,
        GpuSnapshot Gpu,
        double CollectionMilliseconds);
}
