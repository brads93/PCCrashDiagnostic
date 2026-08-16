using System.Security;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Core.Collectors;

public sealed class DumpInventoryCollector
{
    private const int DefaultMaximumCandidatesPerSource = 256;
    private readonly SafeDumpInspector _inspector;
    private readonly IReadOnlyList<DumpSearchRoot>? _searchRoots;
    private readonly int _maximumCandidatesPerSource;
    private readonly Func<bool> _isSensitiveOperationBlocked;

    public DumpInventoryCollector()
        : this(
            new SafeDumpInspector(),
            null,
            DefaultMaximumCandidatesPerSource,
            validateTestRoots: false,
            isSensitiveOperationBlocked: null)
    {
    }

    internal DumpInventoryCollector(
        SafeDumpInspector inspector,
        IReadOnlyList<DumpSearchRoot> searchRoots,
        int maximumCandidatesPerSource = DefaultMaximumCandidatesPerSource,
        Func<bool>? isSensitiveOperationBlocked = null)
        : this(
            inspector,
            searchRoots,
            maximumCandidatesPerSource,
            validateTestRoots: true,
            isSensitiveOperationBlocked: isSensitiveOperationBlocked)
    {
    }

    private DumpInventoryCollector(
        SafeDumpInspector inspector,
        IReadOnlyList<DumpSearchRoot>? searchRoots,
        int maximumCandidatesPerSource,
        bool validateTestRoots,
        Func<bool>? isSensitiveOperationBlocked)
    {
        _inspector = inspector ?? throw new ArgumentNullException(nameof(inspector));
        if (validateTestRoots)
        {
            ArgumentNullException.ThrowIfNull(searchRoots);
        }

        _searchRoots = searchRoots;
        _maximumCandidatesPerSource = maximumCandidatesPerSource > 0
            ? maximumCandidatesPerSource
            : throw new ArgumentOutOfRangeException(nameof(maximumCandidatesPerSource));
        _isSensitiveOperationBlocked = isSensitiveOperationBlocked ?? (() => false);
    }

    public Task<DumpInventory> CollectAsync(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        TargetProfile? targetProfile = null,
        CancellationToken cancellationToken = default)
        => CollectAsync(
            startUtc,
            endUtc,
            targetProfile,
            cancellationToken,
            isSensitiveOperationBlocked: null);

    internal Task<DumpInventory> CollectAsync(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        TargetProfile? targetProfile,
        CancellationToken cancellationToken,
        Func<bool>? isSensitiveOperationBlocked)
    {
        if (endUtc < startUtc)
        {
            throw new ArgumentOutOfRangeException(nameof(endUtc));
        }

        return Task.Run(
            () => Collect(
                startUtc.ToUniversalTime(),
                endUtc.ToUniversalTime(),
                targetProfile,
                cancellationToken,
                isSensitiveOperationBlocked),
            cancellationToken);
    }

    private DumpInventory Collect(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        TargetProfile? targetProfile,
        CancellationToken cancellationToken,
        Func<bool>? isSensitiveOperationBlocked)
    {
        var candidates = new List<DumpCandidate>();
        var statuses = new List<CollectionStatus>();
        try
        {
            foreach (DumpSearchRoot root in _searchRoots ?? DefaultRoots())
            {
                cancellationToken.ThrowIfCancellationRequested();
                ThrowIfSensitiveOperationBlocked(isSensitiveOperationBlocked);
                CollectRoot(
                    root,
                    startUtc,
                    endUtc,
                    targetProfile,
                    candidates,
                    statuses,
                    cancellationToken,
                    isSensitiveOperationBlocked);
            }

            ThrowIfSensitiveOperationBlocked(isSensitiveOperationBlocked);
        }
        catch (SensitiveDumpOperationBlockedException)
        {
            // Discard every candidate collected before the boundary changed. A
            // partially inspected inventory must never escape the collector.
            return BlockedInventory();
        }

        DumpCandidate[] ordered = candidates
            .GroupBy(candidate => candidate.OriginalPath ?? candidate.RedactedPath, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(candidate => candidate.LastWriteUtc)
            .ThenBy(candidate => candidate.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return new DumpInventory(ordered, statuses.ToArray());
    }

    private void CollectRoot(
        DumpSearchRoot root,
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        TargetProfile? targetProfile,
        ICollection<DumpCandidate> candidates,
        ICollection<CollectionStatus> statuses,
        CancellationToken cancellationToken,
        Func<bool>? isSensitiveOperationBlocked)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfSensitiveOperationBlocked(isSensitiveOperationBlocked);
            PathSafety.EnsureNoReparseComponents(root.Path);
            IEnumerable<string> paths;
            if (root.IsSingleFile)
            {
                paths = File.Exists(root.Path) ? [root.Path] : [];
            }
            else if (Directory.Exists(root.Path))
            {
                paths = EnumerateDumpFiles(
                    root.Path,
                    root.MaximumDepth,
                    () => IsSensitiveOperationBlocked(isSensitiveOperationBlocked),
                    cancellationToken);
            }
            else
            {
                statuses.Add(new CollectionStatus(root.Source, CollectionState.Available, "The expected dump location was not present."));
                return;
            }

            int count = 0;
            bool truncated = false;
            foreach (string path in paths)
            {
                cancellationToken.ThrowIfCancellationRequested();
                ThrowIfSensitiveOperationBlocked(isSensitiveOperationBlocked);
                if (root.RequireTargetMatch &&
                    (targetProfile is null || !targetProfile.MatchesArtifactName(Path.GetFileName(path))))
                {
                    continue;
                }

                var info = new FileInfo(path);
                info.Refresh();
                DateTimeOffset lastWriteUtc = info.LastWriteTimeUtc;
                if (!info.Exists || lastWriteUtc < startUtc || lastWriteUtc > endUtc)
                {
                    continue;
                }

                if (count >= _maximumCandidatesPerSource)
                {
                    truncated = true;
                    break;
                }

                DumpCandidate candidate = _inspector.Inspect(path, root.Kind, root.Source, cancellationToken);
                ThrowIfSensitiveOperationBlocked(isSensitiveOperationBlocked);
                candidates.Add(candidate);
                count++;
            }

            statuses.Add(new CollectionStatus(
                root.Source,
                CollectionState.Available,
                truncated
                    ? $"Inspected {count} dump candidates; additional matches were not read."
                    : $"Inspected {count} dump {(count == 1 ? "candidate" : "candidates")}."));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            statuses.Add(Denied(root.Source));
        }
        catch (SecurityException)
        {
            statuses.Add(Denied(root.Source));
        }
        catch (IOException exception)
        {
            statuses.Add(new CollectionStatus(
                root.Source,
                CollectionState.Error,
                $"Dump inventory could not enumerate this source (0x{exception.HResult:X8})."));
        }
    }

    private static IEnumerable<string> EnumerateDumpFiles(
        string root,
        int maximumDepth,
        Func<bool> isSensitiveOperationBlocked,
        CancellationToken cancellationToken)
    {
        var pending = new Queue<(string Path, int Depth)>();
        pending.Enqueue((root, 0));
        while (pending.TryDequeue(out (string Path, int Depth) current))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (isSensitiveOperationBlocked())
            {
                throw new SensitiveDumpOperationBlockedException();
            }

            foreach (string file in Directory.EnumerateFiles(current.Path, "*.dmp", SearchOption.TopDirectoryOnly))
            {
                if (isSensitiveOperationBlocked())
                {
                    throw new SensitiveDumpOperationBlockedException();
                }

                yield return file;
            }

            if (current.Depth >= maximumDepth)
            {
                continue;
            }

            foreach (string directory in Directory.EnumerateDirectories(current.Path, "*", SearchOption.TopDirectoryOnly))
            {
                if (isSensitiveOperationBlocked())
                {
                    throw new SensitiveDumpOperationBlockedException();
                }

                var info = new DirectoryInfo(directory);
                if ((info.Attributes & FileAttributes.ReparsePoint) == 0)
                {
                    pending.Enqueue((info.FullName, current.Depth + 1));
                }
            }
        }
    }

    private void ThrowIfSensitiveOperationBlocked(Func<bool>? perCollectionBoundary)
    {
        if (IsSensitiveOperationBlocked(perCollectionBoundary))
        {
            throw new SensitiveDumpOperationBlockedException();
        }
    }

    private bool IsSensitiveOperationBlocked(Func<bool>? perCollectionBoundary)
    {
        try
        {
            return _isSensitiveOperationBlocked() || (perCollectionBoundary?.Invoke() ?? false);
        }
        catch
        {
            return true;
        }
    }

    private static DumpInventory BlockedInventory() => new(
        [],
        [new CollectionStatus(
            "Dump inventory",
            CollectionState.Unavailable,
            "Dump inspection stopped because Battlefield 6 or the protected target started running; partial results were discarded.")]);

    private static IReadOnlyList<DumpSearchRoot> DefaultRoots()
    {
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        return
        [
            new DumpSearchRoot(
                "Dump inventory/Windows minidumps",
                Path.Combine(windows, "Minidump"),
                DumpKind.WindowsMinidump,
                MaximumDepth: 0),
            new DumpSearchRoot(
                "Dump inventory/Windows memory dump",
                Path.Combine(windows, "MEMORY.DMP"),
                DumpKind.WindowsMemoryDump,
                MaximumDepth: 0,
                IsSingleFile: true),
            new DumpSearchRoot(
                "Dump inventory/LiveKernelReports",
                Path.Combine(windows, "LiveKernelReports"),
                DumpKind.LiveKernelDump,
                MaximumDepth: 2),
            new DumpSearchRoot(
                "Dump inventory/Local application dumps",
                Path.Combine(localAppData, "CrashDumps"),
                DumpKind.ApplicationDump,
                MaximumDepth: 0,
                RequireTargetMatch: true)
        ];
    }

    private static CollectionStatus Denied(string source) => new(
        source,
        CollectionState.Denied,
        "Windows denied access. The collector did not request elevation.");
}

internal sealed record DumpSearchRoot(
    string Source,
    string Path,
    DumpKind Kind,
    int MaximumDepth,
    bool IsSingleFile = false,
    bool RequireTargetMatch = false);

internal sealed class SensitiveDumpOperationBlockedException : Exception
{
    public SensitiveDumpOperationBlockedException()
        : base("Dump inspection stopped because a protected target started running.")
    {
    }
}
