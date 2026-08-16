using System.Security;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Collectors;

/// <summary>
/// Enumerates metadata for Windows-generated crash artifacts. File contents are never opened.
/// </summary>
public sealed class ArtifactCollector
{
    private const int MaximumArtifactsPerSource = 256;

    public Task<ArtifactCollection> CollectAsync(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        CancellationToken cancellationToken = default)
        => CollectAsync(startUtc, endUtc, TargetProfile.Battlefield6, cancellationToken);

    public Task<ArtifactCollection> CollectAsync(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        TargetProfile? targetProfile,
        CancellationToken cancellationToken = default)
    {
        ValidateWindow(startUtc, endUtc);
        return Task.Run(
            () => Collect(startUtc.ToUniversalTime(), endUtc.ToUniversalTime(), targetProfile, cancellationToken),
            cancellationToken);
    }

    private static ArtifactCollection Collect(
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        TargetProfile? targetProfile,
        CancellationToken cancellationToken)
    {
        var artifacts = new List<CrashArtifact>();
        var statuses = new List<CollectionStatus>();
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

        CollectFiles(
            "Crash artifacts/Windows minidumps",
            UnderRoot(windows, "Minidump"),
            "*.dmp",
            "Windows minidump",
            startUtc,
            endUtc,
            maximumDepth: 0,
            static _ => true,
            artifacts,
            statuses,
            cancellationToken);

        CollectSingleFile(
            "Crash artifacts/Windows memory dump",
            UnderRoot(windows, "MEMORY.DMP"),
            "Windows memory dump",
            startUtc,
            endUtc,
            artifacts,
            statuses,
            cancellationToken);

        CollectFiles(
            "Crash artifacts/LiveKernelReports",
            UnderRoot(windows, "LiveKernelReports"),
            "*.dmp",
            "Windows live-kernel dump",
            startUtc,
            endUtc,
            maximumDepth: 2,
            static _ => true,
            artifacts,
            statuses,
            cancellationToken);

        CollectFiles(
            "Crash artifacts/Local crash dumps",
            UnderRoot(localAppData, "CrashDumps"),
            "*.dmp",
            "Application crash dump",
            startUtc,
            endUtc,
            maximumDepth: 0,
            name => !DiagnosticSignalClassifier.IsDiagnosticToolSelfSignal(name) &&
                    (targetProfile?.MatchesArtifactName(name) ?? false),
            artifacts,
            statuses,
            cancellationToken);

        foreach ((string label, string path) in WerRoots(programData, localAppData))
        {
            CollectWerDirectories(
                label,
                path,
                startUtc,
                endUtc,
                targetProfile,
                artifacts,
                statuses,
                cancellationToken);
        }

        CrashArtifact[] ordered = artifacts
            .GroupBy(item => item.OriginalPath ?? item.RedactedPath, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(item => item.LastWriteUtc)
            .ThenBy(item => item.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return new ArtifactCollection(ordered, statuses.ToArray());
    }

    private static void CollectSingleFile(
        string source,
        string path,
        string kind,
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        ICollection<CrashArtifact> artifacts,
        ICollection<CollectionStatus> statuses,
        CancellationToken cancellationToken)
    {
        try
        {
        cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            {
                statuses.Add(new CollectionStatus(
                    source,
                    CollectionState.Available,
                    "The expected file was not present."));
                return;
            }

            FileInfo file = new(path);
            CrashArtifact? artifact = CreateFileArtifact(file, kind, startUtc, endUtc);
            if (artifact is not null)
            {
                artifacts.Add(artifact);
            }

            statuses.Add(new CollectionStatus(
                source,
                CollectionState.Available,
                artifact is null
                    ? "The file was present but outside the requested time window."
                    : "Collected metadata for one file."));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            statuses.Add(Denied(source));
        }
        catch (SecurityException)
        {
            statuses.Add(Denied(source));
        }
        catch (IOException exception)
        {
            statuses.Add(Error(source, exception));
        }
    }

    private static void CollectFiles(
        string source,
        string root,
        string pattern,
        string kind,
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        int maximumDepth,
        Func<string, bool> nameFilter,
        ICollection<CrashArtifact> artifacts,
        ICollection<CollectionStatus> statuses,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
            {
                statuses.Add(new CollectionStatus(
                    source,
                    CollectionState.Available,
                    "The expected directory was not present."));
                return;
            }

            int count = 0;
            bool truncated = false;
            foreach (string path in EnumerateFilesBounded(root, pattern, maximumDepth, cancellationToken))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!nameFilter(Path.GetFileName(path)))
                {
                    continue;
                }

                CrashArtifact? artifact = CreateFileArtifact(new FileInfo(path), kind, startUtc, endUtc);
                if (artifact is null)
                {
                    continue;
                }

                if (count >= MaximumArtifactsPerSource)
                {
                    truncated = true;
                    break;
                }

                artifacts.Add(artifact);
                count++;
            }

            statuses.Add(new CollectionStatus(
                source,
                CollectionState.Available,
                truncated
                    ? $"Collected metadata for {count} file(s); additional matches were not enumerated."
                    : $"Collected metadata for {count} file(s)."));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            statuses.Add(Denied(source));
        }
        catch (SecurityException)
        {
            statuses.Add(Denied(source));
        }
        catch (IOException exception)
        {
            statuses.Add(Error(source, exception));
        }
    }

    private static void CollectWerDirectories(
        string source,
        string root,
        DateTimeOffset startUtc,
        DateTimeOffset endUtc,
        TargetProfile? targetProfile,
        ICollection<CrashArtifact> artifacts,
        ICollection<CollectionStatus> statuses,
        CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
            {
                statuses.Add(new CollectionStatus(
                    source,
                    CollectionState.Available,
                    "The expected directory was not present."));
                return;
            }

            int count = 0;
            bool truncated = false;
            foreach (string path in Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly))
            {
                cancellationToken.ThrowIfCancellationRequested();
                DirectoryInfo directory = new(path);
                if (!IsRelevantWerName(directory.Name, targetProfile))
                {
                    continue;
                }

                DateTimeOffset lastWriteUtc = directory.LastWriteTimeUtc;
                if (lastWriteUtc < startUtc || lastWriteUtc > endUtc)
                {
                    continue;
                }

                if (count >= MaximumArtifactsPerSource)
                {
                    truncated = true;
                    break;
                }

                artifacts.Add(new CrashArtifact(
                    "Windows Error Reporting metadata",
                    directory.Name,
                    RedactPath(directory.FullName),
                    SumDirectFileSizes(directory.FullName, cancellationToken),
                    lastWriteUtc,
                    MayContainSensitiveData: true,
                    directory.FullName));
                count++;
            }

            statuses.Add(new CollectionStatus(
                source,
                CollectionState.Available,
                truncated
                    ? $"Collected metadata for {count} report folder(s); additional matches were not enumerated."
                    : $"Collected metadata for {count} report folder(s)."));
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            statuses.Add(Denied(source));
        }
        catch (SecurityException)
        {
            statuses.Add(Denied(source));
        }
        catch (IOException exception)
        {
            statuses.Add(Error(source, exception));
        }
    }

    private static IEnumerable<string> EnumerateFilesBounded(
        string root,
        string pattern,
        int maximumDepth,
        CancellationToken cancellationToken)
    {
        var pending = new Queue<(string Path, int Depth)>();
        pending.Enqueue((root, 0));
        while (pending.TryDequeue(out (string Path, int Depth) current))
        {
            cancellationToken.ThrowIfCancellationRequested();
            foreach (string file in Directory.EnumerateFiles(current.Path, pattern, SearchOption.TopDirectoryOnly))
            {
                yield return file;
            }

            if (current.Depth >= maximumDepth)
            {
                continue;
            }

            foreach (string directory in Directory.EnumerateDirectories(current.Path, "*", SearchOption.TopDirectoryOnly))
            {
                var info = new DirectoryInfo(directory);
                if ((info.Attributes & FileAttributes.ReparsePoint) == 0)
                {
                    pending.Enqueue((info.FullName, current.Depth + 1));
                }
            }
        }
    }

    private static CrashArtifact? CreateFileArtifact(
        FileInfo file,
        string kind,
        DateTimeOffset startUtc,
        DateTimeOffset endUtc)
    {
        DateTimeOffset lastWriteUtc = file.LastWriteTimeUtc;
        if (lastWriteUtc < startUtc || lastWriteUtc > endUtc)
        {
            return null;
        }

        return new CrashArtifact(
            kind,
            file.Name,
            RedactPath(file.FullName),
            file.Length,
            lastWriteUtc,
            MayContainSensitiveData: true,
            file.FullName);
    }

    private static long SumDirectFileSizes(string directory, CancellationToken cancellationToken)
    {
        long total = 0;
        foreach (string path in Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                long length = new FileInfo(path).Length;
                total = length > long.MaxValue - total ? long.MaxValue : total + length;
            }
            catch (IOException)
            {
                // One unavailable member does not prevent reporting folder metadata.
            }
            catch (UnauthorizedAccessException)
            {
                // One unavailable member does not prevent reporting folder metadata.
            }
        }

        return total;
    }

    private static IEnumerable<(string Label, string Path)> WerRoots(
        string programData,
        string localAppData)
    {
        string machineRoot = UnderRoot(programData, "Microsoft", "Windows", "WER");
        string userRoot = UnderRoot(localAppData, "Microsoft", "Windows", "WER");
        yield return ("Crash artifacts/WER machine archive", UnderRoot(machineRoot, "ReportArchive"));
        yield return ("Crash artifacts/WER machine queue", UnderRoot(machineRoot, "ReportQueue"));
        yield return ("Crash artifacts/WER user archive", UnderRoot(userRoot, "ReportArchive"));
        yield return ("Crash artifacts/WER user queue", UnderRoot(userRoot, "ReportQueue"));
    }

    private static string UnderRoot(string root, params string[] segments) =>
        string.IsNullOrWhiteSpace(root)
            ? string.Empty
            : Path.Combine([root, .. segments]);

    private static bool IsRelevantWerName(string name, TargetProfile? targetProfile) =>
        !DiagnosticSignalClassifier.IsDiagnosticToolSelfSignal(name) &&
        ((targetProfile?.MatchesArtifactName(name) ?? false) ||
         ContainsAny(name, "BlueScreen", "LiveKernelEvent", "HardwareError"));

    private static bool ContainsAny(string text, params string[] needles) =>
        needles.Any(needle => text.Contains(needle, StringComparison.OrdinalIgnoreCase));

    private static string RedactPath(string path)
    {
        string fullPath = Path.GetFullPath(path);
        foreach ((string token, string root) in RedactionRoots()
                     .Where(item => !string.IsNullOrWhiteSpace(item.Root))
                     .OrderByDescending(item => item.Root.Length))
        {
            string normalizedRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar);
            if (fullPath.Equals(normalizedRoot, StringComparison.OrdinalIgnoreCase))
            {
                return token;
            }

            string prefix = normalizedRoot + Path.DirectorySeparatorChar;
            if (fullPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            {
                return token + Path.DirectorySeparatorChar + fullPath[prefix.Length..];
            }
        }

        return "<redacted>" + Path.DirectorySeparatorChar + Path.GetFileName(fullPath);
    }

    private static IEnumerable<(string Token, string Root)> RedactionRoots()
    {
        yield return ("%LocalAppData%", Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData));
        yield return ("%ProgramData%", Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        yield return ("%SystemRoot%", Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        yield return ("%UserProfile%", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
    }

    private static CollectionStatus Denied(string source) => new(
        source,
        CollectionState.Denied,
        "Windows denied access. The collector did not request elevation.");

    private static CollectionStatus Error(string source, IOException exception) => new(
        source,
        CollectionState.Error,
        $"Artifact metadata could not be enumerated (0x{exception.HResult:X8}).");

    private static void ValidateWindow(DateTimeOffset startUtc, DateTimeOffset endUtc)
    {
        if (endUtc < startUtc)
        {
            throw new ArgumentOutOfRangeException(nameof(endUtc), "The end of the artifact window precedes its start.");
        }
    }
}
