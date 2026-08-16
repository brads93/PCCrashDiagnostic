using System.ComponentModel;
using System.Text;
using System.Text.Json;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Reporting;

public sealed class TargetSessionStore
{
    private const string MarkerName = "ACTIVE-v3.json";
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public async Task WriteAsync(
        ActiveTargetSessionMarker marker,
        string sessionsRoot,
        CancellationToken cancellationToken = default)
    {
        Validate(marker);
        string root = Path.GetFullPath(sessionsRoot);
        string folder = PathSafety.EnsureDirectory(root, marker.SessionFolder);
        string path = PathSafety.EnsureContained(root, Path.Combine(folder, MarkerName));
        string temporary = PathSafety.CreateRandomTemporaryPath(root, folder, "active-v3");
        try
        {
            await using (FileStream stream = new(
                             temporary,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             32 * 1024,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await JsonSerializer.SerializeAsync(stream, marker with { SessionFolder = folder }, JsonOptions, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            PathSafety.EnsureSafeFileCommit(root, temporary, path);
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            PathSafety.TryDeleteFile(root, temporary);
        }
    }

    public async Task<IReadOnlyList<TargetRecoveryCandidate>> FindStaleAsync(
        string sessionsRoot,
        DateTimeOffset currentBootUtc,
        CancellationToken cancellationToken = default)
    {
        string root = Path.GetFullPath(sessionsRoot);
        if (!Directory.Exists(root))
        {
            return [];
        }

        PathSafety.EnsureNoReparseComponents(root);
        var candidates = new List<TargetRecoveryCandidate>();
        foreach (string folder in Directory.EnumerateDirectories(root, "*", SearchOption.TopDirectoryOnly))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                string safeFolder = PathSafety.EnsureContained(root, folder);
                string path = Path.Combine(safeFolder, MarkerName);
                if (!File.Exists(path))
                {
                    continue;
                }

                PathSafety.EnsureSafeExistingFile(root, path);
                await using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 32 * 1024, useAsync: true);
                ActiveTargetSessionMarker? marker = await JsonSerializer.DeserializeAsync<ActiveTargetSessionMarker>(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
                if (!TryValidateRecovered(marker, safeFolder, out ActiveTargetSessionMarker safeMarker) || IsOwnerAlive(safeMarker))
                {
                    continue;
                }

                bool bootChanged = safeMarker.StartBootUtc is not null &&
                    Math.Abs((safeMarker.StartBootUtc.Value - currentBootUtc).TotalMinutes) > 2;
                candidates.Add(new TargetRecoveryCandidate(
                    safeMarker,
                    bootChanged,
                    bootChanged ? "RecoveredAfterSystemRestart" : "RecoveredAfterToolInterruption"));
            }
            catch (Exception exception) when (exception is IOException or JsonException or UnauthorizedAccessException)
            {
                // Leave the marker intact for a later retry or manual review.
            }
        }

        return candidates;
    }

    public void Complete(string sessionFolder, string sessionsRoot)
    {
        string root = Path.GetFullPath(sessionsRoot);
        string folder = PathSafety.EnsureContained(root, sessionFolder);
        string path = PathSafety.EnsureContained(root, Path.Combine(folder, MarkerName));
        PathSafety.EnsureNoReparseComponents(root, path);
        if (File.Exists(path))
        {
            PathSafety.EnsureSafeExistingFile(root, path);
            File.Delete(path);
        }
    }

    private static void Validate(ActiveTargetSessionMarker marker)
    {
        ArgumentNullException.ThrowIfNull(marker);
        if (marker.MarkerSchemaVersion != 3 ||
            marker.OwnerProcessId <= 0 ||
            !SessionIdValidator.IsValid(marker.SessionId) ||
            !Path.IsPathFullyQualified(marker.SessionFolder) ||
            marker.StartedUtc == default ||
            marker.LastSampleUtc < marker.StartedUtc ||
            marker.TargetProfile.ProcessNames.Count == 0)
        {
            throw new ArgumentException("The active target-session marker is invalid.", nameof(marker));
        }
    }

    private static bool TryValidateRecovered(
        ActiveTargetSessionMarker? marker,
        string folder,
        out ActiveTargetSessionMarker safe)
    {
        safe = null!;
        if (marker is null || marker.MarkerSchemaVersion != 3 || marker.OwnerProcessId <= 0 ||
            !SessionIdValidator.IsValid(marker.SessionId) ||
            !string.Equals(marker.SessionId, Path.GetFileName(folder), StringComparison.OrdinalIgnoreCase) ||
            marker.TargetProfile.ProcessNames.Count == 0 || marker.TargetProfile.ProcessNames.Count > 16 ||
            marker.StartedUtc == default || marker.LastSampleUtc < marker.StartedUtc ||
            marker.LastSampleUtc - marker.StartedUtc > TimeSpan.FromDays(7) ||
            marker.LastSampleUtc > DateTimeOffset.UtcNow.AddMinutes(5))
        {
            return false;
        }

        safe = marker with { SessionFolder = folder };
        return true;
    }

    private static bool IsOwnerAlive(ActiveTargetSessionMarker marker)
    {
        try
        {
            using System.Diagnostics.Process process = System.Diagnostics.Process.GetProcessById(marker.OwnerProcessId);
            return !process.HasExited && process.StartTime.ToUniversalTime() <= marker.StartedUtc.UtcDateTime.AddSeconds(5);
        }
        catch (ArgumentException)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (Win32Exception)
        {
            return true;
        }
    }
}

public sealed class TargetSampleJournal
{
    private static readonly UTF8Encoding Utf8NoBom = new(false);
    private readonly SemaphoreSlim _gate = new(1, 1);

    public string GetPath(string sessionFolder) => Path.Combine(sessionFolder, "Target-Samples.journal.jsonl");

    public async Task AppendAsync(string sessionFolder, TargetPerformanceSample sample, CancellationToken cancellationToken = default)
    {
        string root = Path.GetFullPath(sessionFolder);
        PathSafety.EnsureDirectory(root, root);
        string path = PathSafety.EnsureContained(root, GetPath(root));
        string line = JsonSerializer.Serialize(sample) + "\n";
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await File.AppendAllTextAsync(path, line, Utf8NoBom, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<IReadOnlyList<TargetPerformanceSample>> ReadAsync(string sessionFolder, CancellationToken cancellationToken = default)
    {
        string root = Path.GetFullPath(sessionFolder);
        string path = PathSafety.EnsureContained(root, GetPath(root));
        if (!File.Exists(path))
        {
            return [];
        }

        var samples = new List<TargetPerformanceSample>();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 64 * 1024, useAsync: true);
            using var reader = new StreamReader(stream, Utf8NoBom, detectEncodingFromByteOrderMarks: true);
            while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
            {
                try
                {
                    TargetPerformanceSample? sample = JsonSerializer.Deserialize<TargetPerformanceSample>(line);
                    if (sample is not null)
                    {
                        samples.Add(sample);
                    }
                }
                catch (JsonException)
                {
                    // Ignore a final partial line; earlier samples remain usable.
                }
            }
        }
        finally
        {
            _gate.Release();
        }

        return samples.OrderBy(sample => sample.TimestampUtc).ToArray();
    }
}
