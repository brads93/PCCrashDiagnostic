using System.Text.Json;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Reporting;

public sealed class ActiveSessionStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public async Task WriteAsync(
        ActiveSessionMarker marker,
        string sessionsRoot,
        CancellationToken cancellationToken = default)
    {
        ValidateWritableMarker(marker);
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionsRoot);
        string canonicalSessionsRoot = Path.GetFullPath(sessionsRoot);
        PathSafety.EnsureDirectory(canonicalSessionsRoot, canonicalSessionsRoot);
        string sessionFolder = PathSafety.EnsureDirectory(canonicalSessionsRoot, marker.SessionFolder);
        marker = marker with { SessionFolder = sessionFolder };
        string path = PathSafety.EnsureContained(canonicalSessionsRoot, Path.Combine(sessionFolder, "ACTIVE.json"));
        PathSafety.EnsureNoReparseComponents(canonicalSessionsRoot, path);
        string temporary = PathSafety.CreateRandomTemporaryPath(
            canonicalSessionsRoot,
            sessionFolder,
            "active-marker");
        bool committed = false;
        try
        {
            await using (var stream = new FileStream(
                             temporary,
                             FileMode.CreateNew,
                             FileAccess.Write,
                             FileShare.None,
                             32 * 1024,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                await JsonSerializer.SerializeAsync(stream, marker, JsonOptions, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            cancellationToken.ThrowIfCancellationRequested();
            PathSafety.EnsureSafeFileCommit(canonicalSessionsRoot, temporary, path);
            File.Move(temporary, path, overwrite: true);
            committed = true;
        }
        finally
        {
            if (!committed)
            {
                PathSafety.TryDeleteFile(canonicalSessionsRoot, temporary);
            }
        }
    }

    public void Complete(string sessionFolder, string sessionsRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionFolder);
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionsRoot);
        string canonicalSessionsRoot = Path.GetFullPath(sessionsRoot);
        string canonicalSessionFolder = PathSafety.EnsureContained(canonicalSessionsRoot, sessionFolder);
        string folderName = Path.GetFileName(canonicalSessionFolder.TrimEnd(
            Path.DirectorySeparatorChar,
            Path.AltDirectorySeparatorChar));
        if (!SessionIdValidator.IsValid(folderName))
        {
            throw new ArgumentException("The active-session folder name is invalid.", nameof(sessionFolder));
        }

        PathSafety.EnsureNoReparseComponents(canonicalSessionsRoot, canonicalSessionFolder);
        string path = PathSafety.EnsureContained(canonicalSessionsRoot, Path.Combine(canonicalSessionFolder, "ACTIVE.json"));
        PathSafety.EnsureNoReparseComponents(canonicalSessionsRoot, path);
        if (File.Exists(path))
        {
            PathSafety.EnsureSafeExistingFile(canonicalSessionsRoot, path);
            PathSafety.EnsureNoReparseComponents(canonicalSessionsRoot, path);
            File.Delete(path);
        }
    }

    public async Task<IReadOnlyList<RecoveryCandidate>> FindStaleAsync(
        string sessionsRoot,
        DateTimeOffset currentBootUtc,
        CancellationToken cancellationToken = default)
    {
        string canonicalSessionsRoot = Path.GetFullPath(sessionsRoot)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!Directory.Exists(canonicalSessionsRoot))
        {
            return [];
        }

        PathSafety.EnsureNoReparseComponents(canonicalSessionsRoot);
        var recovered = new List<RecoveryCandidate>();
        foreach (string candidateFolder in Directory.EnumerateDirectories(canonicalSessionsRoot, "*", SearchOption.TopDirectoryOnly))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                string sessionFolder = PathSafety.EnsureContained(canonicalSessionsRoot, candidateFolder);
                PathSafety.EnsureNoReparseComponents(canonicalSessionsRoot, sessionFolder);
                string markerPath = Path.Combine(sessionFolder, "ACTIVE.json");
                if (!File.Exists(markerPath))
                {
                    continue;
                }

                PathSafety.EnsureSafeExistingFile(canonicalSessionsRoot, markerPath);
                await using FileStream stream = new(markerPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 32 * 1024, useAsync: true);
                ActiveSessionMarker? marker = await JsonSerializer.DeserializeAsync<ActiveSessionMarker>(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
                if (!TryValidateRecoveredMarker(marker, sessionFolder, out ActiveSessionMarker safeMarker) ||
                    IsOwnerAlive(safeMarker))
                {
                    continue;
                }

                bool bootChanged = safeMarker.StartBootUtc is not null &&
                                   Math.Abs((safeMarker.StartBootUtc.Value - currentBootUtc).TotalMinutes) > 2;
                recovered.Add(new RecoveryCandidate(
                    safeMarker,
                    bootChanged,
                    safeMarker.LastSampleUtc,
                    bootChanged ? "RecoveredAfterSystemRestart" : "RecoveredAfterToolInterruption"));
            }
            catch (IOException)
            {
                // A live instance may be updating the marker.
            }
            catch (JsonException)
            {
                // A corrupt marker remains visible for manual review; it is not deleted automatically.
            }
            catch (UnauthorizedAccessException)
            {
                // Access failure is non-destructive and will be surfaced by the caller's collection status.
            }
        }

        return recovered;
    }

    private static void ValidateWritableMarker(ActiveSessionMarker marker)
    {
        ArgumentNullException.ThrowIfNull(marker);
        if (!Path.IsPathFullyQualified(marker.SessionFolder))
        {
            throw new ArgumentException("The active-session folder must be absolute.", nameof(marker));
        }

        string fullFolder = Path.GetFullPath(marker.SessionFolder);
        string folderName = Path.GetFileName(fullFolder.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        if (marker.MarkerSchemaVersion != 1 ||
            !SessionIdValidator.IsValid(marker.SessionId) ||
            !string.Equals(marker.SessionId, folderName, StringComparison.OrdinalIgnoreCase) ||
            marker.OwnerProcessId <= 0 ||
            marker.Mode != DiagnosticMode.Monitor ||
            marker.StartedUtc == default ||
            marker.LastSampleUtc < marker.StartedUtc)
        {
            throw new ArgumentException("The active-session marker is invalid.", nameof(marker));
        }
    }

    private static bool TryValidateRecoveredMarker(
        ActiveSessionMarker? marker,
        string canonicalSessionFolder,
        out ActiveSessionMarker safeMarker)
    {
        safeMarker = null!;
        if (marker is null ||
            marker.MarkerSchemaVersion != 1 ||
            marker.OwnerProcessId <= 0 ||
            marker.Mode != DiagnosticMode.Monitor ||
            !string.Equals(marker.ProcessName, "BF6", StringComparison.OrdinalIgnoreCase) ||
            !SessionIdValidator.IsValid(marker.SessionId) ||
            !string.Equals(marker.SessionId, Path.GetFileName(canonicalSessionFolder), StringComparison.OrdinalIgnoreCase) ||
            marker.StartedUtc == default ||
            marker.LastSampleUtc < marker.StartedUtc ||
            marker.LastSampleUtc - marker.StartedUtc > TimeSpan.FromDays(7) ||
            marker.LastSampleUtc > DateTimeOffset.UtcNow.AddMinutes(5) ||
            (marker.StartBootUtc is not null && marker.StartBootUtc > marker.StartedUtc.AddMinutes(5)))
        {
            return false;
        }

        safeMarker = marker with { SessionFolder = canonicalSessionFolder };
        return true;
    }

    private static bool IsOwnerAlive(ActiveSessionMarker marker)
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
        catch (System.ComponentModel.Win32Exception)
        {
            return true;
        }
    }
}
