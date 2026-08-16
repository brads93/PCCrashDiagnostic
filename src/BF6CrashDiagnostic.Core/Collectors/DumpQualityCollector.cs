using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Security;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Core.Collectors;

/// <summary>
/// Performs bounded container checks and can optionally run an installed, trusted
/// Microsoft SDK DumpChk executable. DumpChk output is interpreted locally and is
/// never retained in the result.
/// </summary>
public sealed class DumpQualityCollector
{
    private const int HeaderLength = 32;
    private const uint MaximumMiniDumpStreams = 4_096;
    private readonly IBoundedCommandRunner _runner;
    private readonly IDumpChkRequestValidator _validator;
    private readonly TimeProvider _timeProvider;

    public DumpQualityCollector()
        : this(new BoundedCommandRunner(), new DumpChkRequestValidator(), TimeProvider.System)
    {
    }

    internal DumpQualityCollector(
        IBoundedCommandRunner runner,
        IDumpChkRequestValidator validator,
        TimeProvider timeProvider)
    {
        _runner = runner;
        _validator = validator;
        _timeProvider = timeProvider;
    }

    public async Task<DumpQuality> InspectAsync(
        DumpQualityRequest request,
        CancellationToken cancellationToken = default,
        Func<bool>? isProtectedTargetRunning = null)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Dump);

        if (IsBlocked())
        {
            return BlockedResult();
        }

        DumpQuality internalResult = InspectInternal(request.Dump, cancellationToken, IsBlocked);
        if (IsBlocked())
        {
            return BlockedResult();
        }
        if (!request.RunDumpChk)
        {
            return internalResult;
        }

        if (request.DumpChk is null)
        {
            return internalResult with
            {
                DumpChkState = DumpChkState.NotFound,
                Detail = internalResult.Detail + " Microsoft DumpChk was not found in an approved Windows SDK directory."
            };
        }

        if (!_validator.IsAllowed(request.DumpChk))
        {
            return internalResult with
            {
                DumpChkState = DumpChkState.Rejected,
                Detail = internalResult.Detail + " The selected DumpChk executable was not an approved Microsoft-signed x64 SDK tool."
            };
        }

        if (internalResult.InternalState is DumpInternalQualityState.Invalid or
            DumpInternalQualityState.Unavailable or DumpInternalQualityState.Denied or
            DumpInternalQualityState.Failed ||
            string.IsNullOrWhiteSpace(request.Dump.OriginalPath))
        {
            return internalResult with
            {
                DumpChkState = DumpChkState.Error,
                Detail = internalResult.Detail + " DumpChk was not started because the bounded checks did not produce a safely readable dump."
            };
        }

        try
        {
            if (IsBlocked())
            {
                return BlockedResult();
            }

            var command = new BoundedCommandRequest(
                request.DumpChk.Path,
                [Path.GetFullPath(request.Dump.OriginalPath)],
                request.Timeout ?? TimeSpan.FromMinutes(1));
            BoundedCommandResult result;
            int blockedDuringRun = 0;
            using var runCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            Task protectedTargetMonitor = MonitorProtectedTargetAsync(
                IsBlocked,
                runCancellation,
                () => Interlocked.Exchange(ref blockedDuringRun, 1));
            try
            {
                result = await _runner.RunAsync(command, runCancellation.Token).ConfigureAwait(false);
            }
            finally
            {
                runCancellation.Cancel();
                try
                {
                    await protectedTargetMonitor.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Expected when the command completes or the caller cancels.
                }
            }

            if (Volatile.Read(ref blockedDuringRun) != 0)
            {
                return BlockedResult();
            }

            if (IsBlocked())
            {
                return BlockedResult();
            }
            if (result.Cancelled)
            {
                return WithDumpChk(internalResult, DumpChkState.Cancelled, request.DumpChk.Version,
                    "DumpChk was cancelled and its process tree was stopped.");
            }

            if (result.TimedOut)
            {
                return WithDumpChk(internalResult, DumpChkState.TimedOut, request.DumpChk.Version,
                    "DumpChk exceeded the configured time limit and its process tree was stopped.");
            }

            string output = result.StandardOutput + "\n" + result.StandardError;
            if (result.ExitCode == 0 &&
                output.Contains("Finished dump check", StringComparison.OrdinalIgnoreCase))
            {
                string detail = result.OutputTruncated
                    ? "DumpChk reported a finished check, but its local output exceeded the capture limit."
                    : "DumpChk reported that the dump check finished.";
                return WithDumpChk(internalResult, DumpChkState.Passed, request.DumpChk.Version, detail);
            }

            if (ContainsInvalidDumpMarker(output))
            {
                return WithDumpChk(internalResult, DumpChkState.Failed, request.DumpChk.Version,
                    "DumpChk reported that the dump was corrupt, incomplete, or could not be opened as a dump.");
            }

            return WithDumpChk(internalResult, DumpChkState.Error, request.DumpChk.Version,
                "DumpChk did not complete with a recognized validation result.");
        }
        catch (OperationCanceledException)
        {
            return WithDumpChk(internalResult, DumpChkState.Cancelled, request.DumpChk.Version,
                "DumpChk was cancelled before a result was available.");
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or Win32Exception)
        {
            return WithDumpChk(internalResult, DumpChkState.Error, request.DumpChk.Version,
                "DumpChk could not be started or contained safely.");
        }

        bool IsBlocked()
        {
            if (isProtectedTargetRunning is null)
            {
                return false;
            }

            try
            {
                return isProtectedTargetRunning();
            }
            catch
            {
                return true;
            }
        }

        DumpQuality BlockedResult() => new(
            _timeProvider.GetUtcNow().ToUniversalTime(),
            DumpQualityClassification.AnalysisUnavailable,
            request.Dump.Format,
            DumpInternalQualityState.Unavailable,
            false,
            false,
            null,
            DumpChkState.NotRequested,
            string.Empty,
            "Dump-quality inspection was unavailable because Battlefield 6 or the protected target was running.");
    }

    private static async Task MonitorProtectedTargetAsync(
        Func<bool> isProtectedTargetRunning,
        CancellationTokenSource runCancellation,
        Action onBlocked)
    {
        while (!runCancellation.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromMilliseconds(250), runCancellation.Token).ConfigureAwait(false);
            if (!isProtectedTargetRunning())
            {
                continue;
            }

            onBlocked();
            await runCancellation.CancelAsync().ConfigureAwait(false);
            return;
        }
    }

    private DumpQuality InspectInternal(
        DumpCandidate candidate,
        CancellationToken cancellationToken,
        Func<bool> isProtectedTargetRunning)
    {
        DateTimeOffset checkedUtc = _timeProvider.GetUtcNow().ToUniversalTime();
        if (string.IsNullOrWhiteSpace(candidate.OriginalPath))
        {
            return Result(DumpFormat.Unknown, DumpInternalQualityState.Unavailable, false, false, null,
                "The dump path was unavailable.");
        }

        string fullPath;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (isProtectedTargetRunning())
            {
                return Result(DumpFormat.Unknown, DumpInternalQualityState.Unavailable, false, false, null,
                    "Dump-quality inspection stopped because a protected target started running.");
            }

            fullPath = Path.GetFullPath(candidate.OriginalPath);
            PathSafety.EnsureNoReparseComponents(fullPath);
            var before = new FileInfo(fullPath);
            before.Refresh();
            if (!before.Exists)
            {
                return Result(DumpFormat.Unknown, DumpInternalQualityState.Unavailable, false, false, null,
                    "The dump file was not present.");
            }

            long length = before.Length;
            DateTime lastWriteUtc = before.LastWriteTimeUtc;
            byte[] header = new byte[HeaderLength];
            int bytesRead = 0;
            using (var input = new FileStream(
                       fullPath,
                       FileMode.Open,
                       FileAccess.Read,
                       FileShare.ReadWrite | FileShare.Delete,
                       HeaderLength,
                       FileOptions.SequentialScan))
            {
                while (bytesRead < header.Length)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (isProtectedTargetRunning())
                    {
                        return Result(DumpFormat.Unknown, DumpInternalQualityState.Unavailable, false, false, null,
                            "Dump-quality inspection stopped because a protected target started running.");
                    }

                    int read = input.Read(header, bytesRead, header.Length - bytesRead);
                    if (read == 0)
                    {
                        break;
                    }

                    bytesRead += read;
                }
            }

            var after = new FileInfo(fullPath);
            after.Refresh();
            if (isProtectedTargetRunning())
            {
                return Result(DumpFormat.Unknown, DumpInternalQualityState.Unavailable, false, false, null,
                    "Dump-quality inspection stopped because a protected target started running.");
            }

            if (!after.Exists || after.Length != length || after.LastWriteTimeUtc != lastWriteUtc)
            {
                return Result(DumpFormat.Unknown, DumpInternalQualityState.Failed, false, false, null,
                    "The dump changed during the bounded quality check.");
            }

            DumpFormat format = SafeDumpInspector.IdentifyFormat(header.AsSpan(0, bytesRead));
            if (format == DumpFormat.Unknown)
            {
                return Result(format, DumpInternalQualityState.Invalid, false, false, null,
                    "The fixed header did not contain a recognized Windows dump signature.");
            }

            bool plausible = format == DumpFormat.MiniDump ? length >= HeaderLength : length >= 4_096;
            if (!plausible)
            {
                return Result(format, DumpInternalQualityState.Invalid, true, false, null,
                    "The dump signature was recognized, but the file was below the minimum bounded size check.");
            }

            if (format != DumpFormat.MiniDump)
            {
                return Result(format, DumpInternalQualityState.HeaderOnly, true, true, null,
                    "The kernel dump signature and minimum size were recognized; deeper validation requires DumpChk or WinDbg.");
            }

            uint streamCount = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(8, 4));
            uint directoryRva = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(12, 4));
            if (streamCount > MaximumMiniDumpStreams)
            {
                return Result(format, DumpInternalQualityState.Invalid, true, true, false,
                    "The MDMP stream count exceeded the bounded structural limit.",
                    DumpQualityClassification.Corrupt);
            }

            bool boundsValid = checked((ulong)directoryRva + ((ulong)streamCount * 12UL)) <= (ulong)length;
            return boundsValid
                ? Result(format, DumpInternalQualityState.Valid, true, true, true,
                    "The MDMP header and stream-directory bounds passed bounded structural checks.")
                : Result(format, DumpInternalQualityState.Invalid, true, true, false,
                    "The MDMP stream directory extended beyond the end of the file.",
                    DumpQualityClassification.Truncated);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            return Result(DumpFormat.Unknown, DumpInternalQualityState.Denied, false, false, null,
                "Windows denied access to the dump.");
        }
        catch (SecurityException)
        {
            return Result(DumpFormat.Unknown, DumpInternalQualityState.Denied, false, false, null,
                "Windows denied access to the dump.");
        }
        catch (Exception exception) when (exception is IOException or ArgumentException or NotSupportedException or OverflowException)
        {
            return Result(DumpFormat.Unknown, DumpInternalQualityState.Failed, false, false, null,
                "The dump could not be checked safely.");
        }

        DumpQuality Result(
            DumpFormat format,
            DumpInternalQualityState state,
            bool recognized,
            bool plausible,
            bool? directoryBounds,
            string detail,
            DumpQualityClassification? classification = null) => new(
                checkedUtc,
                classification ?? Classify(state, recognized),
                format,
                state,
                recognized,
                plausible,
                directoryBounds,
                DumpChkState.NotRequested,
                string.Empty,
                detail);
    }

    private static DumpQualityClassification Classify(
        DumpInternalQualityState state,
        bool signatureRecognized) => state switch
        {
            DumpInternalQualityState.Valid => DumpQualityClassification.Valid,
            DumpInternalQualityState.HeaderOnly => DumpQualityClassification.Recognized,
            DumpInternalQualityState.Invalid when signatureRecognized => DumpQualityClassification.Truncated,
            DumpInternalQualityState.Invalid => DumpQualityClassification.Corrupt,
            DumpInternalQualityState.Unavailable or DumpInternalQualityState.Denied =>
                DumpQualityClassification.Inaccessible,
            _ => DumpQualityClassification.AnalysisUnavailable
        };

    private static DumpQuality WithDumpChk(
        DumpQuality result,
        DumpChkState state,
        string version,
        string detail) => result with
    {
        Classification = state switch
        {
            DumpChkState.Passed => DumpQualityClassification.Valid,
            DumpChkState.Failed => DumpQualityClassification.Corrupt,
            _ => result.Classification
        },
        DumpChkState = state,
        DumpChkVersion = version,
        Detail = result.Detail + " " + detail
    };

    private static bool ContainsInvalidDumpMarker(string output) =>
        output.Contains("DebugClient cannot open DumpFile", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("Could not match Dump File signature", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("dump file is corrupt", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("dump file is corrupted", StringComparison.OrdinalIgnoreCase);
}

public sealed class DumpChkDiscovery
{
    private readonly IDumpChkExecutableVerifier _verifier;

    public DumpChkDiscovery()
        : this(new AuthenticodeDumpChkExecutableVerifier())
    {
    }

    internal DumpChkDiscovery(IDumpChkExecutableVerifier verifier) => _verifier = verifier;

    public IReadOnlyList<DumpChkInstallation> Discover()
    {
        var candidates = new List<DumpChkCandidate>();
        foreach (string programFiles in new[]
                 {
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)
                 }.Where(value => !string.IsNullOrWhiteSpace(value)))
        {
            string root = Path.Combine(programFiles, "Windows Kits", "10", "Debuggers", "x64");
            candidates.Add(new DumpChkCandidate(Path.Combine(root, "dumpchk.exe"), root, "Windows SDK"));
        }

        return DiscoverCandidates(candidates);
    }

    internal IReadOnlyList<DumpChkInstallation> DiscoverCandidates(IEnumerable<DumpChkCandidate> candidates)
    {
        var results = new List<DumpChkInstallation>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (DumpChkCandidate candidate in candidates)
        {
            try
            {
                string fullPath = Path.GetFullPath(candidate.Path);
                if (!candidate.IsApprovedPath(fullPath) || !seen.Add(fullPath) || !File.Exists(fullPath))
                {
                    continue;
                }

                CdbVerificationResult verification = _verifier.Verify(fullPath);
                if (verification.IsMicrosoftSigned && verification.IsX64)
                {
                    results.Add(new DumpChkInstallation(
                        fullPath,
                        verification.Version,
                        candidate.Source,
                        true,
                        true,
                        verification.Signer));
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SecurityException or ArgumentException)
            {
            }
        }

        return results
            .OrderByDescending(item => Version.TryParse(item.Version, out Version? version) ? version : new Version())
            .ThenBy(item => item.Path, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}

internal sealed record DumpChkCandidate(string Path, string ApprovedRoot, string Source)
{
    public bool IsApprovedPath(string fullPath)
    {
        string fullRoot = System.IO.Path.GetFullPath(ApprovedRoot).TrimEnd(System.IO.Path.DirectorySeparatorChar);
        string expected = System.IO.Path.Combine(fullRoot, "dumpchk.exe");
        return string.Equals(fullPath, expected, StringComparison.OrdinalIgnoreCase) &&
               !FileSystemInfoHelpers.HasReparseComponent(fullRoot, fullPath);
    }
}

internal interface IDumpChkExecutableVerifier
{
    CdbVerificationResult Verify(string path);
}

internal sealed class AuthenticodeDumpChkExecutableVerifier : IDumpChkExecutableVerifier
{
    public CdbVerificationResult Verify(string path) => new AuthenticodeCdbExecutableVerifier().Verify(path);
}

internal interface IDumpChkRequestValidator
{
    bool IsAllowed(DumpChkInstallation installation);
}

internal sealed class DumpChkRequestValidator : IDumpChkRequestValidator
{
    private readonly IDumpChkExecutableVerifier _verifier = new AuthenticodeDumpChkExecutableVerifier();

    public bool IsAllowed(DumpChkInstallation installation)
    {
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(installation.Path);
        }
        catch (ArgumentException)
        {
            return false;
        }

        bool approved = false;
        foreach (string programFiles in new[]
                 {
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)
                 }.Where(value => !string.IsNullOrWhiteSpace(value)))
        {
            string root = Path.Combine(programFiles, "Windows Kits", "10", "Debuggers", "x64");
            approved |= new DumpChkCandidate(Path.Combine(root, "dumpchk.exe"), root, "Windows SDK")
                .IsApprovedPath(fullPath);
        }

        if (!approved)
        {
            return false;
        }

        CdbVerificationResult result = _verifier.Verify(fullPath);
        return result.IsMicrosoftSigned && result.IsX64;
    }
}
