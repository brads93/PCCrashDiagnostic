using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;
using Microsoft.Win32.SafeHandles;

namespace BF6CrashDiagnostic.Core.Analysis;

public sealed class WinDbgRunner
{
    private const string MicrosoftSymbolServer = "https://msdl.microsoft.com/download/symbols";
    private readonly IDebuggerProcessHost _processHost;
    private readonly IDebuggerRequestValidator _validator;
    private readonly IUserTokenInspector _userTokenInspector;

    public WinDbgRunner()
        : this(new DebuggerProcessHost(), new DebuggerRequestValidator(), new UserTokenInspector())
    {
    }

    internal WinDbgRunner(
        IDebuggerProcessHost processHost,
        IDebuggerRequestValidator validator,
        IUserTokenInspector userTokenInspector)
    {
        _processHost = processHost;
        _validator = validator;
        _userTokenInspector = userTokenInspector;
    }

    public async Task<DebuggerAnalysis> AnalyzeAsync(
        WinDbgAnalysisRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Dump);
        ArgumentNullException.ThrowIfNull(request.Debugger);
        ArgumentNullException.ThrowIfNull(request.IsProtectedTargetRunning);

        DateTimeOffset startedUtc = DateTimeOffset.UtcNow;
        if (request.IsProtectedTargetRunning())
        {
            return Empty(
                DebuggerAnalysisState.BlockedWhileProtectedTargetRunning,
                startedUtc,
                request,
                "Debugger analysis is unavailable while the protected target is running.");
        }

        if (_userTokenInspector.IsElevated())
        {
            return Empty(
                DebuggerAnalysisState.Failed,
                startedUtc,
                request,
                "WinDbg is never run from an elevated process. Restart the app normally and try again.");
        }

        if (!_validator.IsAllowedDebugger(request.Debugger))
        {
            return Empty(
                DebuggerAnalysisState.InvalidDebuggerSignature,
                startedUtc,
                request,
                "cdb.exe was not an x64 Microsoft-signed debugger in an approved WinDbg or Windows SDK directory.");
        }

        if (request.SymbolAccess == SymbolAccessMode.MicrosoftPublicServer &&
            !request.MicrosoftSymbolDownloadConsent)
        {
            return Empty(
                DebuggerAnalysisState.Failed,
                startedUtc,
                request,
                "Microsoft symbol downloads require explicit consent for this retry.");
        }

        if (request.Timeout < TimeSpan.FromSeconds(5) || request.Timeout > TimeSpan.FromMinutes(10))
        {
            throw new ArgumentOutOfRangeException(nameof(request), "The debugger timeout must be between 5 seconds and 10 minutes.");
        }

        (string dumpPath, DumpArtifactIdentity approvedIdentity) = ValidateDump(request.Dump);
        string symbolCache = ValidateAndCreatePrivateDirectory(request.SymbolCachePath);
        string rawLogDirectory = ValidateAndCreatePrivateDirectory(request.RawLogDirectory);
        cancellationToken.ThrowIfCancellationRequested();

        await using var stableDump = new FileStream(
            dumpPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        DumpArtifactIdentity openedIdentity = DumpPackager.CaptureIdentity(
            dumpPath,
            approvedIdentity.SizeBytes,
            approvedIdentity.LastWriteTimeUtc);
        if (!string.Equals(
                approvedIdentity.FileIdentityHash,
                openedIdentity.FileIdentityHash,
                StringComparison.Ordinal))
        {
            throw new IOException("The selected dump changed before debugger launch.");
        }

        string dumpSha256;
        using (IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            byte[] buffer = new byte[1024 * 1024];
            while (true)
            {
                if (request.IsProtectedTargetRunning())
                {
                    return Empty(
                        DebuggerAnalysisState.BlockedWhileProtectedTargetRunning,
                        startedUtc,
                        request,
                        "Dump hashing stopped because the protected target started running.");
                }

                int read = await stableDump.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                hash.AppendData(buffer.AsSpan(0, read));
            }

            dumpSha256 = Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        }

        if (request.IsProtectedTargetRunning())
        {
            return Empty(
                DebuggerAnalysisState.BlockedWhileProtectedTargetRunning,
                startedUtc,
                request,
                "Debugger analysis was stopped before launch because the protected target started running.",
                dumpSha256);
        }

        string symbolPath = request.SymbolAccess == SymbolAccessMode.LocalOnly
            ? symbolCache
            : $"srv*{symbolCache}*{MicrosoftSymbolServer}";
        string commandList = ReleaseStage.Beta2FeaturesEnabled
            ? $".reload /f; !analyze -v; " +
              $".echo {WinDbgOutputParser.BeginBlackboxBsd}; !blackboxbsd; .echo {WinDbgOutputParser.EndBlackboxBsd}; " +
              $".echo {WinDbgOutputParser.BeginBlackboxScm}; !blackboxscm; .echo {WinDbgOutputParser.EndBlackboxScm}; q"
            : ".reload /f; !analyze -v; q";
        var invocation = new DebuggerInvocation(
            request.Debugger.Path,
            dumpPath,
            symbolPath,
            commandList,
            request.Timeout,
            request.IsProtectedTargetRunning);

        DebuggerProcessResult processResult;
        try
        {
            processResult = await _processHost.RunAsync(invocation, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return Empty(
                DebuggerAnalysisState.Cancelled,
                startedUtc,
                request,
                "Debugger analysis was cancelled and its process tree was stopped.",
                dumpSha256);
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return Empty(
                DebuggerAnalysisState.Failed,
                startedUtc,
                request,
                "The debugger could not be started or contained safely.",
                dumpSha256);
        }

        string rawLogPath = Path.Combine(
            rawLogDirectory,
            $"windbg-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}-{Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant()}.log");
        string standardOutputTruncationNotice = processResult.StandardOutputTruncated
            ? $"{Environment.NewLine}[PC Crash Diagnostic: standard output exceeded the {DebuggerProcessHost.StandardStreamCaptureLimitCharacters:N0}-character capture limit; remaining output was discarded while the stream was drained.]"
            : string.Empty;
        string standardErrorTruncationNotice = processResult.StandardErrorTruncated
            ? $"{Environment.NewLine}[PC Crash Diagnostic: standard error exceeded the {DebuggerProcessHost.StandardStreamCaptureLimitCharacters:N0}-character capture limit; remaining output was discarded while the stream was drained.]"
            : string.Empty;
        string combinedOutput = processResult.StandardOutput +
                                standardOutputTruncationNotice +
                                Environment.NewLine +
                                "--- standard error ---" +
                                Environment.NewLine +
                                processResult.StandardError +
                                standardErrorTruncationNotice;
        await File.WriteAllTextAsync(
                rawLogPath,
                combinedOutput,
                new UTF8Encoding(false),
                cancellationToken)
            .ConfigureAwait(false);

        ParsedDebuggerOutput parsed = WinDbgOutputParser.Parse(combinedOutput);
        DebuggerAnalysisState state = processResult.ProtectedTargetStarted
            ? DebuggerAnalysisState.BlockedWhileProtectedTargetRunning
            : processResult.TimedOut
                ? DebuggerAnalysisState.TimedOut
                : processResult.Cancelled
                    ? DebuggerAnalysisState.Cancelled
                    : processResult.ExitCode == 0
                        ? DebuggerAnalysisState.Completed
                        : DebuggerAnalysisState.Failed;
        string limitation = state switch
        {
            DebuggerAnalysisState.Completed =>
                "These fields are what WinDbg reported. They do not confirm that a named module caused the incident.",
            DebuggerAnalysisState.TimedOut =>
                "WinDbg exceeded the configured time limit and its process tree was stopped.",
            DebuggerAnalysisState.Cancelled =>
                "WinDbg was cancelled and its process tree was stopped.",
            DebuggerAnalysisState.BlockedWhileProtectedTargetRunning =>
                "WinDbg was stopped because the protected target started running.",
            _ => "WinDbg did not complete successfully; any partial fields are informational only."
        };
        if (processResult.StandardOutputTruncated || processResult.StandardErrorTruncated)
        {
            limitation += " WinDbg output exceeded the local capture limit and was truncated; structured fields may be incomplete.";
        }

        return new DebuggerAnalysis(
            state,
            startedUtc,
            DateTimeOffset.UtcNow,
            request.SymbolAccess,
            request.Debugger.Version,
            dumpSha256,
            parsed.BugcheckCode,
            parsed.BugcheckParameters,
            parsed.FailureBucket,
            parsed.ModuleName,
            parsed.ImageName,
            parsed.ProcessName,
            parsed.SymbolStatus,
            parsed.StackModules,
            limitation,
            rawLogPath,
            parsed.BlackboxAvailable.Count > 0 ||
            parsed.BlackboxBootStatus is not null ||
            parsed.BlackboxServiceControlRequests.Count > 0
                ? new DebuggerBlackboxSummary(
                    parsed.BlackboxAvailable,
                    parsed.BlackboxBootStatus,
                    parsed.BlackboxServiceControlRequests)
                : null);
    }

    private static (string Path, DumpArtifactIdentity Identity) ValidateDump(DumpCandidate dump)
    {
        if (string.IsNullOrWhiteSpace(dump.OriginalPath) ||
            dump.InspectionState != DumpInspectionState.Recognized ||
            dump.Format == DumpFormat.Unknown)
        {
            throw new InvalidDataException("A recognized, locally accessible dump candidate is required.");
        }

        string fullPath = Path.GetFullPath(dump.OriginalPath);
        DumpArtifactIdentity identity = DumpPackager.CaptureIdentity(fullPath, dump.SizeBytes, dump.LastWriteUtc);
        return (fullPath, identity);
    }

    private static string ValidateAndCreatePrivateDirectory(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (path.Any(character => character is '"' or '\r' or '\n' || char.IsControl(character)))
        {
            throw new ArgumentException("The local directory path contained unsupported characters.", nameof(path));
        }

        string fullPath = Path.GetFullPath(path);
        Directory.CreateDirectory(fullPath);
        if (FileSystemInfoHelpers.HasReparseComponent(fullPath, fullPath))
        {
            throw new IOException("The local directory cannot be a reparse path.");
        }

        PrivateDirectoryAcl.TryRestrictToCurrentUserAndSystem(fullPath);
        return fullPath;
    }

    private static DebuggerAnalysis Empty(
        DebuggerAnalysisState state,
        DateTimeOffset startedUtc,
        WinDbgAnalysisRequest request,
        string limitation,
        string dumpSha256 = "") =>
        new(
            state,
            startedUtc,
            DateTimeOffset.UtcNow,
            request.SymbolAccess,
            request.Debugger.Version,
            dumpSha256,
            string.Empty,
            [],
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            "Not reported",
            [],
            limitation);
}

internal sealed record DebuggerInvocation(
    string ExecutablePath,
    string DumpPath,
    string SymbolPath,
    string CommandList,
    TimeSpan Timeout,
    Func<bool> IsProtectedTargetRunning);

internal sealed record DebuggerProcessResult(
    int? ExitCode,
    string StandardOutput,
    string StandardError,
    bool TimedOut,
    bool Cancelled,
    bool ProtectedTargetStarted,
    bool StandardOutputTruncated = false,
    bool StandardErrorTruncated = false);

internal interface IDebuggerProcessHost
{
    Task<DebuggerProcessResult> RunAsync(DebuggerInvocation invocation, CancellationToken cancellationToken);
}

internal interface IDebuggerRequestValidator
{
    bool IsAllowedDebugger(CdbInstallation installation);
}

internal interface IUserTokenInspector
{
    bool IsElevated();
}

internal sealed class DebuggerRequestValidator : IDebuggerRequestValidator
{
    private readonly ICdbExecutableVerifier _verifier = new AuthenticodeCdbExecutableVerifier();

    public bool IsAllowedDebugger(CdbInstallation installation)
    {
        if (!CdbPathPolicy.IsApprovedInstalledPath(installation.Path))
        {
            return false;
        }

        CdbVerificationResult result = _verifier.Verify(installation.Path);
        return result.IsMicrosoftSigned && result.IsX64;
    }
}

internal static class CdbPathPolicy
{
    public static bool IsApprovedInstalledPath(string path)
    {
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (ArgumentException)
        {
            return false;
        }

        foreach (string programFiles in new[]
                 {
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                     Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)
                 }.Where(item => !string.IsNullOrWhiteSpace(item)))
        {
            string sdkRoot = Path.Combine(programFiles, "Windows Kits", "10", "Debuggers", "x64");
            if (new CdbCandidate(Path.Combine(sdkRoot, "cdb.exe"), sdkRoot, "Windows SDK")
                .IsApprovedPath(fullPath))
            {
                return true;
            }
        }

        string nativeProgramFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!string.IsNullOrWhiteSpace(nativeProgramFiles))
        {
            string windowsApps = Path.Combine(nativeProgramFiles, "WindowsApps");
            try
            {
                string relative = Path.GetRelativePath(windowsApps, fullPath);
                string[] parts = relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                if (parts.Length == 3 &&
                    parts[0].StartsWith("Microsoft.WinDbg_", StringComparison.OrdinalIgnoreCase) &&
                    parts[1].Equals("amd64", StringComparison.OrdinalIgnoreCase) &&
                    parts[2].Equals("cdb.exe", StringComparison.OrdinalIgnoreCase) &&
                    !FileSystemInfoHelpers.HasReparseComponent(windowsApps, fullPath))
                {
                    return true;
                }
            }
            catch (ArgumentException)
            {
            }
        }

        return false;
    }
}

internal sealed class UserTokenInspector : IUserTokenInspector
{
    public bool IsElevated()
    {
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 0x0008, out SafeFileHandle token))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }

        using (token)
        {
            int elevation = 0;
            int returned;
            return GetTokenInformation(token, 20, ref elevation, sizeof(int), out returned) && elevation != 0;
        }
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out SafeFileHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        SafeFileHandle tokenHandle,
        int tokenInformationClass,
        ref int tokenInformation,
        int tokenInformationLength,
        out int returnLength);
}

internal sealed class DebuggerProcessHost : IDebuggerProcessHost
{
    internal const int StandardStreamCaptureLimitCharacters = 8 * 1024 * 1024;

    public async Task<DebuggerProcessResult> RunAsync(
        DebuggerInvocation invocation,
        CancellationToken cancellationToken)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = invocation.ExecutablePath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            WorkingDirectory = Path.GetDirectoryName(invocation.ExecutablePath) ?? Environment.SystemDirectory
        };
        startInfo.ArgumentList.Add("-sins");
        startInfo.ArgumentList.Add("-y");
        startInfo.ArgumentList.Add(invocation.SymbolPath);
        startInfo.ArgumentList.Add("-z");
        startInfo.ArgumentList.Add(invocation.DumpPath);
        startInfo.ArgumentList.Add("-c");
        startInfo.ArgumentList.Add(invocation.CommandList);

        using var process = new Process { StartInfo = startInfo };
        using var job = new KillOnCloseJob();
        if (!process.Start())
        {
            throw new InvalidOperationException("cdb.exe did not start.");
        }

        process.StandardInput.Close();
        try
        {
            job.Assign(process);
        }
        catch
        {
            TryKill(process);
            throw;
        }

        // The host owns cancellation and kills the contained process tree. Keep
        // draining both redirected pipes until they close so cdb cannot block on
        // a full pipe, while retaining only a bounded amount of text in memory.
        Task<BoundedTextReadResult> stdout = BoundedTextStreamReader.ReadAndDrainAsync(
            process.StandardOutput,
            StandardStreamCaptureLimitCharacters,
            CancellationToken.None);
        Task<BoundedTextReadResult> stderr = BoundedTextStreamReader.ReadAndDrainAsync(
            process.StandardError,
            StandardStreamCaptureLimitCharacters,
            CancellationToken.None);
        Task exit = process.WaitForExitAsync(CancellationToken.None);
        using var timeout = new CancellationTokenSource(invocation.Timeout);
        bool timedOut = false;
        bool cancelled = false;
        bool protectedTargetStarted = false;

        while (!exit.IsCompleted)
        {
            if (invocation.IsProtectedTargetRunning())
            {
                protectedTargetStarted = true;
                TryKill(process);
                break;
            }

            if (cancellationToken.IsCancellationRequested)
            {
                cancelled = true;
                TryKill(process);
                break;
            }

            if (timeout.IsCancellationRequested)
            {
                timedOut = true;
                TryKill(process);
                break;
            }

            await Task.WhenAny(exit, Task.Delay(200, CancellationToken.None)).ConfigureAwait(false);
        }

        await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
        BoundedTextReadResult standardOutput = await stdout.ConfigureAwait(false);
        BoundedTextReadResult standardError = await stderr.ConfigureAwait(false);
        if (cancelled)
        {
            cancellationToken.ThrowIfCancellationRequested();
        }

        return new DebuggerProcessResult(
            process.ExitCode,
            standardOutput.Text,
            standardError.Text,
            timedOut,
            cancelled,
            protectedTargetStarted,
            standardOutput.Truncated,
            standardError.Truncated);
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
        }
        catch (System.ComponentModel.Win32Exception)
        {
        }
    }
}

internal sealed record BoundedTextReadResult(string Text, bool Truncated);

internal static class BoundedTextStreamReader
{
    private const int BufferSize = 16 * 1024;

    public static async Task<BoundedTextReadResult> ReadAndDrainAsync(
        TextReader reader,
        int maxCharacters,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentOutOfRangeException.ThrowIfNegative(maxCharacters);

        var captured = new StringBuilder(Math.Min(maxCharacters, BufferSize));
        char[] buffer = new char[BufferSize];
        bool truncated = false;

        while (true)
        {
            int read = await reader.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            int remaining = maxCharacters - captured.Length;
            if (remaining > 0)
            {
                int retained = Math.Min(remaining, read);
                captured.Append(buffer, 0, retained);
                truncated |= retained < read;
            }
            else
            {
                truncated = true;
            }
        }

        return new BoundedTextReadResult(captured.ToString(), truncated);
    }
}

internal sealed class KillOnCloseJob : IDisposable
{
    private const uint JobObjectLimitKillOnJobClose = 0x00002000;
    private readonly SafeJobHandle _handle;

    public KillOnCloseJob()
    {
        _handle = CreateJobObject(IntPtr.Zero, null);
        if (_handle.IsInvalid)
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }

        var information = new JobObjectExtendedLimitInformation
        {
            BasicLimitInformation = new JobObjectBasicLimitInformation
            {
                LimitFlags = JobObjectLimitKillOnJobClose
            }
        };
        if (!SetInformationJobObject(
                _handle,
                9,
                ref information,
                (uint)Marshal.SizeOf<JobObjectExtendedLimitInformation>()))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    public void Assign(Process process)
    {
        if (!AssignProcessToJobObject(_handle, process.Handle))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    public void Dispose() => _handle.Dispose();

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeJobHandle CreateJobObject(IntPtr jobAttributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        SafeJobHandle job,
        int informationClass,
        ref JobObjectExtendedLimitInformation information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(SafeJobHandle job, IntPtr process);

    private sealed class SafeJobHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private SafeJobHandle()
            : base(true)
        {
        }

        protected override bool ReleaseHandle() => CloseHandle(handle);

        [DllImport("kernel32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr handle);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectBasicLimitInformation
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JobObjectExtendedLimitInformation
    {
        public JobObjectBasicLimitInformation BasicLimitInformation;
        public IoCounters IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }
}

internal static class PrivateDirectoryAcl
{
    public static void EnsureRestrictedToCurrentUserAndSystem(string path)
    {
        try
        {
            ApplyRestrictedAcl(path);
        }
        catch (Exception exception) when (exception is PlatformNotSupportedException or
                                          UnauthorizedAccessException or
                                          System.Security.SecurityException or
                                          InvalidOperationException)
        {
            throw new IOException("An ACL-restricted private directory could not be created.", exception);
        }
    }

    public static void TryRestrictToCurrentUserAndSystem(string path)
    {
        // The directory is created under the user's local app data by callers.
        // The helper applies a stronger explicit DACL; this method intentionally
        // remains best-effort so a read-only scan cannot be blocked by ACL APIs.
        try
        {
            ApplyRestrictedAcl(path);
        }
        catch (PlatformNotSupportedException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
        catch (System.Security.SecurityException)
        {
        }
        catch (InvalidOperationException)
        {
        }
    }

    private static void ApplyRestrictedAcl(string path)
    {
        var directory = new DirectoryInfo(path);
        System.Security.AccessControl.DirectorySecurity security = directory.GetAccessControl();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        // SetAccessRuleProtection removes inherited ACEs but deliberately leaves
        // explicit ACEs in place. This directory may already exist, so clear its
        // entire explicit DACL before establishing the two permitted principals.
        System.Security.AccessControl.FileSystemAccessRule[] existingRules = security
            .GetAccessRules(
                includeExplicit: true,
                includeInherited: false,
                typeof(System.Security.Principal.SecurityIdentifier))
            .OfType<System.Security.AccessControl.FileSystemAccessRule>()
            .ToArray();
        foreach (System.Security.AccessControl.FileSystemAccessRule existingRule in existingRules)
        {
            security.RemoveAccessRuleSpecific(existingRule);
        }

        System.Security.Principal.SecurityIdentifier currentUser =
            System.Security.Principal.WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException("The current Windows user SID was unavailable.");
        var system = new System.Security.Principal.SecurityIdentifier(
            System.Security.Principal.WellKnownSidType.LocalSystemSid,
            null);
        foreach (System.Security.Principal.SecurityIdentifier principal in new HashSet<System.Security.Principal.SecurityIdentifier>
                 {
                     currentUser,
                     system
                 })
        {
            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                principal,
                System.Security.AccessControl.FileSystemRights.FullControl,
                System.Security.AccessControl.InheritanceFlags.ContainerInherit |
                System.Security.AccessControl.InheritanceFlags.ObjectInherit,
                System.Security.AccessControl.PropagationFlags.None,
                System.Security.AccessControl.AccessControlType.Allow));
        }

        directory.SetAccessControl(security);
    }
}
