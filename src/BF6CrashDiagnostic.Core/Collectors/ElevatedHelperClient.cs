using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Core.Collectors;

/// <summary>
/// Launches the fixed one-shot helper through Windows UAC. The request itself
/// travels through the ACL-restricted request store; only its random id appears
/// on the elevated command line.
/// </summary>
public sealed class ElevatedHelperClient : IElevatedHelperClient
{
    private const string HelperFileName = "PCCrashDiagnostic.ElevatedHelper.exe";
    private const string ExpectedHashMetadataName = "PCCrashDiagnostic.ExpectedElevatedHelperSha256";
    private const long MaximumHelperBytes = 1024L * 1024 * 1024;
    private readonly string _helperPath;
    private readonly ElevatedHelperRequestStore _store;
    private readonly string? _expectedSha256;
    private readonly bool _requireHashBinding;
    private readonly bool _allowDevelopmentPath;
    private readonly Func<ProcessStartInfo, Process?> _startProcess;

    public ElevatedHelperClient()
        : this(
            Path.Combine(AppContext.BaseDirectory, HelperFileName),
            new ElevatedHelperRequestStore(),
            ReadExpectedHelperSha256(),
            requireHashBinding: true,
            allowDevelopmentPath: false)
    {
    }

    internal ElevatedHelperClient(string helperPath, ElevatedHelperRequestStore store)
        : this(
            helperPath,
            store,
            ReadExpectedHelperSha256(),
            requireHashBinding: true,
            allowDevelopmentPath: false)
    {
    }

    internal ElevatedHelperClient(
        string helperPath,
        ElevatedHelperRequestStore store,
        string? expectedSha256,
        bool requireHashBinding,
        bool allowDevelopmentPath,
        Func<ProcessStartInfo, Process?>? startProcess = null)
    {
        _helperPath = Path.GetFullPath(helperPath);
        _store = store ?? throw new ArgumentNullException(nameof(store));
        _expectedSha256 = NormalizeSha256(expectedSha256);
        _requireHashBinding = requireHashBinding;
        _allowDevelopmentPath = allowDevelopmentPath;
        _startProcess = startProcess ?? Process.Start;
    }

    /// <summary>
    /// Verifies the packaged helper's fixed path, architecture, reparse boundary,
    /// and embedded SHA-256 binding without starting it or requesting elevation.
    /// </summary>
    public async Task<(bool Succeeded, string Message)> VerifyBindingAsync(
        CancellationToken cancellationToken = default)
    {
        HelperValidationResult validation = await OpenValidatedHelperAsync(cancellationToken)
            .ConfigureAwait(false);
        if (validation.Lease is null)
        {
            return (false, validation.FailureMessage);
        }

        await using FileStream helperLease = validation.Lease;
        return (true, "The elevated helper matches the SHA-256 embedded in the main app.");
    }

    public async Task<ProtectedEvidenceResponse> ExecuteAsync(
        ProtectedEvidenceRequest request,
        Func<bool> isProtectedTargetRunning,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(isProtectedTargetRunning);
        if (timeout < TimeSpan.FromSeconds(30) || timeout > TimeSpan.FromHours(2))
        {
            throw new ArgumentOutOfRangeException(nameof(timeout));
        }

        if (isProtectedTargetRunning())
        {
            return new ProtectedEvidenceResponse(
                false,
                "The elevated helper is unavailable while Battlefield 6 is running.");
        }

        HelperValidationResult validation = await OpenValidatedHelperAsync(cancellationToken)
            .ConfigureAwait(false);
        if (validation.Lease is null)
        {
            return new ProtectedEvidenceResponse(
                false,
                validation.FailureMessage);
        }

        await using FileStream helperLease = validation.Lease;
        ElevatedHelperTicket ticket;
        try
        {
            ticket = await _store.CreateRequestAsync(request, cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            await helperLease.DisposeAsync().ConfigureAwait(false);
            throw;
        }

        Process? process = null;
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = _helperPath,
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory = AppContext.BaseDirectory
            };
            startInfo.ArgumentList.Add(ticket.RequestId);
            process = _startProcess(startInfo);
            await helperLease.DisposeAsync().ConfigureAwait(false);
            if (process is null)
            {
                return new ProtectedEvidenceResponse(false, "Windows did not start the elevated helper.");
            }

            DateTimeOffset deadline = DateTimeOffset.UtcNow + timeout;
            bool exitedWithoutResponse = false;
            DateTimeOffset? exitedUtc = null;
            while (DateTimeOffset.UtcNow < deadline)
            {
                ProtectedEvidenceResponse? response = await _store.TryReadResponseAsync(
                    ticket.RequestId,
                    CancellationToken.None).ConfigureAwait(false);
                if (response is not null)
                {
                    return response;
                }

                if (isProtectedTargetRunning() || cancellationToken.IsCancellationRequested)
                {
                    _store.RequestCancellation(ticket.RequestId);
                }

                if (process.HasExited)
                {
                    exitedUtc ??= DateTimeOffset.UtcNow;
                    exitedWithoutResponse = DateTimeOffset.UtcNow - exitedUtc >= TimeSpan.FromSeconds(2);
                    if (exitedWithoutResponse)
                    {
                        break;
                    }
                }

                await Task.Delay(200, CancellationToken.None).ConfigureAwait(false);
            }

            _store.RequestCancellation(ticket.RequestId);
            return new ProtectedEvidenceResponse(
                false,
                exitedWithoutResponse
                    ? "The elevated helper exited without returning a validated response."
                    : "The elevated helper timed out or was cancelled; partial staging is removed by the helper.");
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode == 1223)
        {
            return new ProtectedEvidenceResponse(false, "Windows UAC consent was cancelled.");
        }
        finally
        {
            process?.Dispose();
            if (process is null)
            {
                _store.DiscardRequest(ticket.RequestId);
            }
        }
    }

    private async Task<HelperValidationResult> OpenValidatedHelperAsync(
        CancellationToken cancellationToken)
    {
        string expected = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, HelperFileName));
        if ((!_allowDevelopmentPath &&
             !string.Equals(_helperPath, expected, StringComparison.OrdinalIgnoreCase)) ||
            !File.Exists(_helperPath) ||
            !Path.GetFileName(_helperPath).Equals(HelperFileName, StringComparison.Ordinal))
        {
            return HelperValidationResult.Failed(
                "The fixed x64 PC Crash Diagnostic helper was not found beside the app.");
        }

        if (_requireHashBinding && _expectedSha256 is null)
        {
            return HelperValidationResult.Failed(
                "The packaged app does not contain the required elevated-helper integrity binding.");
        }

        try
        {
            PathSafety.EnsureNoReparseComponents(_helperPath);
            var lease = new FileStream(
                _helperPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            try
            {
                if (lease.Length is <= 0 or > MaximumHelperBytes || !PeFileInspector.IsX64(_helperPath))
                {
                    await lease.DisposeAsync().ConfigureAwait(false);
                    return HelperValidationResult.Failed(
                        "The fixed PC Crash Diagnostic helper was not a valid x64 executable.");
                }

                if (_expectedSha256 is not null)
                {
                    byte[] actual = await SHA256.HashDataAsync(lease, cancellationToken).ConfigureAwait(false);
                    byte[] expectedHash = Convert.FromHexString(_expectedSha256);
                    if (!CryptographicOperations.FixedTimeEquals(actual, expectedHash))
                    {
                        await lease.DisposeAsync().ConfigureAwait(false);
                        return HelperValidationResult.Failed(
                            "The elevated helper did not match the SHA-256 embedded in the main app.");
                    }

                    lease.Position = 0;
                }

                return new HelperValidationResult(lease, string.Empty);
            }
            catch
            {
                await lease.DisposeAsync().ConfigureAwait(false);
                throw;
            }
        }
        catch (IOException)
        {
            return HelperValidationResult.Failed(
                "The elevated helper could not be opened and verified safely.");
        }
        catch (UnauthorizedAccessException)
        {
            return HelperValidationResult.Failed(
                "Windows denied access while verifying the elevated helper.");
        }
    }

    private static string? ReadExpectedHelperSha256()
    {
        try
        {
            return Assembly.GetEntryAssembly()?
                .GetCustomAttributes<AssemblyMetadataAttribute>()
                .FirstOrDefault(attribute => attribute.Key.Equals(
                    ExpectedHashMetadataName,
                    StringComparison.Ordinal))?
                .Value;
        }
        catch
        {
            return null;
        }
    }

    private static string? NormalizeSha256(string? value)
    {
        string? normalized = value?.Trim().ToLowerInvariant();
        return normalized is { Length: 64 } && normalized.All(Uri.IsHexDigit)
            ? normalized
            : null;
    }

    private sealed record HelperValidationResult(FileStream? Lease, string FailureMessage)
    {
        public static HelperValidationResult Failed(string message) => new(null, message);
    }
}

internal interface IElevatedHelperClient
{
    Task<ProtectedEvidenceResponse> ExecuteAsync(
        ProtectedEvidenceRequest request,
        Func<bool> isProtectedTargetRunning,
        TimeSpan timeout,
        CancellationToken cancellationToken = default);
}
