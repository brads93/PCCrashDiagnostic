using System.Diagnostics;
using BF6CrashDiagnostic.Core.Analysis;

namespace BF6CrashDiagnostic.Core.Collectors;

internal sealed record BoundedCommandRequest(
    string ExecutablePath,
    IReadOnlyList<string> Arguments,
    TimeSpan Timeout,
    int MaximumCharactersPerStream = 512 * 1024);

internal sealed record BoundedCommandResult(
    int? ExitCode,
    string StandardOutput,
    string StandardError,
    bool TimedOut,
    bool Cancelled,
    bool OutputTruncated);

internal interface IBoundedCommandRunner
{
    Task<BoundedCommandResult> RunAsync(
        BoundedCommandRequest request,
        CancellationToken cancellationToken);
}

/// <summary>
/// Runs one fixed local executable without a shell, stdin, or inherited console window.
/// Output is bounded while both pipes continue to be drained, and the process tree is
/// contained in a kill-on-close job.
/// </summary>
internal sealed class BoundedCommandRunner : IBoundedCommandRunner
{
    public async Task<BoundedCommandResult> RunAsync(
        BoundedCommandRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Timeout < TimeSpan.FromSeconds(1) || request.Timeout > TimeSpan.FromMinutes(5))
        {
            throw new ArgumentOutOfRangeException(nameof(request), "The command timeout must be between one second and five minutes.");
        }

        string executable = Path.GetFullPath(request.ExecutablePath);
        var startInfo = new ProcessStartInfo
        {
            FileName = executable,
            WorkingDirectory = Path.GetDirectoryName(executable) ?? string.Empty,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (string argument in request.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = new Process { StartInfo = startInfo };
        using var job = new KillOnCloseJob();
        if (!process.Start())
        {
            throw new InvalidOperationException("The diagnostic command did not start.");
        }

        process.StandardInput.Close();
        job.Assign(process);

        Task<BoundedTextReadResult> outputTask = BoundedTextStreamReader.ReadAndDrainAsync(
            process.StandardOutput,
            request.MaximumCharactersPerStream,
            CancellationToken.None);
        Task<BoundedTextReadResult> errorTask = BoundedTextStreamReader.ReadAndDrainAsync(
            process.StandardError,
            request.MaximumCharactersPerStream,
            CancellationToken.None);

        bool timedOut = false;
        bool cancelled = false;
        using var timeout = new CancellationTokenSource(request.Timeout);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        try
        {
            await process.WaitForExitAsync(linked.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            cancelled = cancellationToken.IsCancellationRequested;
            timedOut = !cancelled;
            TryKill(process);
            await process.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
        }

        BoundedTextReadResult output = await outputTask.ConfigureAwait(false);
        BoundedTextReadResult error = await errorTask.ConfigureAwait(false);
        return new BoundedCommandResult(
            process.HasExited ? process.ExitCode : null,
            output.Text,
            error.Text,
            timedOut,
            cancelled,
            output.Truncated || error.Truncated);
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
