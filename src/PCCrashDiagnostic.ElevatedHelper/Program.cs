using System.Diagnostics;
using System.Runtime.InteropServices;
using BF6CrashDiagnostic.Core.Collectors;
using BF6CrashDiagnostic.Core.Models;
using Microsoft.Win32.SafeHandles;

namespace PCCrashDiagnostic.ElevatedHelper;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        // The helper accepts one opaque id. It never accepts a source path,
        // destination path, command, debugger, or evidence-source name on its
        // elevated command line.
        if (args.Length != 1 || !IsRequestId(args[0]) || !IsElevated())
        {
            return 2;
        }

        string requestId = args[0].ToLowerInvariant();
        ElevatedHelperOrigin origin;
        try
        {
            origin = ElevatedHelperRequestStore.ResolveOrigin(requestId);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or
                                          InvalidDataException or System.Security.SecurityException or
                                          ArgumentException)
        {
            return 2;
        }

        ElevatedHelperRequestStore store = origin.RequestStore;
        ProtectedEvidenceHelper helper = ProtectedEvidenceHelper.CreateForElevatedOrigin(origin);
        _ = helper.CleanupStaleStagingDirectories(DateTimeOffset.UtcNow);
        _ = store.CleanupExpiredMessages(DateTimeOffset.UtcNow);
        using var cancellation = new CancellationTokenSource();
        Task cancellationMonitor = MonitorCancellationAsync(store, requestId, cancellation);

        ProtectedEvidenceResponse response;
        try
        {
            ProtectedEvidenceRequest request = await store.ConsumeRequestAsync(
                requestId,
                cancellation.Token).ConfigureAwait(false);
            response = await helper.ExecuteAsync(request, cancellation.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            response = new ProtectedEvidenceResponse(
                false,
                "The elevated evidence operation was cancelled and any partial staging copy was removed.");
        }
        catch (Exception exception) when (exception is IOException or
                                          UnauthorizedAccessException or
                                          InvalidDataException or
                                          System.Security.SecurityException)
        {
            response = new ProtectedEvidenceResponse(
                false,
                "The one-shot elevated request was invalid, expired, or could not be completed safely.");
        }
        finally
        {
            cancellation.Cancel();
            try
            {
                await cancellationMonitor.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }

            store.ClearCancellation(requestId);
        }

        try
        {
            await store.PublishResponseAsync(requestId, response, CancellationToken.None).ConfigureAwait(false);
            return response.Succeeded ? 0 : 1;
        }
        catch (Exception exception) when (exception is IOException or
                                          UnauthorizedAccessException or
                                          InvalidDataException or
                                          System.Security.SecurityException)
        {
            return 3;
        }
    }

    private static bool IsRequestId(string value) =>
        value.Length == 32 && value.All(Uri.IsHexDigit);

    private static async Task MonitorCancellationAsync(
        ElevatedHelperRequestStore store,
        string requestId,
        CancellationTokenSource cancellation)
    {
        while (!cancellation.IsCancellationRequested)
        {
            if (store.IsCancellationRequested(requestId))
            {
                cancellation.Cancel();
                return;
            }

            await Task.Delay(200, cancellation.Token).ConfigureAwait(false);
        }
    }

    private static bool IsElevated()
    {
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 0x0008, out SafeFileHandle token))
        {
            return false;
        }

        using (token)
        {
            int elevation = 0;
            return GetTokenInformation(token, 20, ref elevation, sizeof(int), out _) && elevation != 0;
        }
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle,
        uint desiredAccess,
        out SafeFileHandle tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        SafeFileHandle tokenHandle,
        int tokenInformationClass,
        ref int tokenInformation,
        int tokenInformationLength,
        out int returnLength);
}
