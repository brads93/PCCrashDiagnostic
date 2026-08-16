using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using BF6CrashDiagnostic.Core.Sharing;

namespace BF6CrashDiagnostic.Core.Reporting;

public enum ReportDeletionScope
{
    SelectedReport,
    AllHistory
}

public enum ReportDeletionState
{
    Recycled,
    PartiallyRecycled,
    Cancelled,
    RecycleBinUnavailable,
    PreviewExpired,
    FilesChanged,
    Failed
}

public sealed record ReportDeletionPreview(
    string PreviewToken,
    ReportDeletionScope Scope,
    int ReportFileCount,
    int RelatedFolderCount,
    long TotalBytes,
    int ExcludedItemCount,
    DateTimeOffset ExpiresUtc);

public sealed record ReportDeletionResult(
    ReportDeletionState State,
    int RecycledItemCount,
    int FailedItemCount,
    string Detail);

internal enum RecycleBinAdapterState
{
    Recycled,
    Cancelled,
    Unavailable,
    Failed
}

internal sealed record RecycleBinAdapterResult(RecycleBinAdapterState State);

internal interface IRecycleBinAdapter
{
    Task<RecycleBinAdapterResult> RecycleAsync(
        string path,
        FileTreeSnapshot expectedSnapshot,
        CancellationToken cancellationToken);
}

/// <summary>
/// Plans report/history removal against exact validated targets, then delegates each target
/// to the Windows Recycle Bin. No permanent-delete API is used as a fallback.
/// </summary>
public sealed class RecycleBinDeletionService
{
    private const int MaximumTargets = 10_000;
    private static readonly TimeSpan PreviewLifetime = TimeSpan.FromMinutes(5);
    private readonly ConcurrentDictionary<string, DeletionPlan> _plans = new(StringComparer.Ordinal);
    private readonly string _dataRoot;
    private readonly ReportHandleRegistry _registry;
    private readonly IRecycleBinAdapter _adapter;
    private readonly SafeSummaryService? _safeSummaries;
    private readonly TimeProvider _timeProvider;

    public RecycleBinDeletionService(
        string dataRoot,
        ReportHandleRegistry registry,
        TimeProvider? timeProvider = null)
        : this(dataRoot, registry, new WindowsRecycleBinAdapter(), safeSummaries: null, timeProvider)
    {
    }

    public RecycleBinDeletionService(
        string dataRoot,
        ReportHandleRegistry registry,
        SafeSummaryService safeSummaries,
        TimeProvider? timeProvider = null)
        : this(dataRoot, registry, new WindowsRecycleBinAdapter(), safeSummaries, timeProvider)
    {
    }

    internal RecycleBinDeletionService(
        string dataRoot,
        ReportHandleRegistry registry,
        IRecycleBinAdapter adapter,
        TimeProvider? timeProvider = null)
        : this(dataRoot, registry, adapter, safeSummaries: null, timeProvider)
    {
    }

    internal RecycleBinDeletionService(
        string dataRoot,
        ReportHandleRegistry registry,
        IRecycleBinAdapter adapter,
        SafeSummaryService? safeSummaries,
        TimeProvider? timeProvider = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        if (!Path.IsPathFullyQualified(dataRoot))
        {
            throw new ArgumentException("The deletion service requires an absolute data root.", nameof(dataRoot));
        }

        _dataRoot = Path.GetFullPath(dataRoot);
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _adapter = adapter ?? throw new ArgumentNullException(nameof(adapter));
        _safeSummaries = safeSummaries;
        _timeProvider = timeProvider ?? TimeProvider.System;
        if (!string.Equals(_dataRoot, Path.GetFullPath(_registry.DataRoot), StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("The report registry and deletion service must use the same data root.", nameof(registry));
        }
    }

    public ReportDeletionPreview PreviewSelected(UiReportHandle handle)
    {
        ResolvedReportHandle resolved = _registry.Resolve(handle);
        var candidates = new List<string>();
        foreach (ReportHandleFile report in resolved.Files)
        {
            candidates.Add(report.FullPath);
            string checksum = report.FullPath + ".sha256";
            if (File.Exists(checksum))
            {
                candidates.Add(checksum);
            }
        }

        AddExistingDirectory(candidates, Path.Combine(_dataRoot, "Sessions"), resolved.SessionId);
        AddExistingDirectory(candidates, Path.Combine(_dataRoot, "DebuggerLogs"), resolved.SessionId);
        DeletionPlan plan = CreatePlan(ReportDeletionScope.SelectedReport, candidates, excludedCount: 0, handle);
        _safeSummaries?.RevokeForReport(handle);
        return ToPreview(plan);
    }

    public async Task<ReportDeletionPreview> PreviewAllHistoryAsync(
        CancellationToken cancellationToken = default)
    {
        var candidates = new List<string>();
        int excluded = 0;
        excluded += await EnumerateValidatedReportFilesAsync(
            Path.Combine(_dataRoot, "Reports"),
            includeChecksums: true,
            candidates,
            cancellationToken).ConfigureAwait(false);
        excluded += await EnumerateValidatedReportFilesAsync(
            Path.Combine(_dataRoot, "Library", "ImportedReports"),
            includeChecksums: false,
            candidates,
            cancellationToken).ConfigureAwait(false);
        EnumerateSessionDirectories(Path.Combine(_dataRoot, "Sessions"), candidates, ref excluded);
        EnumerateSessionDirectories(Path.Combine(_dataRoot, "DebuggerLogs"), candidates, ref excluded);
        DeletionPlan plan = CreatePlan(ReportDeletionScope.AllHistory, candidates, excluded, selectedHandle: null);
        _safeSummaries?.RevokeAll();
        return ToPreview(plan);
    }

    public async Task<ReportDeletionResult> RecycleAsync(
        string previewToken,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(previewToken) || !_plans.TryGetValue(previewToken, out DeletionPlan? plan))
        {
            return new ReportDeletionResult(ReportDeletionState.PreviewExpired, 0, 0, "Preview the deletion again before continuing.");
        }

        if (plan.ExpiresUtc <= _timeProvider.GetUtcNow())
        {
            _plans.TryRemove(previewToken, out _);
            return new ReportDeletionResult(ReportDeletionState.PreviewExpired, 0, plan.Targets.Count, "The deletion preview expired. No files were changed.");
        }

        RevokeSafeSummaries(plan);

        try
        {
            foreach (DeletionTarget target in plan.Targets)
            {
                cancellationToken.ThrowIfCancellationRequested();
                ValidateTargetRoot(target);
                target.Snapshot.VerifyUnchanged();
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or Win32Exception)
        {
            _plans.TryRemove(previewToken, out _);
            return new ReportDeletionResult(ReportDeletionState.FilesChanged, 0, plan.Targets.Count, "The selected report files changed after preview. Nothing was removed.");
        }

        int recycled = 0;
        int failed = 0;
        foreach (DeletionTarget target in plan.Targets)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return Finish(plan, previewToken, recycled == 0 ? ReportDeletionState.Cancelled : ReportDeletionState.PartiallyRecycled,
                    recycled, plan.Targets.Count - recycled, "Recycle Bin removal was cancelled. Remaining items were left in place.");
            }
            try
            {
                ValidateTargetRoot(target);
                target.Snapshot.VerifyUnchanged();
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or Win32Exception)
            {
                failed++;
                return Finish(plan, previewToken, ReportDeletionState.PartiallyRecycled, recycled, failed + plan.Targets.Count - recycled - failed,
                    "A selected item changed while removal was in progress. Remaining items were left in place.");
            }

            RecycleBinAdapterResult result;
            try
            {
                result = await _adapter.RecycleAsync(target.FullPath, target.Snapshot, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return Finish(plan, previewToken, recycled == 0 ? ReportDeletionState.Cancelled : ReportDeletionState.PartiallyRecycled,
                    recycled, plan.Targets.Count - recycled, "Recycle Bin removal was cancelled. Remaining items were left in place.");
            }

            if (result.State == RecycleBinAdapterState.Recycled && !File.Exists(target.FullPath) && !Directory.Exists(target.FullPath))
            {
                recycled++;
                continue;
            }

            failed++;
            ReportDeletionState state = result.State switch
            {
                RecycleBinAdapterState.Cancelled => recycled == 0 ? ReportDeletionState.Cancelled : ReportDeletionState.PartiallyRecycled,
                RecycleBinAdapterState.Unavailable => recycled == 0 ? ReportDeletionState.RecycleBinUnavailable : ReportDeletionState.PartiallyRecycled,
                _ => recycled == 0 ? ReportDeletionState.Failed : ReportDeletionState.PartiallyRecycled
            };
            string detail = result.State == RecycleBinAdapterState.Unavailable
                ? "Windows Recycle Bin removal was unavailable. No permanent-delete fallback was used."
                : "Windows did not move every selected item to the Recycle Bin. No permanent-delete fallback was used.";
            return Finish(plan, previewToken, state, recycled, failed + plan.Targets.Count - recycled - failed, detail);
        }

        return Finish(plan, previewToken, ReportDeletionState.Recycled, recycled, 0, "The selected report data was moved to the Recycle Bin.");
    }

    public bool RevokePreview(string previewToken) =>
        !string.IsNullOrWhiteSpace(previewToken) && _plans.TryRemove(previewToken, out _);

    private ReportDeletionResult Finish(
        DeletionPlan plan,
        string token,
        ReportDeletionState state,
        int recycled,
        int failed,
        string detail)
    {
        _plans.TryRemove(token, out _);
        if (recycled > 0 && plan.SelectedHandle is not null)
        {
            _registry.Revoke(plan.SelectedHandle);
        }
        else if (recycled > 0 && plan.Scope == ReportDeletionScope.AllHistory)
        {
            _registry.RevokeAll();
        }

        return new ReportDeletionResult(state, recycled, failed, detail);
    }

    private void RevokeSafeSummaries(DeletionPlan plan)
    {
        if (plan.SelectedHandle is not null)
        {
            _safeSummaries?.RevokeForReport(plan.SelectedHandle);
        }
        else if (plan.Scope == ReportDeletionScope.AllHistory)
        {
            _safeSummaries?.RevokeAll();
        }
    }

    private DeletionPlan CreatePlan(
        ReportDeletionScope scope,
        IEnumerable<string> paths,
        int excludedCount,
        UiReportHandle? selectedHandle)
    {
        string[] unique = paths
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(path => Directory.Exists(path))
            .ThenBy(path => path, StringComparer.OrdinalIgnoreCase)
            .Take(MaximumTargets + 1)
            .ToArray();
        if (unique.Length > MaximumTargets)
        {
            throw new IOException("The report history exceeds the bounded deletion-preview limit.");
        }

        var targets = new List<DeletionTarget>(unique.Length);
        foreach (string path in unique)
        {
            string trustedRoot = TrustedRootFor(path);
            PathSafety.EnsureContained(trustedRoot, path);
            PathSafety.EnsureNoReparseComponents(trustedRoot, path);
            FileTreeSnapshot snapshot = FileTreeSnapshot.Capture(path);
            targets.Add(new DeletionTarget(path, trustedRoot, snapshot));
        }

        long totalBytes = 0;
        foreach (DeletionTarget target in targets)
        {
            IEnumerable<long> sizes = target.Snapshot.RootIdentity.IsDirectory
                ? target.Snapshot.Entries.Where(item => !item.Identity.IsDirectory).Select(item => item.Identity.SizeBytes)
                : [target.Snapshot.RootIdentity.SizeBytes];
            foreach (long size in sizes)
            {
                totalBytes = totalBytes > long.MaxValue - Math.Max(0, size) ? long.MaxValue : totalBytes + Math.Max(0, size);
            }
        }

        DateTimeOffset now = _timeProvider.GetUtcNow();
        string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var plan = new DeletionPlan(token, scope, now + PreviewLifetime, targets, excludedCount, totalBytes, selectedHandle);
        _plans[token] = plan;
        return plan;
    }

    private static ReportDeletionPreview ToPreview(DeletionPlan plan) => new(
        plan.Token,
        plan.Scope,
        plan.Targets.Count(item => !item.Snapshot.RootIdentity.IsDirectory),
        plan.Targets.Count(item => item.Snapshot.RootIdentity.IsDirectory),
        plan.TotalBytes,
        plan.ExcludedCount,
        plan.ExpiresUtc);

    private void ValidateTargetRoot(DeletionTarget target)
    {
        string currentRoot = TrustedRootFor(target.FullPath);
        if (!string.Equals(currentRoot, target.TrustedRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException("The report target no longer belongs to its trusted root.");
        }

        PathSafety.EnsureContained(target.TrustedRoot, target.FullPath);
        PathSafety.EnsureNoReparseComponents(target.TrustedRoot, target.FullPath);
    }

    private string TrustedRootFor(string path)
    {
        string fullPath = Path.GetFullPath(path);
        string[] roots =
        [
            Path.Combine(_dataRoot, "Reports"),
            Path.Combine(_dataRoot, "Library", "ImportedReports"),
            Path.Combine(_dataRoot, "Sessions"),
            Path.Combine(_dataRoot, "DebuggerLogs")
        ];
        foreach (string root in roots)
        {
            try
            {
                PathSafety.EnsureContained(root, fullPath);
                return root;
            }
            catch (UnauthorizedAccessException)
            {
                // Try the next exact allowlisted root.
            }
        }

        throw new UnauthorizedAccessException("The requested item is outside the report-history roots.");
    }

    private static void AddExistingDirectory(ICollection<string> candidates, string root, string sessionId)
    {
        if (!SessionIdValidator.IsValid(sessionId))
        {
            throw new InvalidDataException("The selected report has an invalid session ID.");
        }

        string path = PathSafety.EnsureContained(root, Path.Combine(root, sessionId));
        if (Directory.Exists(path))
        {
            candidates.Add(path);
        }
    }

    private static async Task<int> EnumerateValidatedReportFilesAsync(
        string root,
        bool includeChecksums,
        ICollection<string> candidates,
        CancellationToken cancellationToken)
    {
        if (!Directory.Exists(root))
        {
            return 0;
        }

        PathSafety.EnsureNoReparseComponents(root);
        string[] entries = Directory.EnumerateFileSystemEntries(root, "*", SearchOption.TopDirectoryOnly)
            .Take((MaximumTargets * 2) + 1)
            .ToArray();
        if (entries.Length > MaximumTargets * 2)
        {
            throw new IOException("The report-history directory exceeds the bounded preview limit.");
        }

        var accepted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string entry in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            FileAttributes attributes = File.GetAttributes(entry);
            if ((attributes & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0 ||
                !Path.GetExtension(entry).Equals(".zip", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            try
            {
                _ = await IncidentLibrary.ReadValidatedArchiveAsync(entry, cancellationToken).ConfigureAwait(false);
                candidates.Add(entry);
                accepted.Add(Path.GetFullPath(entry));
                if (includeChecksums)
                {
                    string checksum = entry + ".sha256";
                    if (File.Exists(checksum) &&
                        (File.GetAttributes(checksum) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) == 0)
                    {
                        candidates.Add(checksum);
                        accepted.Add(Path.GetFullPath(checksum));
                    }
                }
            }
            catch (Exception exception) when (exception is IOException or InvalidDataException or UnauthorizedAccessException or System.Text.Json.JsonException)
            {
                // Invalid archives are not app-owned history and must be left alone.
            }
        }

        return entries.Count(entry => !accepted.Contains(Path.GetFullPath(entry)));
    }

    private static void EnumerateSessionDirectories(
        string root,
        ICollection<string> candidates,
        ref int excluded)
    {
        if (!Directory.Exists(root))
        {
            return;
        }

        PathSafety.EnsureNoReparseComponents(root);
        foreach (string entry in Directory.EnumerateFileSystemEntries(root, "*", SearchOption.TopDirectoryOnly))
        {
            FileAttributes attributes = File.GetAttributes(entry);
            if ((attributes & FileAttributes.ReparsePoint) != 0 ||
                (attributes & FileAttributes.Directory) == 0 ||
                !SessionIdValidator.IsValid(Path.GetFileName(entry)))
            {
                excluded++;
                continue;
            }

            candidates.Add(entry);
        }
    }

    private sealed record DeletionTarget(string FullPath, string TrustedRoot, FileTreeSnapshot Snapshot);

    private sealed record DeletionPlan(
        string Token,
        ReportDeletionScope Scope,
        DateTimeOffset ExpiresUtc,
        IReadOnlyList<DeletionTarget> Targets,
        int ExcludedCount,
        long TotalBytes,
        UiReportHandle? SelectedHandle);
}

internal sealed class WindowsRecycleBinAdapter : IRecycleBinAdapter
{
    public Task<RecycleBinAdapterResult> RecycleAsync(
        string path,
        FileTreeSnapshot expectedSnapshot,
        CancellationToken cancellationToken)
    {
        string fullPath = Path.GetFullPath(path);
        ArgumentNullException.ThrowIfNull(expectedSnapshot);
        cancellationToken.ThrowIfCancellationRequested();
        var completion = new TaskCompletionSource<RecycleBinAdapterResult>(TaskCreationOptions.RunContinuationsAsynchronously);
        var thread = new Thread(() =>
        {
            try
            {
                completion.TrySetResult(Execute(fullPath, expectedSnapshot));
            }
            catch (Exception)
            {
                completion.TrySetResult(new RecycleBinAdapterResult(RecycleBinAdapterState.Unavailable));
            }
        })
        {
            IsBackground = true,
            Name = "PCCrashDiagnostic Recycle Bin"
        };
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        // IFileOperation has no reliable cancellation handshake for an in-flight item. Wait for
        // its result so the caller is never told "cancelled" while Windows is still recycling it.
        return completion.Task;
    }

    private static RecycleBinAdapterResult Execute(string path, FileTreeSnapshot expectedSnapshot)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(8))
        {
            return new RecycleBinAdapterResult(RecycleBinAdapterState.Unavailable);
        }

        IFileOperation? operation = null;
        IShellItem? item = null;
        try
        {
            expectedSnapshot.VerifyUnchanged();
            Type type = Type.GetTypeFromCLSID(FileOperationClassId, throwOnError: true)!;
            operation = (IFileOperation)Activator.CreateInstance(type)!;
            int result = operation.SetOperationFlags(
                FileOperationFlags.Silent |
                FileOperationFlags.NoConfirmation |
                FileOperationFlags.AllowUndo |
                FileOperationFlags.NoErrorUi |
                FileOperationFlags.RecycleOnDelete |
                FileOperationFlags.EarlyFailure |
                FileOperationFlags.NoCopyHooks |
                FileOperationFlags.AddUndoRecord);
            if (result < 0)
            {
                return new RecycleBinAdapterResult(RecycleBinAdapterState.Unavailable);
            }

            Guid itemId = ShellItemInterfaceId;
            result = SHCreateItemFromParsingName(path, IntPtr.Zero, ref itemId, out item);
            if (result < 0 || item is null)
            {
                return new RecycleBinAdapterResult(RecycleBinAdapterState.Failed);
            }

            expectedSnapshot.VerifyUnchanged();
            result = operation.DeleteItem(item, IntPtr.Zero);
            if (result < 0 || operation.PerformOperations() < 0)
            {
                return new RecycleBinAdapterResult(RecycleBinAdapterState.Failed);
            }

            result = operation.GetAnyOperationsAborted(out bool aborted);
            if (result < 0)
            {
                return new RecycleBinAdapterResult(RecycleBinAdapterState.Failed);
            }

            if (aborted)
            {
                return new RecycleBinAdapterResult(RecycleBinAdapterState.Cancelled);
            }

            return !File.Exists(path) && !Directory.Exists(path)
                ? new RecycleBinAdapterResult(RecycleBinAdapterState.Recycled)
                : new RecycleBinAdapterResult(RecycleBinAdapterState.Failed);
        }
        catch (Exception exception) when (exception is COMException or InvalidCastException or TypeLoadException or MissingMethodException or IOException or UnauthorizedAccessException)
        {
            return new RecycleBinAdapterResult(RecycleBinAdapterState.Unavailable);
        }
        finally
        {
            if (item is not null)
            {
                TryRelease(item);
            }

            if (operation is not null)
            {
                TryRelease(operation);
            }
        }
    }

    private static void TryRelease(object value)
    {
        try
        {
            if (Marshal.IsComObject(value))
            {
                Marshal.FinalReleaseComObject(value);
            }
        }
        catch (ArgumentException)
        {
            // Releasing the isolated operation object is best effort after completion.
        }
    }

    private static readonly Guid FileOperationClassId = new("3AD05575-8857-4850-9277-11B85BDB8E09");
    private static readonly Guid ShellItemInterfaceId = new("43826D1E-E718-42EE-BC55-A1E261C37BFE");

    [Flags]
    private enum FileOperationFlags : uint
    {
        Silent = 0x00000004,
        NoConfirmation = 0x00000010,
        AllowUndo = 0x00000040,
        NoErrorUi = 0x00000400,
        RecycleOnDelete = 0x00080000,
        EarlyFailure = 0x00100000,
        NoCopyHooks = 0x00800000,
        AddUndoRecord = 0x20000000
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
    private static extern int SHCreateItemFromParsingName(
        [MarshalAs(UnmanagedType.LPWStr)] string path,
        IntPtr bindContext,
        ref Guid shellItemInterface,
        [MarshalAs(UnmanagedType.Interface)] out IShellItem? shellItem);

    [ComImport]
    [Guid("43826D1E-E718-42EE-BC55-A1E261C37BFE")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellItem
    {
    }

    [ComImport]
    [Guid("947AAB5F-0A5C-4C13-B4D6-4BF7836FC9F8")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IFileOperation
    {
        [PreserveSig] int Advise(IntPtr progressSink, out uint cookie);
        [PreserveSig] int Unadvise(uint cookie);
        [PreserveSig] int SetOperationFlags(FileOperationFlags operationFlags);
        [PreserveSig] int SetProgressMessage([MarshalAs(UnmanagedType.LPWStr)] string message);
        [PreserveSig] int SetProgressDialog(IntPtr progressDialog);
        [PreserveSig] int SetProperties(IntPtr properties);
        [PreserveSig] int SetOwnerWindow(uint ownerWindow);
        [PreserveSig] int ApplyPropertiesToItem(IShellItem item);
        [PreserveSig] int ApplyPropertiesToItems(IntPtr items);
        [PreserveSig] int RenameItem(IShellItem item, [MarshalAs(UnmanagedType.LPWStr)] string newName, IntPtr sink);
        [PreserveSig] int RenameItems(IntPtr items, [MarshalAs(UnmanagedType.LPWStr)] string newName);
        [PreserveSig] int MoveItem(IShellItem item, IShellItem destinationFolder, [MarshalAs(UnmanagedType.LPWStr)] string newName, IntPtr sink);
        [PreserveSig] int MoveItems(IntPtr items, IShellItem destinationFolder);
        [PreserveSig] int CopyItem(IShellItem item, IShellItem destinationFolder, [MarshalAs(UnmanagedType.LPWStr)] string copyName, IntPtr sink);
        [PreserveSig] int CopyItems(IntPtr items, IShellItem destinationFolder);
        [PreserveSig] int DeleteItem(IShellItem item, IntPtr sink);
        [PreserveSig] int DeleteItems(IntPtr items);
        [PreserveSig] int NewItem(IShellItem destinationFolder, uint fileAttributes, [MarshalAs(UnmanagedType.LPWStr)] string name, [MarshalAs(UnmanagedType.LPWStr)] string templateName, IntPtr sink);
        [PreserveSig] int PerformOperations();
        [PreserveSig] int GetAnyOperationsAborted([MarshalAs(UnmanagedType.Bool)] out bool aborted);
    }
}
