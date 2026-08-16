using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace BF6CrashDiagnostic.Core.Reporting;

internal readonly record struct LocalFileIdentity(
    uint VolumeSerialNumber,
    ulong FileIndex,
    bool IsDirectory,
    bool IsReparsePoint,
    long SizeBytes,
    long LastWriteTimeUtcTicks);

internal sealed record FileTreeEntry(string RelativePath, LocalFileIdentity Identity);

internal sealed record FileTreeSnapshot(
    string RootPath,
    LocalFileIdentity RootIdentity,
    IReadOnlyList<FileTreeEntry> Entries)
{
    private const int MaximumEntries = 100_000;

    public static FileTreeSnapshot Capture(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string root = Path.GetFullPath(path);
        LocalFileIdentity rootIdentity = WindowsFileIdentity.Capture(root);
        if (rootIdentity.IsReparsePoint)
        {
            throw new IOException("Reparse points are not valid report-deletion targets.");
        }

        if (!rootIdentity.IsDirectory)
        {
            return new FileTreeSnapshot(root, rootIdentity, []);
        }

        var entries = new List<FileTreeEntry>();
        var pending = new Stack<string>();
        var visitedDirectories = new HashSet<(uint Volume, ulong Index)>
        {
            (rootIdentity.VolumeSerialNumber, rootIdentity.FileIndex)
        };
        pending.Push(root);
        while (pending.Count > 0)
        {
            string directory = pending.Pop();
            string[] children = Directory.EnumerateFileSystemEntries(directory, "*", SearchOption.TopDirectoryOnly)
                .Order(StringComparer.OrdinalIgnoreCase)
                .ThenBy(value => value, StringComparer.Ordinal)
                .ToArray();
            foreach (string child in children)
            {
                if (entries.Count >= MaximumEntries)
                {
                    throw new IOException("The report directory exceeds the bounded deletion-manifest limit.");
                }

                LocalFileIdentity identity = WindowsFileIdentity.Capture(child);
                if (identity.IsReparsePoint)
                {
                    throw new IOException("Reparse points are not valid report-deletion targets.");
                }

                string relative = Path.GetRelativePath(root, child);
                if (relative.StartsWith("..", StringComparison.Ordinal) || Path.IsPathFullyQualified(relative))
                {
                    throw new IOException("A report directory entry escaped its trusted root.");
                }

                entries.Add(new FileTreeEntry(relative, identity));
                if (identity.IsDirectory)
                {
                    if (!visitedDirectories.Add((identity.VolumeSerialNumber, identity.FileIndex)))
                    {
                        throw new IOException("A report directory contained an unexpected filesystem cycle.");
                    }

                    pending.Push(child);
                }
            }
        }

        return new FileTreeSnapshot(root, rootIdentity, entries);
    }

    public void VerifyUnchanged()
    {
        FileTreeSnapshot current = Capture(RootPath);
        if (RootIdentity != current.RootIdentity || Entries.Count != current.Entries.Count)
        {
            throw new IOException("The selected report files changed after the deletion preview.");
        }

        for (int index = 0; index < Entries.Count; index++)
        {
            if (!string.Equals(Entries[index].RelativePath, current.Entries[index].RelativePath, StringComparison.Ordinal) ||
                Entries[index].Identity != current.Entries[index].Identity)
            {
                throw new IOException("The selected report files changed after the deletion preview.");
            }
        }
    }
}

internal static partial class WindowsFileIdentity
{
    private const uint DeleteAccess = 0x00010000;
    private const uint FileListDirectory = 0x00000001;
    private const uint FileReadAttributes = 0x00000080;
    private const uint GenericWrite = 0x40000000;
    private const uint FileShareRead = 0x00000001;
    private const uint FileShareWrite = 0x00000002;
    private const uint FileShareDelete = 0x00000004;
    private const uint CreateNew = 1;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const uint FileFlagOpenReparsePoint = 0x00200000;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint FileFlagWriteThrough = 0x80000000;
    private const uint FileAttributeDirectory = 0x00000010;
    private const uint FileAttributeReparsePoint = 0x00000400;
    private const int FileRenameInfo = 3;

    public static LocalFileIdentity Capture(string path)
    {
        string fullPath = Path.GetFullPath(path);
        using SafeFileHandle handle = CreateFile(
            fullPath,
            FileReadAttributes,
            FileShareRead | FileShareWrite | FileShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics | FileFlagOpenReparsePoint,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "The report path could not be opened for identity validation.");
        }

        return Capture(handle);
    }

    public static LocalFileIdentity Capture(SafeFileHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (handle.IsInvalid || handle.IsClosed)
        {
            throw new IOException("The file handle is not available for identity validation.");
        }

        if (!GetFileInformationByHandle(handle, out ByHandleFileInformation info))
        {
            throw new Win32Exception(Marshal.GetLastPInvokeError(), "The report path identity could not be read.");
        }

        ulong fileIndex = ((ulong)info.FileIndexHigh << 32) | info.FileIndexLow;
        ulong unsignedSize = ((ulong)info.FileSizeHigh << 32) | info.FileSizeLow;
        long size = unsignedSize > long.MaxValue ? long.MaxValue : (long)unsignedSize;
        long lastWrite = ((long)info.LastWriteTimeHigh << 32) | info.LastWriteTimeLow;
        return new LocalFileIdentity(
            info.VolumeSerialNumber,
            fileIndex,
            (info.FileAttributes & FileAttributeDirectory) != 0,
            (info.FileAttributes & FileAttributeReparsePoint) != 0,
            size,
            lastWrite);
    }

    public static StableDirectoryLease AcquireStableDirectory(
        string path,
        LocalFileIdentity expectedIdentity)
    {
        string fullPath = Path.GetFullPath(path);
        string root = Path.GetPathRoot(fullPath)
            ?? throw new IOException("The export folder has no local drive root.");
        var componentPaths = new List<string> { root };
        string relative = Path.GetRelativePath(root, fullPath);
        if (!string.Equals(relative, ".", StringComparison.Ordinal))
        {
            string current = root;
            foreach (string component in relative.Split(
                         [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
                         StringSplitOptions.RemoveEmptyEntries))
            {
                current = Path.Combine(current, component);
                componentPaths.Add(current);
            }
        }

        var handles = new List<SafeFileHandle>(componentPaths.Count);
        try
        {
            foreach (string componentPath in componentPaths)
            {
                SafeFileHandle handle = CreateFile(
                    componentPath,
                    FileListDirectory | FileReadAttributes,
                    FileShareRead | FileShareWrite,
                    IntPtr.Zero,
                    OpenExisting,
                    FileFlagBackupSemantics | FileFlagOpenReparsePoint,
                    IntPtr.Zero);
                if (handle.IsInvalid)
                {
                    int error = Marshal.GetLastPInvokeError();
                    handle.Dispose();
                    throw new Win32Exception(error, "The export folder could not be locked against path replacement.");
                }

                LocalFileIdentity identity = Capture(handle);
                if (!identity.IsDirectory || identity.IsReparsePoint)
                {
                    handle.Dispose();
                    throw new IOException("The export folder path contains an unsupported reparse point.");
                }

                handles.Add(handle);
            }

            LocalFileIdentity actualIdentity = Capture(handles[^1]);
            if (actualIdentity.VolumeSerialNumber != expectedIdentity.VolumeSerialNumber ||
                actualIdentity.FileIndex != expectedIdentity.FileIndex ||
                !actualIdentity.IsDirectory || actualIdentity.IsReparsePoint)
            {
                throw new IOException("The export folder changed after it was reviewed.");
            }

            var lease = new StableDirectoryLease(fullPath, actualIdentity, handles);
            handles = [];
            return lease;
        }
        finally
        {
            foreach (SafeFileHandle handle in handles)
            {
                handle.Dispose();
            }
        }
    }

    public static SafeFileHandle CreateExclusiveExportFile(string path)
    {
        string fullPath = Path.GetFullPath(path);
        SafeFileHandle handle = CreateFile(
            fullPath,
            GenericWrite | DeleteAccess | FileReadAttributes,
            0,
            IntPtr.Zero,
            CreateNew,
            FileAttributeNormal | FileFlagOverlapped | FileFlagWriteThrough,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new Win32Exception(error, "The temporary export file could not be created.");
        }

        return handle;
    }

    public static void RenameToLockedDestination(
        SafeFileHandle file,
        string destinationPath)
    {
        ArgumentNullException.ThrowIfNull(file);
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);
        if (!Path.IsPathFullyQualified(destinationPath) ||
            destinationPath.StartsWith("\\\\", StringComparison.Ordinal) ||
            destinationPath.StartsWith("\\\\?\\", StringComparison.Ordinal))
        {
            throw new IOException("The export destination is not a fully qualified local path.");
        }

        string fullDestinationPath = Path.GetFullPath(destinationPath);
        byte[] nameBytes = System.Text.Encoding.Unicode.GetBytes(fullDestinationPath);
        int rootHandleOffset = IntPtr.Size == 8 ? 8 : 4;
        int nameLengthOffset = rootHandleOffset + IntPtr.Size;
        int nameOffset = nameLengthOffset + sizeof(int);
        int unalignedBufferSize = checked(nameOffset + nameBytes.Length + sizeof(char));
        int bufferSize = checked((unalignedBufferSize + (IntPtr.Size - 1)) & ~(IntPtr.Size - 1));
        IntPtr buffer = Marshal.AllocHGlobal(bufferSize);
        try
        {
            for (int offset = 0; offset < bufferSize; offset++)
            {
                Marshal.WriteByte(buffer, offset, 0);
            }

            // Every directory component in this absolute path is held without delete sharing by
            // StableDirectoryLease, so Windows cannot resolve the name through a replacement tree.
            Marshal.WriteIntPtr(buffer, rootHandleOffset, IntPtr.Zero);
            Marshal.WriteInt32(buffer, nameLengthOffset, nameBytes.Length);
            Marshal.Copy(nameBytes, 0, IntPtr.Add(buffer, nameOffset), nameBytes.Length);
            if (!SetFileInformationByHandle(file, FileRenameInfo, buffer, (uint)bufferSize))
            {
                int error = Marshal.GetLastPInvokeError();
                throw new Win32Exception(error, $"The completed export could not be published atomically (Windows error {error}).");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static string GetFinalPath(SafeFileHandle file)
    {
        ArgumentNullException.ThrowIfNull(file);
        int capacity = 1024;
        IntPtr buffer = Marshal.AllocHGlobal(checked(capacity * sizeof(char)));
        try
        {
            uint length = GetFinalPathNameByHandle(file, buffer, (uint)capacity, 0);
            if (length == 0)
            {
                throw new Win32Exception(Marshal.GetLastPInvokeError(), "The completed export path could not be verified.");
            }

            if (length >= capacity)
            {
                capacity = checked((int)length + 1);
                buffer = Marshal.ReAllocHGlobal(buffer, (IntPtr)checked(capacity * sizeof(char)));
                length = GetFinalPathNameByHandle(file, buffer, (uint)capacity, 0);
                if (length == 0 || length >= capacity)
                {
                    throw new Win32Exception(Marshal.GetLastPInvokeError(), "The completed export path could not be verified.");
                }
            }

            string path = Marshal.PtrToStringUni(buffer, checked((int)length))
                ?? throw new IOException("The completed export path could not be decoded.");
            return path.StartsWith("\\\\?\\", StringComparison.Ordinal) ? path[4..] : path;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
    private static partial SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation fileInformation);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool SetFileInformationByHandle(
        SafeFileHandle file,
        int fileInformationClass,
        IntPtr fileInformation,
        uint bufferSize);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFinalPathNameByHandleW", SetLastError = true)]
    private static partial uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        IntPtr path,
        uint pathLength,
        uint flags);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public uint CreationTimeLow;
        public uint CreationTimeHigh;
        public uint LastAccessTimeLow;
        public uint LastAccessTimeHigh;
        public uint LastWriteTimeLow;
        public uint LastWriteTimeHigh;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }
}

internal sealed class StableDirectoryLease : IDisposable
{
    private IReadOnlyList<SafeFileHandle>? _handles;

    internal StableDirectoryLease(
        string fullPath,
        LocalFileIdentity identity,
        IReadOnlyList<SafeFileHandle> handles)
    {
        FullPath = fullPath;
        Identity = identity;
        _handles = handles;
    }

    public string FullPath { get; }
    public LocalFileIdentity Identity { get; }
    public SafeFileHandle DirectoryHandle =>
        _handles is { Count: > 0 } handles
            ? handles[^1]
            : throw new ObjectDisposedException(nameof(StableDirectoryLease));

    public void VerifyDestinationAbsent(string fullPath)
    {
        if (!string.Equals(Path.GetDirectoryName(Path.GetFullPath(fullPath)), FullPath, StringComparison.OrdinalIgnoreCase) ||
            File.Exists(fullPath) || Directory.Exists(fullPath))
        {
            throw new IOException("The export destination changed during export.");
        }
    }

    public void Dispose()
    {
        IReadOnlyList<SafeFileHandle>? handles = Interlocked.Exchange(ref _handles, null);
        if (handles is null)
        {
            return;
        }

        for (int index = handles.Count - 1; index >= 0; index--)
        {
            handles[index].Dispose();
        }
    }
}
