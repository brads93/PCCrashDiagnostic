using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Core.Collectors;

/// <summary>
/// Reads documented user-mode MINIDUMP streams through MiniDumpReadDumpStream.
/// It does not read memory ranges, exception context, strings, module paths, or
/// stack frames. Kernel dump formats remain header-only until WinDbg is used.
/// </summary>
public sealed class MiniDumpMetadataReader
{
    private const int ThreadListStream = 3;
    private const int ModuleListStream = 4;
    private const int SystemInfoStream = 7;
    private const int MiscInfoStream = 15;

    public Task<MiniDumpMetadata> ReadAsync(
        DumpCandidate candidate,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => Read(candidate, cancellationToken), cancellationToken);

    public MiniDumpMetadata Read(
        DumpCandidate candidate,
        CancellationToken cancellationToken = default,
        Func<bool>? isSensitiveOperationBlocked = null)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        ThrowIfSensitiveOperationBlocked(isSensitiveOperationBlocked);
        if (candidate.InspectionState != DumpInspectionState.Recognized ||
            candidate.Format == DumpFormat.Unknown)
        {
            return Empty(MiniDumpMetadataState.Unrecognized, candidate.Format,
                "The candidate did not have a recognized Windows dump signature.");
        }

        if (candidate.Format is DumpFormat.PageDump32 or DumpFormat.PageDump64)
        {
            return Empty(
                MiniDumpMetadataState.RecognizedKernelDump,
                candidate.Format,
                "A kernel PAGEDUMP signature was recognized. Only signature metadata is inspected until WinDbg is available.");
        }

        if (!candidate.SizePlausible || string.IsNullOrWhiteSpace(candidate.OriginalPath))
        {
            return Empty(MiniDumpMetadataState.Invalid, candidate.Format,
                "The user-mode minidump was truncated or unavailable.");
        }

        string fullPath;
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfSensitiveOperationBlocked(isSensitiveOperationBlocked);
            fullPath = Path.GetFullPath(candidate.OriginalPath);
            _ = DumpPackager.CaptureIdentity(fullPath, candidate.SizeBytes, candidate.LastWriteUtc);
            ThrowIfSensitiveOperationBlocked(isSensitiveOperationBlocked);
        }
        catch (UnauthorizedAccessException)
        {
            return Empty(MiniDumpMetadataState.Denied, candidate.Format,
                "Windows denied access to the minidump.");
        }
        catch (IOException)
        {
            return Empty(MiniDumpMetadataState.Unavailable, candidate.Format,
                "The minidump changed or became unavailable before stream inspection.");
        }
        catch (InvalidDataException)
        {
            return Empty(MiniDumpMetadataState.Invalid, candidate.Format,
                "The file no longer had a valid minidump signature.");
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfSensitiveOperationBlocked(isSensitiveOperationBlocked);
            using MemoryMappedFile mapping = MemoryMappedFile.CreateFromFile(
                fullPath,
                FileMode.Open,
                null,
                0,
                MemoryMappedFileAccess.Read);
            using MemoryMappedViewAccessor view = mapping.CreateViewAccessor(
                0,
                0,
                MemoryMappedFileAccess.Read);
            bool addedRef = false;
            try
            {
                view.SafeMemoryMappedViewHandle.DangerousAddRef(ref addedRef);
                IntPtr baseAddress = view.SafeMemoryMappedViewHandle.DangerousGetHandle();
                long mappedLength = candidate.SizeBytes;
                var streams = new List<string>();

                string architecture = string.Empty;
                int? processorCount = null;
                int? major = null;
                int? minor = null;
                int? build = null;
                ThrowIfSensitiveOperationBlocked(isSensitiveOperationBlocked);
                if (TryGetStream(baseAddress, mappedLength, SystemInfoStream, 28, out IntPtr systemInfo, out _))
                {
                    streams.Add("SystemInfoStream");
                    ushort architectureCode = unchecked((ushort)Marshal.ReadInt16(systemInfo, 0));
                    architecture = ArchitectureName(architectureCode);
                    processorCount = Marshal.ReadByte(systemInfo, 6);
                    major = Marshal.ReadInt32(systemInfo, 8);
                    minor = Marshal.ReadInt32(systemInfo, 12);
                    build = Marshal.ReadInt32(systemInfo, 16);
                }

                uint? processId = null;
                DateTimeOffset? processCreateTime = null;
                ThrowIfSensitiveOperationBlocked(isSensitiveOperationBlocked);
                if (TryGetStream(baseAddress, mappedLength, MiscInfoStream, 24, out IntPtr miscInfo, out uint miscSize))
                {
                    uint declaredSize = unchecked((uint)Marshal.ReadInt32(miscInfo, 0));
                    uint flags = unchecked((uint)Marshal.ReadInt32(miscInfo, 4));
                    if (declaredSize >= 24 && declaredSize <= miscSize)
                    {
                        streams.Add("MiscInfoStream");
                        if ((flags & 0x00000001) != 0)
                        {
                            processId = unchecked((uint)Marshal.ReadInt32(miscInfo, 8));
                        }

                        if ((flags & 0x00000002) != 0)
                        {
                            uint unixSeconds = unchecked((uint)Marshal.ReadInt32(miscInfo, 12));
                            processCreateTime = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);
                        }
                    }
                }

                ThrowIfSensitiveOperationBlocked(isSensitiveOperationBlocked);
                int? threadCount = TryReadBoundedCount(
                    baseAddress,
                    mappedLength,
                    ThreadListStream,
                    "ThreadListStream",
                    streams);
                ThrowIfSensitiveOperationBlocked(isSensitiveOperationBlocked);
                int? moduleCount = TryReadBoundedCount(
                    baseAddress,
                    mappedLength,
                    ModuleListStream,
                    "ModuleListStream",
                    streams);

                cancellationToken.ThrowIfCancellationRequested();
                ThrowIfSensitiveOperationBlocked(isSensitiveOperationBlocked);
                if (streams.Count == 0)
                {
                    return Empty(MiniDumpMetadataState.Invalid, candidate.Format,
                        "The MDMP container did not expose any supported documented streams.");
                }

                return new MiniDumpMetadata(
                    MiniDumpMetadataState.ParsedUserModeMiniDump,
                    candidate.Format,
                    architecture,
                    processorCount,
                    major,
                    minor,
                    build,
                    processId,
                    processCreateTime,
                    threadCount,
                    moduleCount,
                    streams,
                    "Read bounded metadata from documented user-mode minidump streams. No process memory or paths were read.");
            }
            finally
            {
                if (addedRef)
                {
                    view.SafeMemoryMappedViewHandle.DangerousRelease();
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            return Empty(MiniDumpMetadataState.Denied, candidate.Format,
                "Windows denied access to the minidump.");
        }
        catch (Exception exception) when (exception is IOException or ArgumentException or DllNotFoundException or EntryPointNotFoundException)
        {
            return Empty(MiniDumpMetadataState.Failed, candidate.Format,
                "The documented minidump stream reader could not parse the file safely.");
        }
    }

    private static int? TryReadBoundedCount(
        IntPtr baseAddress,
        long mappedLength,
        int streamType,
        string streamName,
        ICollection<string> streams)
    {
        if (!TryGetStream(baseAddress, mappedLength, streamType, 4, out IntPtr stream, out _))
        {
            return null;
        }

        uint count = unchecked((uint)Marshal.ReadInt32(stream, 0));
        if (count > 1_000_000)
        {
            return null;
        }

        streams.Add(streamName);
        return checked((int)count);
    }

    private static void ThrowIfSensitiveOperationBlocked(Func<bool>? boundary)
    {
        if (boundary is null)
        {
            return;
        }

        try
        {
            if (!boundary())
            {
                return;
            }
        }
        catch
        {
            // Boundary queries fail closed.
        }

        throw new SensitiveDumpOperationBlockedException();
    }

    private static bool TryGetStream(
        IntPtr baseAddress,
        long mappedLength,
        int streamType,
        uint minimumSize,
        out IntPtr stream,
        out uint streamSize)
    {
        stream = IntPtr.Zero;
        streamSize = 0;
        if (!MiniDumpReadDumpStream(baseAddress, streamType, out _, out IntPtr candidate, out uint size) ||
            candidate == IntPtr.Zero || size < minimumSize)
        {
            return false;
        }

        ulong mapStart = unchecked((ulong)baseAddress.ToInt64());
        ulong mapEnd = mapStart + checked((ulong)mappedLength);
        ulong streamStart = unchecked((ulong)candidate.ToInt64());
        ulong streamEnd = streamStart + size;
        if (mapEnd < mapStart || streamEnd < streamStart || streamStart < mapStart || streamEnd > mapEnd)
        {
            return false;
        }

        stream = candidate;
        streamSize = size;
        return true;
    }

    private static string ArchitectureName(ushort architecture) => architecture switch
    {
        0 => "x86",
        5 => "ARM",
        6 => "IA64",
        9 => "x64",
        12 => "ARM64",
        _ => $"Unknown ({architecture})"
    };

    private static MiniDumpMetadata Empty(
        MiniDumpMetadataState state,
        DumpFormat format,
        string detail) =>
        new(state, format, string.Empty, null, null, null, null, null, null, null, null, [], detail);

    [DllImport("dbghelp.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool MiniDumpReadDumpStream(
        IntPtr baseOfDump,
        int streamNumber,
        out IntPtr directory,
        out IntPtr streamPointer,
        out uint streamSize);
}
