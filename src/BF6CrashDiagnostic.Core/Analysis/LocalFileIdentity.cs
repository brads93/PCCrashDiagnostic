using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Text;
using BF6CrashDiagnostic.Core.Reporting;
using Microsoft.Win32.SafeHandles;

namespace BF6CrashDiagnostic.Core.Analysis;

/// <summary>
/// A local file identity used to keep a debugger input stable between
/// validation and launch. This type has no report-packaging semantics.
/// </summary>
internal sealed record LocalFileIdentity(
    string FullPath,
    long SizeBytes,
    DateTime LastWriteTimeUtc,
    string DumpSignature,
    string FileIdentityHash);

internal static class LocalFileIdentityCapture
{
    public static LocalFileIdentity Capture(
        string dumpPath,
        long expectedSizeBytes,
        DateTimeOffset expectedLastWriteUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dumpPath);
        string fullPath = ValidatePath(dumpPath);
        using var input = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            4096,
            FileOptions.SequentialScan);
        return CaptureOpened(fullPath, input, expectedSizeBytes, expectedLastWriteUtc);
    }

    public static LocalFileIdentity CaptureOpened(
        string dumpPath,
        FileStream input,
        long expectedSizeBytes,
        DateTimeOffset expectedLastWriteUtc)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (expectedSizeBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedSizeBytes));
        }

        string fullPath = ValidatePath(dumpPath);
        VerifyMetadata(fullPath, input, expectedSizeBytes, expectedLastWriteUtc.UtcDateTime);
        string signature = ReadDumpSignature(input);
        string fileIdentityHash = GetFileIdentityHash(input.SafeFileHandle);
        VerifyMetadata(fullPath, input, expectedSizeBytes, expectedLastWriteUtc.UtcDateTime);
        return new LocalFileIdentity(
            fullPath,
            expectedSizeBytes,
            expectedLastWriteUtc.UtcDateTime,
            signature,
            fileIdentityHash);
    }

    public static bool IsSameFile(LocalFileIdentity expected, LocalFileIdentity actual) =>
        string.Equals(expected.FullPath, actual.FullPath, StringComparison.OrdinalIgnoreCase) &&
        expected.SizeBytes == actual.SizeBytes &&
        expected.LastWriteTimeUtc == actual.LastWriteTimeUtc &&
        string.Equals(expected.DumpSignature, actual.DumpSignature, StringComparison.Ordinal) &&
        string.Equals(expected.FileIdentityHash, actual.FileIdentityHash, StringComparison.Ordinal);

    private static string ValidatePath(string dumpPath)
    {
        string fullPath = Path.GetFullPath(dumpPath);
        if (!Path.GetExtension(fullPath).Equals(".dmp", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Only a .dmp file can be used for debugger analysis.");
        }

        PathSafety.EnsureNoReparseComponents(fullPath);
        return fullPath;
    }

    private static void VerifyMetadata(
        string fullPath,
        FileStream input,
        long expectedSizeBytes,
        DateTime expectedLastWriteUtc)
    {
        var info = new FileInfo(fullPath);
        info.Refresh();
        if (!info.Exists ||
            !string.Equals(info.FullName, fullPath, StringComparison.OrdinalIgnoreCase) ||
            info.Length != expectedSizeBytes ||
            info.LastWriteTimeUtc != expectedLastWriteUtc ||
            input.Length != expectedSizeBytes)
        {
            throw new IOException("The selected dump changed after it was inventoried.");
        }
    }

    private static string ReadDumpSignature(FileStream input)
    {
        long originalPosition = input.Position;
        try
        {
            input.Position = 0;
            Span<byte> header = stackalloc byte[8];
            int totalRead = 0;
            while (totalRead < header.Length)
            {
                int read = input.Read(header[totalRead..]);
                if (read == 0)
                {
                    break;
                }

                totalRead += read;
            }

            if (totalRead >= 4 && header[..4].SequenceEqual("MDMP"u8))
            {
                return "MDMP";
            }

            if (totalRead >= 8 &&
                header[..4].SequenceEqual("PAGE"u8) &&
                (header[4..8].SequenceEqual("DUMP"u8) || header[4..8].SequenceEqual("DU64"u8)))
            {
                return Encoding.ASCII.GetString(header);
            }

            throw new InvalidDataException("The selected file does not have a recognized Windows crash-dump signature.");
        }
        finally
        {
            input.Position = originalPosition;
        }
    }

    private static string GetFileIdentityHash(SafeFileHandle handle)
    {
        if (!GetFileInformationByHandle(handle, out ByHandleFileInformation information))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not read the crash dump file identity.");
        }

        Span<byte> identity = stackalloc byte[12];
        BinaryPrimitives.WriteUInt32LittleEndian(identity, information.VolumeSerialNumber);
        BinaryPrimitives.WriteUInt32LittleEndian(identity[4..], information.FileIndexHigh);
        BinaryPrimitives.WriteUInt32LittleEndian(identity[8..], information.FileIndexLow);
        return Convert.ToHexString(SHA256.HashData(identity)).ToLowerInvariant();
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation fileInformation);

    [StructLayout(LayoutKind.Sequential)]
    private struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public FILETIME CreationTime;
        public FILETIME LastAccessTime;
        public FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }
}
