using System.Buffers.Binary;
using System.ComponentModel;
using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace BF6CrashDiagnostic.Core.Reporting;

public sealed class DumpArtifactIdentity
{
    internal DumpArtifactIdentity(
        string fullPath,
        long sizeBytes,
        DateTime lastWriteTimeUtc,
        string extension,
        string dumpSignature,
        string fileIdentityHash)
    {
        FullPath = fullPath;
        SizeBytes = sizeBytes;
        LastWriteTimeUtc = lastWriteTimeUtc;
        Extension = extension;
        DumpSignature = dumpSignature;
        FileIdentityHash = fileIdentityHash;
    }

    public string FullPath { get; }

    public long SizeBytes { get; }

    public DateTime LastWriteTimeUtc { get; }

    public string Extension { get; }

    public string DumpSignature { get; }

    internal string FileIdentityHash { get; }
}

public sealed record DumpPackageContext(
    string SessionId,
    string ReportSha256,
    string SourceType);

public sealed class DumpPackager
{
    private const int BufferSize = 128 * 1024;

    public static DumpArtifactIdentity CaptureIdentity(
        string dumpPath,
        long expectedSizeBytes,
        DateTimeOffset expectedLastWriteUtc)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dumpPath);
        if (expectedSizeBytes < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(expectedSizeBytes));
        }

        string fullDumpPath = Path.GetFullPath(dumpPath);
        string extension = Path.GetExtension(fullDumpPath);
        if (!extension.Equals(".dmp", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Only files with the .dmp extension can be packaged as crash dumps.");
        }

        PathSafety.EnsureNoReparseComponents(fullDumpPath);
        using var input = new FileStream(
            fullDumpPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            4096,
            FileOptions.SequentialScan);

        var info = new FileInfo(fullDumpPath);
        info.Refresh();
        if (!info.Exists ||
            info.Length != expectedSizeBytes ||
            info.LastWriteTimeUtc != expectedLastWriteUtc.UtcDateTime)
        {
            throw new IOException("The crash dump no longer matches the artifact recorded during analysis.");
        }

        string signature = ReadDumpSignature(input);
        string fileIdentityHash = GetFileIdentityHash(input.SafeFileHandle);
        VerifyFileMetadata(fullDumpPath, expectedSizeBytes, expectedLastWriteUtc.UtcDateTime);
        return new DumpArtifactIdentity(
            fullDumpPath,
            expectedSizeBytes,
            expectedLastWriteUtc.UtcDateTime,
            extension.ToLowerInvariant(),
            signature,
            fileIdentityHash);
    }

    internal static bool TryCaptureIdentity(
        string dumpPath,
        long expectedSizeBytes,
        DateTimeOffset expectedLastWriteUtc,
        out DumpArtifactIdentity identity)
    {
        try
        {
            identity = CaptureIdentity(dumpPath, expectedSizeBytes, expectedLastWriteUtc);
            return true;
        }
        catch (ArgumentException)
        {
        }
        catch (IOException)
        {
        }
        catch (InvalidDataException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
        catch (NotSupportedException)
        {
        }

        identity = null!;
        return false;
    }

    public Task<string> PackageAsync(
        DumpArtifactIdentity dumpIdentity,
        string destinationFolder,
        Func<bool> isBf6Running,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default) =>
        PackageCoreAsync(dumpIdentity, destinationFolder, isBf6Running, null, progress, cancellationToken);

    public Task<string> PackageForReportAsync(
        DumpArtifactIdentity dumpIdentity,
        string destinationFolder,
        Func<bool> isProtectedTargetRunning,
        DumpPackageContext context,
        IProgress<double>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        return PackageCoreAsync(
            dumpIdentity,
            destinationFolder,
            isProtectedTargetRunning,
            context,
            progress,
            cancellationToken);
    }

    private async Task<string> PackageCoreAsync(
        DumpArtifactIdentity dumpIdentity,
        string destinationFolder,
        Func<bool> isBf6Running,
        DumpPackageContext? context,
        IProgress<double>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(dumpIdentity);
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationFolder);
        ArgumentNullException.ThrowIfNull(isBf6Running);

        ThrowIfBf6Running(isBf6Running);
        cancellationToken.ThrowIfCancellationRequested();

        string fullDestinationFolder = Path.GetFullPath(destinationFolder);
        PathSafety.EnsureDirectory(fullDestinationFolder, fullDestinationFolder);
        EnsureFreeSpace(fullDestinationFolder, dumpIdentity.SizeBytes);

        PathSafety.EnsureNoReparseComponents(dumpIdentity.FullPath);
        await using var input = new FileStream(
            dumpIdentity.FullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            BufferSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        VerifySourceIdentity(dumpIdentity, input);
        input.Position = 0;

        (string finalPath, string partialPath, FileStream output) =
            CreateUniquePartialArchive(fullDestinationFolder);
        string checksumPath = finalPath + ".sha256";
        string checksumPartialPath = PathSafety.CreateRandomTemporaryPath(
            fullDestinationFolder,
            fullDestinationFolder,
            "dump-checksum");
        bool checksumPublished = false;
        bool packagePublished = false;
        string dumpSha256 = string.Empty;

        try
        {
            await using (output)
            {
                using var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true);
                ZipArchiveEntry warning = archive.CreateEntry("PRIVACY-WARNING.txt", CompressionLevel.NoCompression);
                await using (Stream warningStream = warning.Open())
                await using (var warningWriter = new StreamWriter(warningStream, new UTF8Encoding(false)))
                {
                    await warningWriter.WriteAsync("This archive contains a raw crash dump. It can contain sensitive memory, paths, account material, or other private data. Share it only with a trusted recipient.\r\n").ConfigureAwait(false);
                }

                ZipArchiveEntry dumpEntry = archive.CreateEntry(
                    Path.GetFileName(dumpIdentity.FullPath),
                    CompressionLevel.Fastest);
                using var dumpHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                await using (Stream entryStream = dumpEntry.Open())
                {
                    byte[] buffer = new byte[BufferSize];
                    long copied = 0;
                    while (true)
                    {
                        ThrowIfBf6Running(isBf6Running);
                        int count = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                        if (count == 0)
                        {
                            break;
                        }

                        await entryStream.WriteAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
                        dumpHash.AppendData(buffer, 0, count);
                        copied += count;
                        progress?.Report(dumpIdentity.SizeBytes == 0
                            ? 1
                            : Math.Clamp((double)copied / dumpIdentity.SizeBytes, 0, 1));
                        ThrowIfBf6Running(isBf6Running);
                    }
                }
                dumpSha256 = Convert.ToHexString(dumpHash.GetHashAndReset()).ToLowerInvariant();

                VerifySourceIdentity(dumpIdentity, input);
                ThrowIfBf6Running(isBf6Running);

                ZipArchiveEntry manifest = archive.CreateEntry("Manifest.json", CompressionLevel.Optimal);
                await using Stream manifestStream = manifest.Open();
                await JsonSerializer.SerializeAsync(manifestStream, new
                {
                    PackageSchemaVersion = context is null ? 1 : 2,
                    CreatedUtc = DateTimeOffset.UtcNow,
                    DumpFileName = Path.GetFileName(dumpIdentity.FullPath),
                    Length = dumpIdentity.SizeBytes,
                    LastWriteTimeUtc = dumpIdentity.LastWriteTimeUtc,
                    DumpSignature = dumpIdentity.DumpSignature,
                    DumpSha256 = dumpSha256,
                    SourceType = context?.SourceType ?? "Legacy diagnostic artifact",
                    ReportSessionId = context?.SessionId,
                    ReportSha256 = context?.ReportSha256
                }, cancellationToken: cancellationToken).ConfigureAwait(false);
            }

            VerifySourceIdentity(dumpIdentity, input);
            ThrowIfBf6Running(isBf6Running);
            cancellationToken.ThrowIfCancellationRequested();

            PathSafety.EnsureSafeExistingFile(fullDestinationFolder, partialPath);
            await using (var hashStream = new FileStream(
                             partialPath,
                             FileMode.Open,
                             FileAccess.Read,
                             FileShare.Read,
                             BufferSize,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                string sha = Convert.ToHexString(
                        await SHA256.HashDataAsync(hashStream, cancellationToken).ConfigureAwait(false))
                    .ToLowerInvariant();
                await using var checksumOutput = new FileStream(
                    checksumPartialPath,
                    FileMode.CreateNew,
                    FileAccess.Write,
                    FileShare.None,
                    4096,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                await using var checksumWriter = new StreamWriter(checksumOutput, new UTF8Encoding(false));
                await checksumWriter.WriteAsync(
                    $"{sha} *{Path.GetFileName(finalPath)}{Environment.NewLine}".AsMemory(),
                    cancellationToken).ConfigureAwait(false);
                await checksumWriter.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            VerifySourceIdentity(dumpIdentity, input);
            ThrowIfBf6Running(isBf6Running);
            cancellationToken.ThrowIfCancellationRequested();

            // Publishing is deliberately non-cancellable. The checksum goes first so a
            // final ZIP name is never visible without the checksum for those exact bytes.
            PathSafety.EnsureSafeFileCommit(fullDestinationFolder, checksumPartialPath, checksumPath);
            File.Move(checksumPartialPath, checksumPath);
            checksumPublished = true;

            VerifySourceIdentity(dumpIdentity, input);
            ThrowIfBf6Running(isBf6Running);
            PathSafety.EnsureSafeFileCommit(fullDestinationFolder, partialPath, finalPath);
            File.Move(partialPath, finalPath);
            packagePublished = true;

            progress?.Report(1);
            return finalPath;
        }
        finally
        {
            PathSafety.TryDeleteFile(fullDestinationFolder, partialPath);
            PathSafety.TryDeleteFile(fullDestinationFolder, checksumPartialPath);

            if (!packagePublished && checksumPublished)
            {
                PathSafety.TryDeleteFile(fullDestinationFolder, checksumPath);
            }
        }
    }

    private static void EnsureFreeSpace(string destinationFolder, long dumpSizeBytes)
    {
        string? root = Path.GetPathRoot(destinationFolder);
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new IOException("The destination drive could not be identified for the free-space check.");
        }

        var drive = new DriveInfo(root);
        long reserve = 64L * 1024 * 1024;
        long required = dumpSizeBytes > long.MaxValue - reserve ? long.MaxValue : dumpSizeBytes + reserve;
        if (drive.AvailableFreeSpace < required)
        {
            throw new IOException("The destination does not have enough free space for a separate dump package.");
        }
    }

    private static (string FinalPath, string PartialPath, FileStream Output) CreateUniquePartialArchive(
        string destinationFolder)
    {
        for (int attempt = 0; attempt < 32; attempt++)
        {
            string randomSuffix = Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
            string name = $"PCCrashDiagnostic-Dump-Package-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss-fff}-{randomSuffix}.zip";
            string finalPath = PathSafety.EnsureContained(destinationFolder, Path.Combine(destinationFolder, name));
            string checksumPath = finalPath + ".sha256";
            PathSafety.EnsureNoReparseComponents(destinationFolder, finalPath);
            PathSafety.EnsureNoReparseComponents(destinationFolder, checksumPath);
            if (File.Exists(finalPath) || File.Exists(checksumPath))
            {
                continue;
            }

            string partialPath = PathSafety.CreateRandomTemporaryPath(
                destinationFolder,
                destinationFolder,
                "dump-archive");
            try
            {
                var output = new FileStream(
                    partialPath,
                    FileMode.CreateNew,
                    FileAccess.ReadWrite,
                    FileShare.None,
                    BufferSize,
                    FileOptions.Asynchronous | FileOptions.SequentialScan);
                return (finalPath, partialPath, output);
            }
            catch (IOException) when (File.Exists(partialPath))
            {
                PathSafety.TryDeleteFile(destinationFolder, partialPath);
            }
        }

        throw new IOException("Could not reserve a unique crash dump package name.");
    }

    private static void VerifySourceIdentity(DumpArtifactIdentity expected, FileStream input)
    {
        string fullPath = Path.GetFullPath(expected.FullPath);
        if (!string.Equals(fullPath, expected.FullPath, StringComparison.OrdinalIgnoreCase) ||
            !Path.GetExtension(fullPath).Equals(expected.Extension, StringComparison.OrdinalIgnoreCase))
        {
            throw SourceChanged();
        }

        PathSafety.EnsureNoReparseComponents(fullPath);
        VerifyFileMetadata(fullPath, expected.SizeBytes, expected.LastWriteTimeUtc);
        if (input.Length != expected.SizeBytes ||
            !string.Equals(ReadDumpSignature(input), expected.DumpSignature, StringComparison.Ordinal) ||
            !string.Equals(GetFileIdentityHash(input.SafeFileHandle), expected.FileIdentityHash, StringComparison.Ordinal))
        {
            throw SourceChanged();
        }

        VerifyFileMetadata(fullPath, expected.SizeBytes, expected.LastWriteTimeUtc);
    }

    private static void VerifyFileMetadata(string fullPath, long expectedLength, DateTime expectedLastWriteUtc)
    {
        var current = new FileInfo(fullPath);
        current.Refresh();
        if (!current.Exists ||
            !string.Equals(current.FullName, fullPath, StringComparison.OrdinalIgnoreCase) ||
            current.Length != expectedLength ||
            current.LastWriteTimeUtc != expectedLastWriteUtc)
        {
            throw SourceChanged();
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

    private static void ThrowIfBf6Running(Func<bool> isBf6Running)
    {
        if (isBf6Running())
        {
            throw new InvalidOperationException("Crash dump packaging is unavailable while BF6 is running.");
        }
    }

    private static IOException SourceChanged() =>
        new("The selected crash dump changed after analysis. No package was published; run a new analysis before trying again.");

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
