using System.Security;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Core.Collectors;

/// <summary>
/// Inspects only the fixed-format header bytes needed to identify a Windows dump container.
/// It never parses streams, memory pages, strings, modules, or stack data.
/// </summary>
public sealed class SafeDumpInspector
{
    public const int MaximumHeaderBytesRead = 32;

    public Task<DumpCandidate> InspectAsync(
        string path,
        DumpKind kind,
        string source,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => Inspect(path, kind, source, cancellationToken), cancellationToken);

    public DumpCandidate Inspect(
        string path,
        DumpKind kind,
        string source,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(path);
        }
        catch (ArgumentException)
        {
            return Failure(path, kind, source, DumpInspectionState.Unavailable, "The dump path was invalid.");
        }
        catch (NotSupportedException)
        {
            return Failure(path, kind, source, DumpInspectionState.Unavailable, "The dump path was unsupported.");
        }

        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Path.GetExtension(fullPath).Equals(".dmp", StringComparison.OrdinalIgnoreCase))
            {
                return Failure(fullPath, kind, source, DumpInspectionState.Unrecognized, "The candidate did not have a .dmp extension.");
            }

            PathSafety.EnsureNoReparseComponents(fullPath);
            var before = new FileInfo(fullPath);
            before.Refresh();
            if (!before.Exists)
            {
                return Failure(fullPath, kind, source, DumpInspectionState.Unavailable, "The dump candidate was not present.");
            }

            long expectedLength = before.Length;
            DateTime expectedLastWriteUtc = before.LastWriteTimeUtc;
            byte[] header = new byte[MaximumHeaderBytesRead];
            int bytesRead = 0;
            using (var input = new FileStream(
                       fullPath,
                       FileMode.Open,
                       FileAccess.Read,
                       FileShare.ReadWrite | FileShare.Delete,
                       MaximumHeaderBytesRead,
                       FileOptions.SequentialScan))
            {
                while (bytesRead < header.Length)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    int count = input.Read(header, bytesRead, header.Length - bytesRead);
                    if (count == 0)
                    {
                        break;
                    }

                    bytesRead += count;
                }
            }

            var after = new FileInfo(fullPath);
            after.Refresh();
            if (!after.Exists || after.Length != expectedLength || after.LastWriteTimeUtc != expectedLastWriteUtc)
            {
                return Failure(fullPath, kind, source, DumpInspectionState.Error, "The dump candidate changed during inspection.");
            }

            DumpFormat format = IdentifyFormat(header.AsSpan(0, bytesRead));
            bool plausible = IsSizePlausible(format, expectedLength);
            DumpInspectionState state = format == DumpFormat.Unknown
                ? DumpInspectionState.Unrecognized
                : DumpInspectionState.Recognized;
            string detail = format switch
            {
                DumpFormat.Unknown => "The first 32 bytes did not contain a recognized Windows dump signature.",
                _ when plausible => "Recognized a Windows dump signature using a bounded header read.",
                _ => "Recognized a Windows dump signature, but the file was smaller than the minimum plausibility threshold."
            };
            return new DumpCandidate(
                kind,
                source,
                before.Name,
                EvidencePathRedactor.Redact(fullPath) ?? "<redacted>",
                expectedLength,
                expectedLastWriteUtc,
                format,
                state,
                bytesRead,
                plausible,
                detail,
                fullPath);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            return Failure(fullPath, kind, source, DumpInspectionState.Denied, "Windows denied access. The inspector did not request elevation.");
        }
        catch (SecurityException)
        {
            return Failure(fullPath, kind, source, DumpInspectionState.Denied, "Windows denied access. The inspector did not request elevation.");
        }
        catch (FileNotFoundException)
        {
            return Failure(fullPath, kind, source, DumpInspectionState.Unavailable, "The dump candidate disappeared during inspection.");
        }
        catch (DirectoryNotFoundException)
        {
            return Failure(fullPath, kind, source, DumpInspectionState.Unavailable, "The dump candidate directory was unavailable.");
        }
        catch (IOException)
        {
            return Failure(fullPath, kind, source, DumpInspectionState.Error, "The dump candidate could not be inspected safely.");
        }
    }

    internal static DumpFormat IdentifyFormat(ReadOnlySpan<byte> header)
    {
        if (header.Length >= 4 && header[..4].SequenceEqual("MDMP"u8))
        {
            return DumpFormat.MiniDump;
        }

        if (header.Length >= 8 && header[..4].SequenceEqual("PAGE"u8))
        {
            if (header[4..8].SequenceEqual("DUMP"u8))
            {
                return DumpFormat.PageDump32;
            }

            if (header[4..8].SequenceEqual("DU64"u8))
            {
                return DumpFormat.PageDump64;
            }
        }

        return DumpFormat.Unknown;
    }

    private static bool IsSizePlausible(DumpFormat format, long sizeBytes) => format switch
    {
        DumpFormat.MiniDump => sizeBytes >= 32,
        DumpFormat.PageDump32 or DumpFormat.PageDump64 => sizeBytes >= 4096,
        _ => false
    };

    private static DumpCandidate Failure(
        string path,
        DumpKind kind,
        string source,
        DumpInspectionState state,
        string detail)
    {
        string name;
        try
        {
            name = Path.GetFileName(path);
        }
        catch (ArgumentException)
        {
            name = "Unknown.dmp";
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            name = "Unknown.dmp";
        }

        return new DumpCandidate(
            kind,
            source,
            name,
            EvidencePathRedactor.Redact(path) ?? "<redacted>",
            0,
            DateTimeOffset.UnixEpoch,
            DumpFormat.Unknown,
            state,
            0,
            false,
            detail,
            path);
    }
}
