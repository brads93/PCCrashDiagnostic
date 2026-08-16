using System.Collections.Concurrent;
using System.Security.Cryptography;
using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Core.Sharing;

public sealed record TechnicalReportExportTicket(
    string Ticket,
    string SuggestedFileName,
    long SizeBytes,
    DateTimeOffset ExpiresUtc,
    IReadOnlyList<string> Members);

public sealed record TechnicalReportExportResult(
    string DestinationFileName,
    long BytesWritten,
    SafeExportDestinationAssessment Destination);

/// <summary>
/// Validates a standard report archive at preview and copy time. This never accepts a source
/// path from UI code and never exports dumps or raw debugger logs outside the standard archive.
/// </summary>
public sealed class TechnicalReportExportValidator
{
    private const long MaximumReportBytes = 512L * 1024 * 1024;
    private const int MaximumActiveTickets = 32;
    private static readonly TimeSpan TicketLifetime = TimeSpan.FromMinutes(5);
    private readonly ConcurrentDictionary<string, ExportEntry> _tickets = new(StringComparer.Ordinal);
    private readonly ReportHandleRegistry _registry;
    private readonly TimeProvider _timeProvider;
    private readonly Action? _beforeDestinationLeaseAcquisition;

    public TechnicalReportExportValidator(ReportHandleRegistry registry, TimeProvider? timeProvider = null)
        : this(registry, timeProvider, beforeDestinationLeaseAcquisition: null)
    {
    }

    internal TechnicalReportExportValidator(
        ReportHandleRegistry registry,
        TimeProvider? timeProvider,
        Action? beforeDestinationLeaseAcquisition)
    {
        _registry = registry ?? throw new ArgumentNullException(nameof(registry));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _beforeDestinationLeaseAcquisition = beforeDestinationLeaseAcquisition;
    }

    public SafeExportDestinationAssessment AssessDestination(string destinationPath) =>
        ValidateDestination(destinationPath).Assessment;

    public async Task<TechnicalReportExportTicket> PrepareAsync(
        UiReportHandle handle,
        CancellationToken cancellationToken = default)
    {
        ResolvedReportHandle resolved = _registry.Resolve(handle);
        ReportHandleFile source = resolved.Files.FirstOrDefault(item =>
                Path.GetExtension(item.FullPath).Equals(".zip", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidDataException("This report format is not supported for technical export yet.");
        byte[] hashBeforeValidation = await ComputeSha256Async(source.FullPath, cancellationToken).ConfigureAwait(false);
        ValidatedReportArchive archive = await IncidentLibrary.ReadValidatedArchiveAsync(source.FullPath, cancellationToken)
            .ConfigureAwait(false);
        if (archive.ReportSchemaVersion is not (2 or 3) ||
            !string.Equals(archive.SessionId, resolved.SessionId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The selected report does not match its registered schema-2/3 identity.");
        }

        source.Snapshot.VerifyUnchanged();
        byte[] sourceSha256 = await ComputeSha256Async(source.FullPath, cancellationToken).ConfigureAwait(false);
        source.Snapshot.VerifyUnchanged();
        if (!CryptographicOperations.FixedTimeEquals(hashBeforeValidation, sourceSha256))
        {
            throw new InvalidDataException("The technical report changed while its export preview was being prepared.");
        }
        long size = source.Snapshot.RootIdentity.SizeBytes;
        if (size is <= 0 or > MaximumReportBytes)
        {
            throw new InvalidDataException("The technical report is empty or exceeds the 512 MiB export limit.");
        }

        DateTimeOffset now = _timeProvider.GetUtcNow();
        foreach (ExportEntry old in _tickets.Values.Where(item => item.ExpiresUtc <= now))
        {
            _tickets.TryRemove(old.Token, out _);
        }

        if (_tickets.Count >= MaximumActiveTickets)
        {
            ExportEntry? oldest = _tickets.Values.OrderBy(item => item.ExpiresUtc).FirstOrDefault();
            if (oldest is not null)
            {
                _tickets.TryRemove(oldest.Token, out _);
            }
        }

        string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        DateTimeOffset expires = now + TicketLifetime;
        _tickets[token] = new ExportEntry(token, expires, resolved.SessionId, handle, source, sourceSha256);
        return new TechnicalReportExportTicket(
            token,
            "PCCrashDiagnostic-Technical-Report-" + now.ToString("yyyyMMdd-HHmm'Z'") + ".zip",
            size,
            expires,
            archive.Members);
    }

    public async Task<TechnicalReportExportResult> ExportAsync(
        string ticket,
        string destinationPath,
        CancellationToken cancellationToken = default)
    {
        ExportEntry entry = Resolve(ticket);
        ResolvedReportHandle current = _registry.Resolve(entry.Handle);
        if (!string.Equals(current.SessionId, entry.SessionId, StringComparison.Ordinal) ||
            !current.Files.Any(item => string.Equals(item.FullPath, entry.Source.FullPath, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("The technical report is no longer bound to the selected history entry.");
        }

        entry.Source.Snapshot.VerifyUnchanged();
        ValidatedReportArchive archive = await IncidentLibrary.ReadValidatedArchiveAsync(entry.Source.FullPath, cancellationToken)
            .ConfigureAwait(false);
        if (archive.ReportSchemaVersion is not (2 or 3) ||
            !string.Equals(archive.SessionId, entry.SessionId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The technical report changed after export preview.");
        }

        ValidatedTechnicalDestination destination = ValidateDestination(destinationPath);
        string temporary = Path.Combine(
            destination.ParentDirectory,
            ".pcd-technical-report-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)).ToLowerInvariant() + ".partial");
        _beforeDestinationLeaseAcquisition?.Invoke();
        using StableDirectoryLease lease = WindowsFileIdentity.AcquireStableDirectory(
            destination.ParentDirectory,
            destination.ParentIdentity);
        lease.VerifyDestinationAbsent(destination.FullPath);
        try
        {
            byte[] copiedSha256;
            using var temporaryHandle = WindowsFileIdentity.CreateExclusiveExportFile(temporary);
            await using (FileStream input = new(
                             entry.Source.FullPath,
                             FileMode.Open,
                             FileAccess.Read,
                             FileShare.Read,
                             128 * 1024,
                             FileOptions.Asynchronous | FileOptions.SequentialScan))
            await using (FileStream output = new(
                             temporaryHandle,
                             FileAccess.Write,
                             128 * 1024,
                             isAsync: true))
            using (IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                byte[] buffer = new byte[128 * 1024];
                int read;
                while ((read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
                {
                    hash.AppendData(buffer, 0, read);
                    await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                }

                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                output.Flush(flushToDisk: true);
                copiedSha256 = hash.GetHashAndReset();
                if (!CryptographicOperations.FixedTimeEquals(entry.SourceSha256, copiedSha256))
                {
                    throw new InvalidDataException("The technical report changed after export preview.");
                }

                entry.Source.Snapshot.VerifyUnchanged();
                LocalFileIdentity partialIdentity = WindowsFileIdentity.Capture(output.SafeFileHandle);
                if (partialIdentity.IsDirectory || partialIdentity.IsReparsePoint ||
                    partialIdentity.SizeBytes != entry.Source.Snapshot.RootIdentity.SizeBytes)
                {
                    throw new IOException("The technical-report copy failed identity validation.");
                }

                cancellationToken.ThrowIfCancellationRequested();
                lease.VerifyDestinationAbsent(destination.FullPath);
                WindowsFileIdentity.RenameToLockedDestination(
                    output.SafeFileHandle,
                    destination.FullPath);
                string publishedPath = WindowsFileIdentity.GetFinalPath(output.SafeFileHandle);
                if (!string.Equals(Path.GetFullPath(publishedPath), destination.FullPath, StringComparison.OrdinalIgnoreCase))
                {
                    throw new IOException($"The completed export was assigned an unexpected filename '{Path.GetFileName(publishedPath)}'.");
                }

                return new TechnicalReportExportResult(
                    Path.GetFileName(destination.FullPath),
                    partialIdentity.SizeBytes,
                    destination.Assessment);
            }
        }
        finally
        {
            try
            {
                if (File.Exists(temporary))
                {
                    File.Delete(temporary);
                }
            }
            catch (IOException)
            {
                // Leave the conspicuously named partial; do not broaden cleanup.
            }
            catch (UnauthorizedAccessException)
            {
                // Leave the conspicuously named partial; do not broaden cleanup.
            }
        }
    }

    public bool Revoke(string ticket) => !string.IsNullOrWhiteSpace(ticket) && _tickets.TryRemove(ticket, out _);

    private ExportEntry Resolve(string ticket)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ticket);
        if (!_tickets.TryGetValue(ticket, out ExportEntry? entry) || entry.ExpiresUtc <= _timeProvider.GetUtcNow())
        {
            _tickets.TryRemove(ticket, out _);
            throw new InvalidOperationException("The technical-report export preview expired. Preview it again before exporting.");
        }

        return entry;
    }

    private static ValidatedTechnicalDestination ValidateDestination(string destinationPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationPath);
        if (!Path.IsPathFullyQualified(destinationPath))
        {
            throw new ArgumentException("Choose an absolute local export path.", nameof(destinationPath));
        }

        string fullPath = Path.GetFullPath(destinationPath);
        if (fullPath.StartsWith("\\\\", StringComparison.Ordinal) ||
            fullPath.StartsWith("\\\\?\\", StringComparison.Ordinal) ||
            !Path.GetExtension(fullPath).Equals(".zip", StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("Technical report export requires a local .zip destination.");
        }

        string parent = Path.GetDirectoryName(fullPath)
            ?? throw new IOException("The export destination has no parent folder.");
        if (!Directory.Exists(parent))
        {
            throw new DirectoryNotFoundException("Create the export destination folder first.");
        }

        string root = Path.GetPathRoot(parent) ?? throw new IOException("The export destination has no drive root.");
        if (new DriveInfo(root).DriveType is DriveType.Network or DriveType.CDRom or DriveType.NoRootDirectory)
        {
            throw new IOException("Technical report export requires a writable local drive.");
        }

        PathSafety.EnsureNoReparseComponents(parent);
        if (File.Exists(fullPath) || Directory.Exists(fullPath))
        {
            throw new IOException("The technical-report destination already exists.");
        }

        LocalFileIdentity parentIdentity = WindowsFileIdentity.Capture(parent);
        return new ValidatedTechnicalDestination(
            fullPath,
            parent,
            parentIdentity,
            SafeExportDestinationClassifier.Classify(parent));
    }

    private static void VerifyDestination(ValidatedTechnicalDestination destination)
    {
        PathSafety.EnsureNoReparseComponents(destination.ParentDirectory);
        LocalFileIdentity current = WindowsFileIdentity.Capture(destination.ParentDirectory);
        if (current.VolumeSerialNumber != destination.ParentIdentity.VolumeSerialNumber ||
            current.FileIndex != destination.ParentIdentity.FileIndex ||
            !current.IsDirectory || current.IsReparsePoint ||
            File.Exists(destination.FullPath) || Directory.Exists(destination.FullPath))
        {
            throw new IOException("The technical-report destination changed during export.");
        }
    }

    private static async Task<byte[]> ComputeSha256Async(string path, CancellationToken cancellationToken)
    {
        await using FileStream stream = new(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        return await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
    }

    private sealed record ExportEntry(
        string Token,
        DateTimeOffset ExpiresUtc,
        string SessionId,
        UiReportHandle Handle,
        ReportHandleFile Source,
        byte[] SourceSha256);

    private sealed record ValidatedTechnicalDestination(
        string FullPath,
        string ParentDirectory,
        LocalFileIdentity ParentIdentity,
        SafeExportDestinationAssessment Assessment);
}
