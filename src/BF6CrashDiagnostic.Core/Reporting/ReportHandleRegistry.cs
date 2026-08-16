using System.Collections.Concurrent;
using System.ComponentModel;
using System.Security.Cryptography;

namespace BF6CrashDiagnostic.Core.Reporting;

public enum ReportOrigin
{
    Generated,
    Imported
}

/// <summary>
/// Process-local capability for one validated report. It intentionally cannot reveal or
/// accept a filesystem path, and it cannot be constructed outside the Core assembly.
/// </summary>
public sealed class UiReportHandle : IEquatable<UiReportHandle>
{
    internal UiReportHandle(string token)
    {
        Token = token;
    }

    internal string Token { get; }

    public bool Equals(UiReportHandle? other) =>
        other is not null && CryptographicOperations.FixedTimeEquals(
            Convert.FromHexString(Token),
            Convert.FromHexString(other.Token));

    public override bool Equals(object? obj) => Equals(obj as UiReportHandle);

    public override int GetHashCode() => StringComparer.Ordinal.GetHashCode(Token);

    public override string ToString() => "PC Crash Diagnostic report";
}

internal sealed record ReportHandleFile(
    string FullPath,
    ReportOrigin Origin,
    FileTreeSnapshot Snapshot);

internal sealed record ResolvedReportHandle(
    string SessionId,
    IReadOnlyList<ReportHandleFile> Files,
    DateTimeOffset ExpiresUtc);

public sealed class ReportHandleRegistry
{
    private const long MaximumReportBytes = 512L * 1024 * 1024;
    private const int MaximumLocalReportCopies = 256;
    private static readonly TimeSpan DefaultLifetime = TimeSpan.FromHours(1);

    private readonly ConcurrentDictionary<string, ResolvedReportHandle> _entries = new(StringComparer.Ordinal);
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _lifetime;
    private readonly string _dataRoot;
    private readonly string _reportsRoot;
    private readonly string _importsRoot;

    public ReportHandleRegistry(
        string dataRoot,
        TimeProvider? timeProvider = null,
        TimeSpan? handleLifetime = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataRoot);
        if (!Path.IsPathFullyQualified(dataRoot))
        {
            throw new ArgumentException("The report registry requires an absolute data root.", nameof(dataRoot));
        }

        _dataRoot = Path.GetFullPath(dataRoot);
        _reportsRoot = Path.Combine(_dataRoot, "Reports");
        _importsRoot = Path.Combine(_dataRoot, "Library", "ImportedReports");
        _timeProvider = timeProvider ?? TimeProvider.System;
        _lifetime = handleLifetime ?? DefaultLifetime;
        if (_lifetime <= TimeSpan.Zero || _lifetime > TimeSpan.FromHours(24))
        {
            throw new ArgumentOutOfRangeException(nameof(handleLifetime), "Handle lifetime must be between zero and 24 hours.");
        }
    }

    public async Task<UiReportHandle> RegisterValidatedAsync(
        ReportOrigin origin,
        IEnumerable<string> localReportPaths,
        CancellationToken cancellationToken = default) =>
        await RegisterValidatedCopiesAsync(
                localReportPaths.Select(path => new LocalReportCopy(path, origin == ReportOrigin.Imported)),
                cancellationToken)
            .ConfigureAwait(false);

    /// <summary>
    /// Binds every validated app-local archive for one logical report session. Each copy is
    /// independently constrained to the generated or imported report root recorded for it;
    /// external import sources therefore cannot become part of the handle.
    /// </summary>
    public async Task<UiReportHandle> RegisterValidatedCopiesAsync(
        IEnumerable<LocalReportCopy> localReportCopies,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(localReportCopies);
        LocalReportCopy[] suppliedCopies = localReportCopies
            .Take(MaximumLocalReportCopies + 1)
            .ToArray();
        if (suppliedCopies.Length is 0 or > MaximumLocalReportCopies)
        {
            throw new ArgumentException(
                $"A report handle must bind one to {MaximumLocalReportCopies} local report copies.",
                nameof(localReportCopies));
        }

        ReportHandleFile[] files = suppliedCopies
            .Select(copy => ValidateReportFile(
                copy.Imported ? ReportOrigin.Imported : ReportOrigin.Generated,
                copy.ReportPath))
            .DistinctBy(item => item.FullPath, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        string? sessionId = null;
        foreach (ReportHandleFile file in files)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!Path.GetExtension(file.FullPath).Equals(".zip", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("This report format cannot be registered until its archive validator is available.");
            }

            ValidatedReportArchive validated = await IncidentLibrary.ReadValidatedArchiveAsync(file.FullPath, cancellationToken)
                .ConfigureAwait(false);
            file.Snapshot.VerifyUnchanged();
            if (sessionId is null)
            {
                sessionId = validated.SessionId;
            }
            else if (!string.Equals(sessionId, validated.SessionId, StringComparison.Ordinal))
            {
                throw new InvalidDataException("All local report copies in one handle must have the same report session identity.");
            }
        }

        if (sessionId is null || !SessionIdValidator.IsValid(sessionId))
        {
            throw new InvalidDataException("The validated report session ID is invalid.");
        }

        return RegisterCore(sessionId, files);
    }

    internal UiReportHandle Register(
        string sessionId,
        ReportOrigin origin,
        IEnumerable<string> localReportPaths)
    {
        if (!SessionIdValidator.IsValid(sessionId))
        {
            throw new ArgumentException("The report session ID is invalid.", nameof(sessionId));
        }

        ArgumentNullException.ThrowIfNull(localReportPaths);
        string[] suppliedPaths = localReportPaths
            .Take(MaximumLocalReportCopies + 1)
            .ToArray();
        if (suppliedPaths.Length is 0 or > MaximumLocalReportCopies)
        {
            throw new ArgumentException(
                $"A report handle must bind one to {MaximumLocalReportCopies} local report copies.",
                nameof(localReportPaths));
        }

        ReportHandleFile[] files = suppliedPaths
            .Select(path => ValidateReportFile(origin, path))
            .DistinctBy(item => item.FullPath, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return RegisterCore(sessionId, files);
    }

    private UiReportHandle RegisterCore(
        string sessionId,
        IReadOnlyList<ReportHandleFile> files)
    {
        DateTimeOffset expires = _timeProvider.GetUtcNow() + _lifetime;
        for (int attempt = 0; attempt < 8; attempt++)
        {
            string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
            if (_entries.TryAdd(token, new ResolvedReportHandle(sessionId, files, expires)))
            {
                return new UiReportHandle(token);
            }
        }

        throw new CryptographicException("Could not allocate a unique report handle.");
    }

    public bool IsValid(UiReportHandle? handle)
    {
        if (handle is null)
        {
            return false;
        }

        try
        {
            _ = Resolve(handle);
            return true;
        }
        catch (Exception exception) when (exception is InvalidOperationException or IOException or UnauthorizedAccessException or Win32Exception)
        {
            _entries.TryRemove(handle.Token, out _);
            return false;
        }
    }

    public bool Revoke(UiReportHandle? handle) =>
        handle is not null && _entries.TryRemove(handle.Token, out _);

    public void RevokeAll() => _entries.Clear();

    internal ResolvedReportHandle Resolve(UiReportHandle handle)
    {
        ArgumentNullException.ThrowIfNull(handle);
        if (!_entries.TryGetValue(handle.Token, out ResolvedReportHandle? entry) ||
            entry.ExpiresUtc <= _timeProvider.GetUtcNow())
        {
            _entries.TryRemove(handle.Token, out _);
            throw new InvalidOperationException("The report selection expired. Select the report again.");
        }

        foreach (ReportHandleFile file in entry.Files)
        {
            file.Snapshot.VerifyUnchanged();
            ValidateReportFile(file.Origin, file.FullPath);
        }

        return entry;
    }

    internal string DataRoot => _dataRoot;

    private string RootFor(ReportOrigin origin) => origin switch
    {
        ReportOrigin.Generated => _reportsRoot,
        ReportOrigin.Imported => _importsRoot,
        _ => throw new ArgumentOutOfRangeException(nameof(origin))
    };

    private ReportHandleFile ValidateReportFile(ReportOrigin origin, string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string trustedRoot = RootFor(origin);
        string fullPath = PathSafety.EnsureContained(trustedRoot, path);
        string extension = Path.GetExtension(fullPath);
        if (!extension.Equals(".zip", StringComparison.OrdinalIgnoreCase) &&
            !extension.Equals(".pcdreport", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Only a standard PC Crash Diagnostic report can be registered.");
        }

        PathSafety.EnsureNoReparseComponents(trustedRoot, fullPath);
        FileTreeSnapshot snapshot = FileTreeSnapshot.Capture(fullPath);
        if (snapshot.RootIdentity.IsDirectory || snapshot.RootIdentity.IsReparsePoint ||
            snapshot.RootIdentity.SizeBytes is <= 0 or > MaximumReportBytes)
        {
            throw new InvalidDataException("The report file is empty, too large, or not a regular file.");
        }

        return new ReportHandleFile(fullPath, origin, snapshot);
    }
}
