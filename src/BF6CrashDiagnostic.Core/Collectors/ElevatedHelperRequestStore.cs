using System.Security.Cryptography;
using System.Text.Json;
using BF6CrashDiagnostic.Core.Analysis;
using BF6CrashDiagnostic.Core.Models;
using BF6CrashDiagnostic.Core.Reporting;

namespace BF6CrashDiagnostic.Core.Collectors;

public sealed record ElevatedHelperTicket(
    string RequestId,
    string RequestPath,
    string ResponsePath,
    DateTimeOffset ExpiresUtc);

public sealed record ElevatedHelperOrigin(
    ElevatedHelperRequestStore RequestStore,
    string DataRoot,
    string OriginatingUserSid);

internal sealed record ElevatedHelperOriginCandidate(
    string UserSid,
    string LocalApplicationDataRoot);

internal sealed record ElevatedHelperRequestEnvelope(
    int ProtocolVersion,
    string RequestId,
    DateTimeOffset CreatedUtc,
    DateTimeOffset ExpiresUtc,
    ProtectedEvidenceRequest Request);

internal sealed record ElevatedHelperResponseEnvelope(
    int ProtocolVersion,
    string RequestId,
    DateTimeOffset CreatedUtc,
    ProtectedEvidenceResponse Response);

/// <summary>
/// File-backed one-shot request channel for the UAC helper. The helper accepts
/// only a 32-character random request id and derives both paths from this
/// ACL-restricted local directory; callers cannot supply an elevated output
/// path or arbitrary command line.
/// </summary>
public sealed class ElevatedHelperRequestStore
{
    private const int ProtocolVersion = 2;
    private const int MaximumMessageBytes = 64 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false,
        MaxDepth = 16
    };
    private readonly string _root;
    private readonly System.Security.Principal.SecurityIdentifier? _originatingUserSid;
    private readonly bool _enforceOriginAcl;
    private readonly bool _validateOriginAclOnly;

    internal static string DefaultRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "PCCrashDiagnostic",
        "HelperRequests");

    internal string Root => _root;

    public ElevatedHelperRequestStore()
        : this(
            DefaultRoot,
            System.Security.Principal.WindowsIdentity.GetCurrent().User ??
            throw new InvalidOperationException("The current Windows user SID was unavailable."),
            enforceOriginAcl: true,
            validateOriginAclOnly: false)
    {
    }

    internal ElevatedHelperRequestStore(string root)
        : this(root, originatingUserSid: null, enforceOriginAcl: false, validateOriginAclOnly: false)
    {
    }

    private ElevatedHelperRequestStore(
        string root,
        System.Security.Principal.SecurityIdentifier? originatingUserSid,
        bool enforceOriginAcl,
        bool validateOriginAclOnly)
    {
        _root = Path.GetFullPath(root);
        _originatingUserSid = originatingUserSid;
        _enforceOriginAcl = enforceOriginAcl;
        _validateOriginAclOnly = validateOriginAclOnly;
    }

    public static ElevatedHelperOrigin ResolveOrigin(string requestId)
    {
        string normalized = NormalizeRequestId(requestId);
        var candidates = new List<ElevatedHelperOriginCandidate>();
        using Microsoft.Win32.RegistryKey? profiles = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
            writable: false);
        if (profiles is null)
        {
            throw new IOException("Windows profile metadata was unavailable.");
        }

        foreach (string sidText in profiles.GetSubKeyNames().Take(257))
        {
            if (candidates.Count >= 256)
            {
                throw new InvalidDataException("Too many Windows profiles were present for a bounded helper lookup.");
            }

            try
            {
                _ = new System.Security.Principal.SecurityIdentifier(sidText);
                using Microsoft.Win32.RegistryKey? profile = profiles.OpenSubKey(sidText, writable: false);
                string? profilePath = profile?.GetValue(
                    "ProfileImagePath",
                    null,
                    Microsoft.Win32.RegistryValueOptions.DoNotExpandEnvironmentNames) as string;
                if (string.IsNullOrWhiteSpace(profilePath))
                {
                    continue;
                }

                string expanded = Environment.ExpandEnvironmentVariables(profilePath);
                candidates.Add(new ElevatedHelperOriginCandidate(
                    sidText,
                    Path.Combine(Path.GetFullPath(expanded), "AppData", "Local")));
            }
            catch (Exception exception) when (exception is ArgumentException or IOException or UnauthorizedAccessException)
            {
            }
        }

        return ResolveOriginFromCandidates(normalized, candidates);
    }

    internal static ElevatedHelperOrigin ResolveOriginFromCandidates(
        string requestId,
        IEnumerable<ElevatedHelperOriginCandidate> candidates,
        Action<string, string>? validateBeforeProbe = null,
        Func<string, bool>? fileExists = null)
    {
        string normalized = NormalizeRequestId(requestId);
        validateBeforeProbe ??= static (localRoot, requestPath) =>
        {
            PathSafety.EnsureNoReparseComponents(localRoot);
            PathSafety.EnsureNoReparseComponents(localRoot, requestPath);
        };
        fileExists ??= File.Exists;
        var matches = new List<ElevatedHelperOrigin>();
        foreach (ElevatedHelperOriginCandidate candidate in candidates.Take(257))
        {
            var sid = new System.Security.Principal.SecurityIdentifier(candidate.UserSid);
            string localRoot = ValidateFixedLocalRoot(candidate.LocalApplicationDataRoot);
            string dataRoot = Path.GetFullPath(Path.Combine(localRoot, "PCCrashDiagnostic"));
            string requestRoot = Path.GetFullPath(Path.Combine(dataRoot, "HelperRequests"));
            string requestPath = Path.GetFullPath(Path.Combine(requestRoot, normalized + ".request.json"));
            // Validate every existing component before probing the request name;
            // a planted junction must not turn origin discovery into network I/O.
            validateBeforeProbe(localRoot, requestPath);
            if (!fileExists(requestPath))
            {
                continue;
            }

            OriginDataAcl.VerifyDirectory(requestRoot, sid, userCanWrite: true);
            OriginDataAcl.VerifyFile(requestPath, sid, userCanWrite: true);
            matches.Add(new ElevatedHelperOrigin(
                new ElevatedHelperRequestStore(
                    requestRoot,
                    sid,
                    enforceOriginAcl: true,
                    validateOriginAclOnly: true),
                dataRoot,
                sid.Value));
            if (matches.Count > 1)
            {
                throw new InvalidDataException("The elevated request id appeared in more than one Windows profile.");
            }
        }

        return matches.Count == 1
            ? matches[0]
            : throw new InvalidDataException("The elevated request id was not found in exactly one validated Windows profile.");
    }

    private static string ValidateFixedLocalRoot(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 1_024 ||
            !System.Text.RegularExpressions.Regex.IsMatch(
                path,
                @"^[A-Za-z]:[\\/]",
                System.Text.RegularExpressions.RegexOptions.CultureInvariant) ||
            path.StartsWith(@"\\", StringComparison.Ordinal) ||
            path.StartsWith(@"\\?\", StringComparison.Ordinal) ||
            path.StartsWith(@"\.\", StringComparison.Ordinal))
        {
            throw new InvalidDataException("A Windows profile root was not a bounded local path.");
        }

        string fullPath = Path.GetFullPath(path);
        string root = Path.GetPathRoot(fullPath)
            ?? throw new InvalidDataException("A Windows profile root had no local drive.");
        var drive = new DriveInfo(root);
        if (drive.DriveType != DriveType.Fixed)
        {
            throw new InvalidDataException("A Windows profile root was not on a fixed local drive.");
        }

        return fullPath;
    }

    public async Task<ElevatedHelperTicket> CreateRequestAsync(
        ProtectedEvidenceRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        EnsureRoot();
        string requestId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        DateTimeOffset nowUtc = DateTimeOffset.UtcNow;
        var envelope = new ElevatedHelperRequestEnvelope(
            ProtocolVersion,
            requestId,
            nowUtc,
            nowUtc.AddMinutes(5),
            request);
        (string requestPath, string responsePath) = Paths(requestId);
        await WriteCreateNewAsync(requestPath, envelope, cancellationToken).ConfigureAwait(false);
        return new ElevatedHelperTicket(requestId, requestPath, responsePath, envelope.ExpiresUtc);
    }

    public async Task<ProtectedEvidenceRequest> ConsumeRequestAsync(
        string requestId,
        CancellationToken cancellationToken = default)
    {
        EnsureRoot();
        (string requestPath, _) = Paths(requestId);
        ElevatedHelperRequestEnvelope envelope;
        try
        {
            envelope = await ReadLockedAsync<ElevatedHelperRequestEnvelope>(requestPath, cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            PathSafety.TryDeleteFile(_root, requestPath);
        }

        if (envelope.ProtocolVersion != ProtocolVersion ||
            !string.Equals(envelope.RequestId, requestId, StringComparison.Ordinal) ||
            envelope.ExpiresUtc < DateTimeOffset.UtcNow ||
            envelope.ExpiresUtc - envelope.CreatedUtc > TimeSpan.FromMinutes(5))
        {
            throw new InvalidDataException("The elevated-helper request was invalid or expired.");
        }

        return envelope.Request;
    }

    public async Task PublishResponseAsync(
        string requestId,
        ProtectedEvidenceResponse response,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(response);
        EnsureRoot();
        (_, string responsePath) = Paths(requestId);
        var envelope = new ElevatedHelperResponseEnvelope(
            ProtocolVersion,
            requestId,
            DateTimeOffset.UtcNow,
            response);
        await WriteCreateNewAsync(responsePath, envelope, cancellationToken).ConfigureAwait(false);
    }

    public async Task<ProtectedEvidenceResponse?> TryReadResponseAsync(
        string requestId,
        CancellationToken cancellationToken = default)
    {
        EnsureRoot();
        (_, string responsePath) = Paths(requestId);
        if (!File.Exists(responsePath))
        {
            return null;
        }

        try
        {
            if (new FileInfo(responsePath).Length == 0)
            {
                return null;
            }
        }
        catch (IOException)
        {
            return null;
        }

        ElevatedHelperResponseEnvelope envelope;
        try
        {
            envelope = await ReadLockedAsync<ElevatedHelperResponseEnvelope>(responsePath, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (IOException)
        {
            // The helper creates the response with FileMode.CreateNew and keeps it
            // exclusively locked until serialization is complete. Seeing the name
            // is therefore not proof that the response is ready to consume yet.
            return null;
        }
        catch
        {
            PathSafety.TryDeleteFile(_root, responsePath);
            throw;
        }

        PathSafety.TryDeleteFile(_root, responsePath);

        if (envelope.ProtocolVersion != ProtocolVersion ||
            !string.Equals(envelope.RequestId, requestId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("The elevated-helper response did not match the request.");
        }

        return envelope.Response;
    }

    public void RequestCancellation(string requestId)
    {
        EnsureRoot();
        string path = CancellationPath(requestId);
        PathSafety.EnsureNoReparseComponents(_root, path);
        try
        {
            using FileStream marker = new(
                path,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.Read,
                1,
                FileOptions.WriteThrough);
        }
        catch (IOException) when (File.Exists(path))
        {
        }
    }

    public bool IsCancellationRequested(string requestId)
    {
        EnsureRoot();
        string path = CancellationPath(requestId);
        PathSafety.EnsureNoReparseComponents(_root, path);
        return File.Exists(path);
    }

    public void ClearCancellation(string requestId)
    {
        EnsureRoot();
        PathSafety.TryDeleteFile(_root, CancellationPath(requestId));
    }

    public void DiscardRequest(string requestId)
    {
        EnsureRoot();
        (string requestPath, string responsePath) = Paths(requestId);
        PathSafety.TryDeleteFile(_root, requestPath);
        PathSafety.TryDeleteFile(_root, responsePath);
        PathSafety.TryDeleteFile(_root, CancellationPath(requestId));
    }

    public int CleanupExpiredMessages(DateTimeOffset nowUtc)
    {
        PathSafety.EnsureNoReparseComponents(_root);
        if (!Directory.Exists(_root))
        {
            return 0;
        }

        int removed = 0;
        foreach (string path in Directory.EnumerateFiles(_root, "*", SearchOption.TopDirectoryOnly)
                     .Where(path => Path.GetExtension(path).Equals(".json", StringComparison.OrdinalIgnoreCase) ||
                                    Path.GetExtension(path).Equals(".cancel", StringComparison.OrdinalIgnoreCase)))
        {
            try
            {
                string fullPath = PathSafety.EnsureContained(_root, path);
                PathSafety.EnsureNoReparseComponents(_root, fullPath);
                if (nowUtc - File.GetCreationTimeUtc(fullPath) >= TimeSpan.FromHours(24))
                {
                    File.Delete(fullPath);
                    removed++;
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }

        return removed;
    }

    private void EnsureRoot()
    {
        PathSafety.EnsureNoReparseComponents(_root);
        if (_validateOriginAclOnly)
        {
            if (!Directory.Exists(_root))
            {
                throw new DirectoryNotFoundException("The originating request folder was unavailable.");
            }

            OriginDataAcl.VerifyDirectory(
                _root,
                _originatingUserSid ?? throw new InvalidOperationException("The request origin SID was missing."),
                userCanWrite: true);
            return;
        }

        Directory.CreateDirectory(_root);
        PathSafety.EnsureNoReparseComponents(_root);
        if (_enforceOriginAcl)
        {
            OriginDataAcl.ProtectDirectory(
                _root,
                _originatingUserSid ?? throw new InvalidOperationException("The request origin SID was missing."),
                userCanWrite: true);
        }
        else
        {
            PrivateDirectoryAcl.EnsureRestrictedToCurrentUserAndSystem(_root);
        }
    }

    private (string RequestPath, string ResponsePath) Paths(string requestId)
    {
        string normalized = NormalizeRequestId(requestId);
        string requestPath = PathSafety.EnsureContained(_root, Path.Combine(_root, normalized + ".request.json"));
        string responsePath = PathSafety.EnsureContained(_root, Path.Combine(_root, normalized + ".response.json"));
        return (requestPath, responsePath);
    }

    private string CancellationPath(string requestId)
    {
        string normalized = NormalizeRequestId(requestId);
        return PathSafety.EnsureContained(_root, Path.Combine(_root, normalized + ".cancel"));
    }

    private static string NormalizeRequestId(string requestId)
    {
        if (requestId.Length != 32 || requestId.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new ArgumentException("The elevated-helper request id was invalid.", nameof(requestId));
        }

        return requestId.ToLowerInvariant();
    }

    private async Task<T> ReadLockedAsync<T>(string path, CancellationToken cancellationToken)
    {
        PathSafety.EnsureSafeExistingFile(_root, path);
        var info = new FileInfo(path);
        if (info.Length is <= 0 or > MaximumMessageBytes)
        {
            throw new InvalidDataException("The elevated-helper message exceeded its fixed size limit.");
        }

        await using var input = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.None,
            4096,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        T? value = await JsonSerializer.DeserializeAsync<T>(input, JsonOptions, cancellationToken)
            .ConfigureAwait(false);
        return value ?? throw new InvalidDataException("The elevated-helper message was empty or malformed.");
    }

    private async Task WriteCreateNewAsync<T>(
        string path,
        T value,
        CancellationToken cancellationToken)
    {
        PathSafety.EnsureNoReparseComponents(_root, path);
        bool completed = false;
        try
        {
            await using var output = new FileStream(
                path,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                4096,
                FileOptions.Asynchronous | FileOptions.WriteThrough);
            await JsonSerializer.SerializeAsync(output, value, JsonOptions, cancellationToken).ConfigureAwait(false);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            if (output.Length > MaximumMessageBytes)
            {
                throw new InvalidDataException("The elevated-helper message exceeded its fixed size limit.");
            }

            completed = true;
        }
        finally
        {
            if (!completed)
            {
                PathSafety.TryDeleteFile(_root, path);
            }
        }
    }
}

internal static class OriginDataAcl
{
    public static void ProtectDirectory(
        string path,
        System.Security.Principal.SecurityIdentifier originatingUserSid,
        bool userCanWrite)
    {
        try
        {
            var directory = new DirectoryInfo(path);
            var security = new System.Security.AccessControl.DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.SetOwner(originatingUserSid);
            AddRule(
                security,
                originatingUserSid,
                userCanWrite
                    ? System.Security.AccessControl.FileSystemRights.FullControl
                    : System.Security.AccessControl.FileSystemRights.ReadAndExecute |
                      System.Security.AccessControl.FileSystemRights.Synchronize,
                inherit: true);
            foreach (System.Security.Principal.SecurityIdentifier sid in TrustedAdministrators())
            {
                AddRule(security, sid, System.Security.AccessControl.FileSystemRights.FullControl, inherit: true);
            }

            directory.SetAccessControl(security);
            VerifyDirectory(path, originatingUserSid, userCanWrite);
        }
        catch (Exception exception) when (IsAclFailure(exception))
        {
            throw new IOException("The originating-profile diagnostic folder ACL was invalid.", exception);
        }
    }

    public static void VerifyDirectory(
        string path,
        System.Security.Principal.SecurityIdentifier originatingUserSid,
        bool userCanWrite) => Verify(
        new DirectoryInfo(path).GetAccessControl(),
        originatingUserSid,
        userCanWrite,
        requireProtectedAcl: true);

    public static void VerifyFile(
        string path,
        System.Security.Principal.SecurityIdentifier originatingUserSid,
        bool userCanWrite) => Verify(
        new FileInfo(path).GetAccessControl(),
        originatingUserSid,
        userCanWrite,
        requireProtectedAcl: false);

    private static void Verify(
        System.Security.AccessControl.FileSystemSecurity security,
        System.Security.Principal.SecurityIdentifier originatingUserSid,
        bool userCanWrite,
        bool requireProtectedAcl)
    {
        System.Security.Principal.SecurityIdentifier[] administrators = TrustedAdministrators();
        System.Security.Principal.IdentityReference? owner = security.GetOwner(
            typeof(System.Security.Principal.SecurityIdentifier));
        if (owner is null ||
            requireProtectedAcl && !security.AreAccessRulesProtected ||
            !owner.Equals(originatingUserSid) && !administrators.Contains(owner))
        {
            throw new UnauthorizedAccessException("The originating-profile diagnostic owner was invalid.");
        }

        const System.Security.AccessControl.FileSystemRights writeRights =
            System.Security.AccessControl.FileSystemRights.Write |
            System.Security.AccessControl.FileSystemRights.Modify |
            System.Security.AccessControl.FileSystemRights.FullControl |
            System.Security.AccessControl.FileSystemRights.ChangePermissions |
            System.Security.AccessControl.FileSystemRights.TakeOwnership |
            System.Security.AccessControl.FileSystemRights.Delete;
        foreach (System.Security.AccessControl.FileSystemAccessRule rule in security.GetAccessRules(
                     includeExplicit: true,
                     includeInherited: true,
                     typeof(System.Security.Principal.SecurityIdentifier)))
        {
            if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow ||
                rule.IdentityReference is not System.Security.Principal.SecurityIdentifier sid ||
                (rule.FileSystemRights & writeRights) == 0)
            {
                continue;
            }

            bool writerAllowed = administrators.Contains(sid) ||
                                 userCanWrite && sid.Equals(originatingUserSid);
            if (!writerAllowed)
            {
                throw new UnauthorizedAccessException("An unrelated principal could write the originating-profile diagnostic data.");
            }
        }
    }

    private static void AddRule(
        System.Security.AccessControl.DirectorySecurity security,
        System.Security.Principal.SecurityIdentifier sid,
        System.Security.AccessControl.FileSystemRights rights,
        bool inherit) => security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
        sid,
        rights,
        inherit
            ? System.Security.AccessControl.InheritanceFlags.ContainerInherit |
              System.Security.AccessControl.InheritanceFlags.ObjectInherit
            : System.Security.AccessControl.InheritanceFlags.None,
        System.Security.AccessControl.PropagationFlags.None,
        System.Security.AccessControl.AccessControlType.Allow));

    private static System.Security.Principal.SecurityIdentifier[] TrustedAdministrators() =>
    [
        new(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null),
        new(System.Security.Principal.WellKnownSidType.LocalSystemSid, null)
    ];

    private static bool IsAclFailure(Exception exception) => exception is
        PlatformNotSupportedException or UnauthorizedAccessException or
        System.Security.SecurityException or InvalidOperationException or
        System.ComponentModel.Win32Exception;
}
