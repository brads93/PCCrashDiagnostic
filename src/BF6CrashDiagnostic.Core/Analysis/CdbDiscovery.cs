using System.Diagnostics;
using BF6CrashDiagnostic.Core.Models;

namespace BF6CrashDiagnostic.Core.Analysis;

/// <summary>
/// Finds cdb.exe only in the Windows SDK debugger directory or the packaged
/// Microsoft WinDbg installation. Every result is an x64 PE with a valid,
/// trusted Microsoft Authenticode signature.
/// </summary>
public sealed class CdbDiscovery
{
    private readonly ICdbExecutableVerifier _verifier;

    public CdbDiscovery()
        : this(new AuthenticodeCdbExecutableVerifier())
    {
    }

    internal CdbDiscovery(ICdbExecutableVerifier verifier) => _verifier = verifier;

    public IReadOnlyList<CdbInstallation> Discover()
    {
        var candidates = new List<CdbCandidate>();
        AddSdkCandidate(candidates, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
        AddSdkCandidate(candidates, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        AddPackagedWinDbgCandidates(candidates, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        return DiscoverCandidates(candidates);
    }

    internal IReadOnlyList<CdbInstallation> DiscoverCandidates(IEnumerable<CdbCandidate> candidates)
    {
        var installations = new List<CdbInstallation>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (CdbCandidate candidate in candidates)
        {
            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(candidate.Path);
                if (!candidate.IsApprovedPath(fullPath) || !seen.Add(fullPath) || !File.Exists(fullPath))
                {
                    continue;
                }

                CdbVerificationResult result = _verifier.Verify(fullPath);
                if (!result.IsMicrosoftSigned || !result.IsX64)
                {
                    continue;
                }

                installations.Add(new CdbInstallation(
                    fullPath,
                    result.Version,
                    candidate.Source,
                    result.IsMicrosoftSigned,
                    result.IsX64,
                    result.Signer));
            }
            catch (ArgumentException)
            {
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
            catch (System.Security.SecurityException)
            {
            }
        }

        return installations
            .OrderByDescending(item => ParseVersion(item.Version))
            .ThenBy(item => item.Path, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static void AddSdkCandidate(ICollection<CdbCandidate> candidates, string programFiles)
    {
        if (string.IsNullOrWhiteSpace(programFiles))
        {
            return;
        }

        string root = Path.Combine(programFiles, "Windows Kits", "10", "Debuggers", "x64");
        candidates.Add(new CdbCandidate(Path.Combine(root, "cdb.exe"), root, "Windows SDK"));
    }

    private static void AddPackagedWinDbgCandidates(ICollection<CdbCandidate> candidates, string programFiles)
    {
        if (string.IsNullOrWhiteSpace(programFiles))
        {
            return;
        }

        string windowsApps = Path.Combine(programFiles, "WindowsApps");
        try
        {
            foreach (string packageRoot in Directory.EnumerateDirectories(
                         windowsApps,
                         "Microsoft.WinDbg_*",
                         SearchOption.TopDirectoryOnly))
            {
                string debuggerRoot = Path.Combine(packageRoot, "amd64");
                candidates.Add(new CdbCandidate(
                    Path.Combine(debuggerRoot, "cdb.exe"),
                    debuggerRoot,
                    "Microsoft WinDbg"));
            }
        }
        catch (DirectoryNotFoundException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
        catch (IOException)
        {
        }
    }

    private static Version ParseVersion(string value) =>
        Version.TryParse(value, out Version? version) ? version : new Version(0, 0);
}

internal sealed record CdbCandidate(string Path, string ApprovedRoot, string Source)
{
    public bool IsApprovedPath(string fullPath)
    {
        string fullRoot = System.IO.Path.GetFullPath(ApprovedRoot)
            .TrimEnd(System.IO.Path.DirectorySeparatorChar) + System.IO.Path.DirectorySeparatorChar;
        string expected = System.IO.Path.Combine(fullRoot, "cdb.exe");
        return string.Equals(fullPath, expected, StringComparison.OrdinalIgnoreCase) &&
               !FileSystemInfoHelpers.HasReparseComponent(fullRoot, fullPath);
    }
}

internal sealed record CdbVerificationResult(
    bool IsMicrosoftSigned,
    bool IsX64,
    string Signer,
    string Version);

internal interface ICdbExecutableVerifier
{
    CdbVerificationResult Verify(string path);
}

internal sealed class AuthenticodeCdbExecutableVerifier : ICdbExecutableVerifier
{
    public CdbVerificationResult Verify(string path)
    {
        bool isX64 = PeFileInspector.IsX64(path);
        if (!isX64 || !AuthenticodeTrust.TryGetTrustedSigner(path, out string signer))
        {
            return new CdbVerificationResult(false, isX64, string.Empty, string.Empty);
        }

        bool microsoft = signer.Contains("O=Microsoft Corporation", StringComparison.OrdinalIgnoreCase) ||
                         signer.Contains("CN=Microsoft Windows", StringComparison.OrdinalIgnoreCase);
        string version = FileVersionInfo.GetVersionInfo(path).FileVersion ?? string.Empty;
        return new CdbVerificationResult(microsoft, true, signer, version);
    }
}
