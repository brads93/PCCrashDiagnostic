using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
        candidates.Add(new CdbCandidate(
            Path.Combine(root, "cdb.exe"),
            root,
            "Windows SDK"));
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

internal static class PeFileInspector
{
    private const ushort ImageFileMachineAmd64 = 0x8664;

    public static bool IsX64(string path)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            Span<byte> dosHeader = stackalloc byte[64];
            if (stream.Read(dosHeader) != dosHeader.Length || dosHeader[0] != (byte)'M' || dosHeader[1] != (byte)'Z')
            {
                return false;
            }

            int peOffset = BitConverter.ToInt32(dosHeader[0x3c..0x40]);
            if (peOffset < 64 || peOffset > 1024 * 1024 || peOffset > stream.Length - 6)
            {
                return false;
            }

            stream.Position = peOffset;
            Span<byte> peHeader = stackalloc byte[6];
            if (stream.Read(peHeader) != peHeader.Length ||
                peHeader[0] != (byte)'P' || peHeader[1] != (byte)'E' ||
                peHeader[2] != 0 || peHeader[3] != 0)
            {
                return false;
            }

            return BitConverter.ToUInt16(peHeader[4..6]) == ImageFileMachineAmd64;
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }
}

internal static class AuthenticodeTrust
{
    private static readonly Guid WinTrustActionGenericVerifyV2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public static bool TryGetTrustedSigner(string path, out string signerSubject)
    {
        signerSubject = string.Empty;
        var fileInfo = new WinTrustFileInfo(path);
        IntPtr fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        WinTrustData trustData = default;
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, false);
            trustData = new WinTrustData(fileInfoPointer, stateAction: 1);
            Guid action = WinTrustActionGenericVerifyV2;
            int trustStatus = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);
            if (trustStatus != 0 || trustData.StateData == IntPtr.Zero)
            {
                signerSubject = $"WinVerifyTrust=0x{trustStatus:X8}; state={trustData.StateData}";
                return false;
            }

            IntPtr providerData = WTHelperProvDataFromStateData(trustData.StateData);
            IntPtr providerSigner = providerData == IntPtr.Zero
                ? IntPtr.Zero
                : WTHelperGetProvSignerFromChain(providerData, 0, false, 0);
            if (providerSigner == IntPtr.Zero)
            {
                signerSubject = $"ProviderData={providerData}; providerSigner={providerSigner}";
                return false;
            }

            CryptProviderSigner signer = Marshal.PtrToStructure<CryptProviderSigner>(providerSigner);
            if (signer.CertificateChain == IntPtr.Zero || signer.CertificateCount == 0)
            {
                signerSubject = $"CertificateCount={signer.CertificateCount}; chain={signer.CertificateChain}";
                return false;
            }

            CryptProviderCertificate providerCertificate =
                Marshal.PtrToStructure<CryptProviderCertificate>(signer.CertificateChain);
            if (providerCertificate.CertificateContext == IntPtr.Zero)
            {
                signerSubject = "Provider certificate context was null.";
                return false;
            }

            CertificateContext certificateContext =
                Marshal.PtrToStructure<CertificateContext>(providerCertificate.CertificateContext);
            if (certificateContext.EncodedCertificate == IntPtr.Zero ||
                certificateContext.EncodedCertificateSize is 0 or > 1024 * 1024)
            {
                signerSubject = $"EncodedCertificate={certificateContext.EncodedCertificate}; size={certificateContext.EncodedCertificateSize}";
                return false;
            }

            byte[] encoded = new byte[checked((int)certificateContext.EncodedCertificateSize)];
            Marshal.Copy(certificateContext.EncodedCertificate, encoded, 0, encoded.Length);
            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(encoded);
            signerSubject = certificate.Subject;
            return signerSubject.Length > 0;
        }
        catch (DllNotFoundException)
        {
            return false;
        }
        catch (EntryPointNotFoundException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
        finally
        {
            if (trustData.StateData != IntPtr.Zero)
            {
                trustData.StateAction = 2; // WTD_STATEACTION_CLOSE
                Guid closeAction = WinTrustActionGenericVerifyV2;
                _ = WinVerifyTrust(IntPtr.Zero, ref closeAction, ref trustData);
            }

            Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPointer);
            Marshal.FreeHGlobal(fileInfoPointer);
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
    private static extern int WinVerifyTrust(
        IntPtr windowHandle,
        [In] ref Guid actionId,
        ref WinTrustData trustData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperProvDataFromStateData(IntPtr stateData);

    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern IntPtr WTHelperGetProvSignerFromChain(
        IntPtr providerData,
        uint signerIndex,
        [MarshalAs(UnmanagedType.Bool)] bool counterSigner,
        uint counterSignerIndex);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustFileInfo
    {
        public WinTrustFileInfo(string path)
        {
            StructureSize = (uint)Marshal.SizeOf<WinTrustFileInfo>();
            FilePath = path;
        }

        public uint StructureSize;
        [MarshalAs(UnmanagedType.LPWStr)] public string FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        public WinTrustData(IntPtr fileInfo, uint stateAction)
        {
            StructureSize = (uint)Marshal.SizeOf<WinTrustData>();
            PolicyCallbackData = IntPtr.Zero;
            SipClientData = IntPtr.Zero;
            UiChoice = 2; // WTD_UI_NONE
            RevocationChecks = 0; // WTD_REVOKE_NONE
            UnionChoice = 1; // WTD_CHOICE_FILE
            FileInfo = fileInfo;
            StateAction = stateAction;
            StateData = IntPtr.Zero;
            UrlReference = null;
            ProviderFlags = 0x00001000; // WTD_CACHE_ONLY_URL_RETRIEVAL
            UiContext = 0;
        }

        public uint StructureSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr FileInfo;
        public uint StateAction;
        public IntPtr StateData;
        [MarshalAs(UnmanagedType.LPWStr)] public string? UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptProviderSigner
    {
        public uint StructureSize;
        public System.Runtime.InteropServices.ComTypes.FILETIME VerifyAsOf;
        public uint CertificateCount;
        public IntPtr CertificateChain;
        public uint SignerType;
        public IntPtr Signer;
        public uint Error;
        public uint CounterSignerCount;
        public IntPtr CounterSigners;
        public IntPtr ChainContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CryptProviderCertificate
    {
        public uint StructureSize;
        public IntPtr CertificateContext;
        [MarshalAs(UnmanagedType.Bool)] public bool Commercial;
        [MarshalAs(UnmanagedType.Bool)] public bool TrustedRoot;
        [MarshalAs(UnmanagedType.Bool)] public bool SelfSigned;
        [MarshalAs(UnmanagedType.Bool)] public bool TestCertificate;
        public uint RevokedReason;
        public uint Confidence;
        public uint Error;
        public IntPtr TrustListContext;
        [MarshalAs(UnmanagedType.Bool)] public bool TrustListSignerCertificate;
        public IntPtr CtlContext;
        public uint CtlError;
        [MarshalAs(UnmanagedType.Bool)] public bool IsCyclic;
        public IntPtr ChainElement;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct CertificateContext
    {
        public uint EncodingType;
        public IntPtr EncodedCertificate;
        public uint EncodedCertificateSize;
        public IntPtr CertificateInfo;
        public IntPtr CertificateStore;
    }
}

internal static class FileSystemInfoHelpers
{
    public static bool HasReparseComponent(string root, string fullPath)
    {
        try
        {
            string fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar);
            string current = fullRoot;
            if (Directory.Exists(current) &&
                (File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                return true;
            }

            string relative = Path.GetRelativePath(fullRoot, fullPath);
            if (relative.StartsWith("..", StringComparison.Ordinal) || Path.IsPathRooted(relative))
            {
                return true;
            }

            foreach (string component in relative.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
            {
                if (string.IsNullOrWhiteSpace(component))
                {
                    continue;
                }

                current = Path.Combine(current, component);
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                {
                    return true;
                }
            }

            return false;
        }
        catch (IOException)
        {
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            return true;
        }
    }
}
