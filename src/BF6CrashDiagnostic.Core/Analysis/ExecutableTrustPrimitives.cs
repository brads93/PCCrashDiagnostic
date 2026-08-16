using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace BF6CrashDiagnostic.Core.Analysis;

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
                trustData.StateAction = 2;
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
            UiChoice = 2;
            RevocationChecks = 0;
            UnionChoice = 1;
            FileInfo = fileInfo;
            StateAction = stateAction;
            StateData = IntPtr.Zero;
            UrlReference = null;
            ProviderFlags = 0x00001000;
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
