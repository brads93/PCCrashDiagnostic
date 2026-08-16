[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ExecutablePath,

    [ValidateSet('Unsigned', 'Signed')]
    [string]$ExpectedState = 'Unsigned',

    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$ExpectedSignerThumbprint,

    [string]$ExpectedSignerSubject,

    [string]$ExpectedSignerIssuer,

    [switch]$RequireRfc3161
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$fullPath = [IO.Path]::GetFullPath($ExecutablePath)
if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) { throw "Executable not found: $fullPath" }
if ([IO.Path]::GetFileName($fullPath) -cne 'PCCrashDiagnostic.exe') { throw 'Authenticode policy accepts only PCCrashDiagnostic.exe.' }

$version = [Diagnostics.FileVersionInfo]::GetVersionInfo($fullPath)
$metadata = [ordered]@{
    FileDescription = 'PC Crash Diagnostic'
    ProductName = 'PC Crash Diagnostic'
    CompanyName = 'PC Crash Diagnostic contributors'
    LegalCopyright = 'Copyright (c) 2026 PC Crash Diagnostic contributors'
    FileVersion = '3.2.0.0'
    InternalName = 'PCCrashDiagnostic.dll'
    OriginalFilename = 'PCCrashDiagnostic.dll'
}
foreach ($entry in $metadata.GetEnumerator()) {
    if ([string]$version.($entry.Key) -cne [string]$entry.Value) {
        throw "PE metadata mismatch for $($entry.Key): expected '$($entry.Value)', found '$($version.($entry.Key))'."
    }
}
if ([string]$version.ProductVersion -notmatch '^3\.2\.0-beta\.1(?:\+[^\s]+)?$') {
    throw "PE metadata mismatch for ProductVersion: '$($version.ProductVersion)'."
}

$signature = Get-AuthenticodeSignature -LiteralPath $fullPath
if ($ExpectedState -ceq 'Unsigned') {
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::NotSigned) {
        throw "Unsigned policy expected NotSigned, found $($signature.Status)."
    }
    return [pscustomobject]@{
        AuthenticodeStatus = 'NotSigned'
        SignerSubject = $null
        SignerIssuer = $null
        SignerThumbprint = $null
        TimestampSubject = $null
        TimestampIssuer = $null
        TimestampCertificatePresent = $false
        Rfc3161TimestampVerified = $false
        LegacyCounterSignaturePresent = $false
        MetadataVerified = $true
    }
}

if ([string]::IsNullOrWhiteSpace($ExpectedSignerThumbprint) -or
    [string]::IsNullOrWhiteSpace($ExpectedSignerSubject) -or
    [string]::IsNullOrWhiteSpace($ExpectedSignerIssuer)) {
    throw 'Signed policy requires exact signer thumbprint, subject, and issuer values.'
}
if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or $null -eq $signature.SignerCertificate) {
    throw "Authenticode trust validation failed: $($signature.Status) / $($signature.StatusMessage)"
}
$signer = $signature.SignerCertificate
if ($signer.Thumbprint.ToUpperInvariant() -cne $ExpectedSignerThumbprint.ToUpperInvariant()) {
    throw 'Signer thumbprint does not match the pinned release policy.'
}
if ([string]$signer.Subject -cne $ExpectedSignerSubject) { throw "Signer subject mismatch: '$($signer.Subject)'." }
if ([string]$signer.Issuer -cne $ExpectedSignerIssuer) { throw "Signer issuer mismatch: '$($signer.Issuer)'." }
if (@($signer.Extensions | Where-Object {
            $_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] -and
            @($_.EnhancedKeyUsages | Where-Object Value -ceq '1.3.6.1.5.5.7.3.3').Count -eq 1
        }).Count -ne 1) {
    throw 'Signer certificate does not contain the Code Signing enhanced-key-usage OID.'
}
if ($null -eq $signature.TimeStamperCertificate) { throw 'Signed executable has no timestamp certificate.' }
$timeStamper = $signature.TimeStamperCertificate
if (@($timeStamper.Extensions | Where-Object {
            $_ -is [Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] -and
            @($_.EnhancedKeyUsages | Where-Object Value -ceq '1.3.6.1.5.5.7.3.8').Count -eq 1
        }).Count -ne 1) {
    throw 'Timestamp certificate does not contain the Time Stamping enhanced-key-usage OID.'
}

Add-Type -AssemblyName System.Security.Cryptography.Pkcs
$bytes = [IO.File]::ReadAllBytes($fullPath)
if ($bytes.Length -lt 0x100 -or [BitConverter]::ToUInt16($bytes, 0) -ne 0x5A4D) { throw 'Executable is not a valid PE image.' }
$peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
if ($peOffset -lt 0 -or $peOffset + 256 -gt $bytes.Length -or
    [BitConverter]::ToUInt32($bytes, $peOffset) -ne 0x00004550) { throw 'PE header is invalid or truncated.' }
$optionalHeaderOffset = $peOffset + 24
$optionalMagic = [BitConverter]::ToUInt16($bytes, $optionalHeaderOffset)
$dataDirectoryOffset = switch ($optionalMagic) {
    0x10B { $optionalHeaderOffset + 96 }
    0x20B { $optionalHeaderOffset + 112 }
    default { throw "Unsupported PE optional-header magic: 0x$($optionalMagic.ToString('X4'))" }
}
$securityDirectoryOffset = $dataDirectoryOffset + (4 * 8)
$certificateOffset = [BitConverter]::ToUInt32($bytes, $securityDirectoryOffset)
$certificateSize = [BitConverter]::ToUInt32($bytes, $securityDirectoryOffset + 4)
if ($certificateOffset -eq 0 -or $certificateSize -lt 8 -or
    [uint64]$certificateOffset + [uint64]$certificateSize -gt [uint64]$bytes.Length) {
    throw 'PE security directory is missing or invalid.'
}

$rfc3161Oid = '1.3.6.1.4.1.311.3.3.1'
$legacyCounterSignatureOid = '1.2.840.113549.1.9.6'
$rfc3161Present = $false
$legacyPresent = $false
$cursor = [int]$certificateOffset
$end = [int]($certificateOffset + $certificateSize)
while ($cursor + 8 -le $end) {
    $length = [BitConverter]::ToUInt32($bytes, $cursor)
    $certificateType = [BitConverter]::ToUInt16($bytes, $cursor + 6)
    if ($length -lt 8 -or [uint64]$cursor + [uint64]$length -gt [uint64]$end) { throw 'WIN_CERTIFICATE entry is invalid or truncated.' }
    if ($certificateType -eq 2) {
        $content = [byte[]]::new($length - 8)
        [Array]::Copy($bytes, $cursor + 8, $content, 0, $content.Length)
        $cms = [Security.Cryptography.Pkcs.SignedCms]::new()
        $cms.Decode($content)
        foreach ($signerInfo in $cms.SignerInfos) {
            foreach ($attribute in $signerInfo.UnsignedAttributes) {
                if ([string]$attribute.Oid.Value -ceq $rfc3161Oid) { $rfc3161Present = $true }
                if ([string]$attribute.Oid.Value -ceq $legacyCounterSignatureOid) { $legacyPresent = $true }
            }
        }
    }
    $cursor += [int](($length + 7) -band 0xFFFFFFF8)
}
if ($RequireRfc3161 -and (-not $rfc3161Present -or $legacyPresent)) {
    throw "RFC 3161 policy failed (RFC3161=$rfc3161Present, legacyCounterSignature=$legacyPresent)."
}

[pscustomobject]@{
    AuthenticodeStatus = 'Valid'
    SignerSubject = [string]$signer.Subject
    SignerIssuer = [string]$signer.Issuer
    SignerThumbprint = $signer.Thumbprint.ToUpperInvariant()
    TimestampSubject = [string]$timeStamper.Subject
    TimestampIssuer = [string]$timeStamper.Issuer
    TimestampCertificatePresent = $true
    Rfc3161TimestampVerified = $rfc3161Present -and -not $legacyPresent
    LegacyCounterSignaturePresent = $legacyPresent
    MetadataVerified = $true
}
