[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ArtifactsRoot,
    [ValidateSet('3.2.0-beta.1')][string]$ExpectedVersion = '3.2.0-beta.1',
    [ValidateSet('ShareReadOnly')][string]$ExpectedFeatureProfile = 'ShareReadOnly',
    [switch]$RunSmokeTest,
    [switch]$RequireShareApproved
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$root = [IO.Path]::GetFullPath($ArtifactsRoot)
if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw "Candidate directory not found: $root" }

function Assert-NoReparsePoint {
    param([Parameter(Mandatory)][string]$LiteralPath)
    $current = [IO.Path]::GetFullPath($LiteralPath)
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Candidate input traverses a reparse point: $current"
            }
        }
        $parent = Split-Path -Parent $current
        if ($parent -ceq $current) { break }
        $current = $parent
    }
}
Assert-NoReparsePoint -LiteralPath $root

function Assert-Equal {
    param($Expected, $Actual, [Parameter(Mandatory)][string]$Description)
    if ($Expected -is [string] -or $Actual -is [string]) {
        if ([string]$Expected -cne [string]$Actual) { throw "$Description mismatch. Expected '$Expected'; found '$Actual'." }
    } elseif ($Expected -ne $Actual) { throw "$Description mismatch. Expected '$Expected'; found '$Actual'." }
}
function Get-Sha256 {
    param([Parameter(Mandatory)][string]$LiteralPath)
    return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Assert-SafeEntryName {
    param([Parameter(Mandatory)][string]$Name)
    $normalized = $Name.Replace('\', '/')
    $segments = @($normalized.Split('/'))
    if ([string]::IsNullOrWhiteSpace($normalized) -or $normalized.StartsWith('/') -or $normalized.Contains(':') -or
        $segments.Count -eq 0 -or @($segments | Where-Object { [string]::IsNullOrWhiteSpace($_) -or $_ -in @('.', '..') }).Count -ne 0 -or
        $normalized.IndexOfAny([char[]]@(0, 10, 13)) -ge 0) { throw "Unsafe ZIP entry name: $Name" }
    foreach ($segment in $segments) {
        $trimmed = $segment.TrimEnd(' ', '.')
        if ($trimmed -cne $segment -or $trimmed -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$') {
            throw "ZIP entry is not safe on Windows: $Name"
        }
    }
}
function Get-ZipEntries {
    param([Parameter(Mandatory)][string]$LiteralPath)
    $archive = [IO.Compression.ZipFile]::OpenRead($LiteralPath)
    try {
        $names = @()
        foreach ($entry in $archive.Entries) {
            Assert-SafeEntryName $entry.FullName
            if ([string]::IsNullOrWhiteSpace($entry.Name) -or (($entry.ExternalAttributes -shr 16) -band 0xF000) -eq 0xA000) {
                throw "ZIP contains a directory or symbolic-link entry: $($entry.FullName)"
            }
            $names += $entry.FullName
        }
        if (@($names | Group-Object { $_.ToUpperInvariant() } | Where-Object Count -gt 1).Count -ne 0) { throw "ZIP contains duplicate or case-colliding entries: $LiteralPath" }
        return $names
    } finally { $archive.Dispose() }
}
function Assert-PeAmd64 {
    param([Parameter(Mandatory)][string]$LiteralPath)
    $stream = [IO.File]::OpenRead($LiteralPath)
    try {
        $reader = [IO.BinaryReader]::new($stream, [Text.Encoding]::ASCII, $true)
        try {
            if ($reader.ReadUInt16() -ne 0x5A4D) { throw 'Executable does not have an MZ header.' }
            $stream.Position = 0x3C; $peOffset = $reader.ReadInt32()
            if ($peOffset -lt 64 -or $peOffset -gt $stream.Length - 6) { throw 'Executable has an invalid PE offset.' }
            $stream.Position = $peOffset
            if ($reader.ReadUInt32() -ne 0x00004550) { throw 'Executable does not have a PE header.' }
            if ($reader.ReadUInt16() -ne 0x8664) { throw 'Executable is not AMD64.' }
        } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
}
function Assert-ShareCapabilities {
    param([Parameter(Mandatory)]$Capabilities, [Parameter(Mandatory)][string]$Description)
    $expected = [ordered]@{
        Profile = 'ShareReadOnly'; StandardEvidence = $true; TargetMonitoring = $true
        CrashReadinessReadOnly = $true; AccessibleDumpMetadata = $true; LocalHistory = $true
        SafeSummaryExport = $true; TechnicalReportExport = $true; RecycleBinDeletion = $true
        DumpChk = $true; WinDbg = $true; MicrosoftSymbolsAfterConsent = $true
        ElevatedHelper = $false; SettingsApply = $false; SettingsRestore = $false; WerLocalDumps = $false
        ProtectedEvidence = $false; ProtectedDumpStaging = $false; DumpPackaging = $false
    }
    $actualNames = @($Capabilities.PSObject.Properties.Name | Sort-Object)
    if (@(Compare-Object @($expected.Keys | Sort-Object) $actualNames).Count -ne 0) { throw "$Description capability fields are incomplete or unexpected." }
    foreach ($entry in $expected.GetEnumerator()) { Assert-Equal $entry.Value $Capabilities.($entry.Key) "$Description capability $($entry.Key)" }
}

$manifestPath = Join-Path $root 'ReleaseManifest.json'
$checksumsPath = Join-Path $root 'SHA256SUMS.txt'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or -not (Test-Path -LiteralPath $checksumsPath -PathType Leaf)) {
    throw 'ReleaseManifest.json and SHA256SUMS.txt are required.'
}
Assert-NoReparsePoint -LiteralPath $manifestPath
Assert-NoReparsePoint -LiteralPath $checksumsPath
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
Assert-Equal 3 $manifest.ManifestSchemaVersion 'Manifest schema version'
Assert-Equal 'PC Crash Diagnostic' $manifest.Product 'Product'
Assert-Equal $ExpectedVersion $manifest.Version 'Version'
Assert-Equal $ExpectedFeatureProfile $manifest.FeatureProfile 'Feature profile'
Assert-Equal $false ([bool]$manifest.PrivilegedOperationsEnabled) 'Privileged-operations gate'
Assert-Equal $false ([bool]$manifest.ElevatedHelperIncluded) 'Elevated-helper gate'
Assert-Equal $false ([bool]$manifest.WerLocalDumpCaptureEnabled) 'WER LocalDumps gate'
Assert-ShareCapabilities $manifest.Capabilities 'Release manifest'
Assert-Equal 'None' $manifest.Elevation 'Elevation boundary'
Assert-Equal 'None' $manifest.SettingsMutation 'Settings-mutation boundary'
Assert-Equal 'None' $manifest.ProtectedEvidence 'Protected-evidence boundary'
Assert-Equal 'ConsentOnlyMicrosoftSymbols' $manifest.Network 'Network boundary'
Assert-Equal 'Absent' $manifest.Helper 'Helper boundary'
Assert-Equal '10.0.400' $manifest.DotNetSdkVersion 'SDK version'
Assert-Equal '10.0.11' $manifest.RuntimeFrameworkVersion 'Runtime version'
Assert-Equal 'win-x64' $manifest.RuntimeIdentifier 'Runtime identifier'
Assert-Equal 'PCCrashDiagnostic.exe' $manifest.ExecutableName 'Executable name'
Assert-Equal 'https://github.com/brads93/PCCrashDiagnostic' $manifest.SourceRepository 'Source repository'
if ([string]$manifest.SourceCommit -notmatch '^[0-9a-f]{40}$' -or [string]$manifest.SourceTree -notmatch '^[0-9a-f]{40}$') {
    throw 'Manifest source commit/tree identity is missing or malformed.'
}
if ([string]$manifest.SourceTreeState -notin @('clean', 'dirty')) { throw 'Manifest source-tree state is invalid.' }
if ([string]$manifest.CandidateState -notin @('UnsignedCandidate', 'UnsignedDirtyLocalCandidate', 'SignedAwaitingExactPackageVmEvidence', 'ApprovedForSharing')) {
    throw 'Manifest candidate state is invalid.'
}
$isSignedCandidate = [string]$manifest.CandidateState -in @('SignedAwaitingExactPackageVmEvidence', 'ApprovedForSharing')
if (([string]$manifest.SourceTreeState -ceq 'dirty' -and [string]$manifest.CandidateState -cne 'UnsignedDirtyLocalCandidate') -or
    ([string]$manifest.SourceTreeState -ceq 'clean' -and [string]$manifest.CandidateState -ceq 'UnsignedDirtyLocalCandidate')) {
    throw 'Candidate state does not match the recorded source-tree state.'
}
if ($isSignedCandidate) {
    if ([string]$manifest.AuthenticodeStatus -cne 'Valid' -or
        [string]$manifest.UnsignedSigningInputSha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]::IsNullOrWhiteSpace([string]$manifest.SigningInputArtifactId) -or
        [string]::IsNullOrWhiteSpace([string]$manifest.SignerSubject) -or
        [string]::IsNullOrWhiteSpace([string]$manifest.SignerIssuer) -or
        -not [bool]$manifest.Rfc3161TimestampVerified -or -not [bool]$manifest.ReproducibleBuildVerified -or
        [string]$manifest.ReproducibilityPeerSha256 -cne [string]$manifest.UnsignedSigningInputSha256 -or
        -not [bool]$manifest.SourceOriginVerified -or -not [bool]$manifest.SourceTagVerified -or
        [string]$manifest.SourceTag -cne "v$ExpectedVersion") {
        throw 'A signed candidate must record exact source, reproducibility, signer-policy, signing-input, and RFC 3161 evidence.'
    }
} elseif ([string]$manifest.AuthenticodeStatus -cne 'NotSigned' -or
    -not [string]::IsNullOrWhiteSpace([string]$manifest.UnsignedSigningInputSha256) -or
    -not [string]::IsNullOrWhiteSpace([string]$manifest.SigningInputArtifactId) -or
    [bool]$manifest.Rfc3161TimestampVerified -or [bool]$manifest.ReproducibleBuildVerified) {
    throw 'An unsigned candidate must not claim signing-input identity or a signature.'
}
if ([bool]$manifest.ShareApproved) {
    if ([string]$manifest.AuthenticodeStatus -cne 'Valid' -or -not [bool]$manifest.TimestampCertificatePresent -or
        -not [bool]$manifest.Rfc3161TimestampVerified -or -not [bool]$manifest.ExactPackageVmEvidenceVerified) {
        throw 'ShareApproved requires valid Authenticode, RFC 3161, and exact-package VM evidence.'
    }
    if ([string]$manifest.SourceTreeState -cne 'clean' -or @($manifest.ShareApprovalBlockers).Count -ne 0) {
        throw 'ShareApproved requires a clean source tree and no remaining approval blockers.'
    }
    if ([string]$manifest.CandidateState -cne 'ApprovedForSharing') { throw 'ShareApproved requires CandidateState=ApprovedForSharing.' }
} elseif ($RequireShareApproved) {
    throw 'This artifact remains a candidate and is not approved for sharing.'
} elseif (@($manifest.ShareApprovalBlockers).Count -eq 0) {
    throw 'A non-approved candidate must state its remaining share blockers.'
} elseif ([string]$manifest.CandidateState -ceq 'ApprovedForSharing') {
    throw 'ApprovedForSharing cannot be claimed while ShareApproved is false.'
}

$manifestEvidence = @($manifest.Evidence)
if ($manifestEvidence.Count -ne 3) { throw 'Manifest evidence must list exactly three packaged evidence files.' }
foreach ($evidenceName in @('TestEvidence.json', 'SBOM.spdx.json', 'Provenance.intoto.json')) {
    $match = @($manifestEvidence | Where-Object Name -ceq $evidenceName)
    if ($match.Count -ne 1 -or [string]$match[0].Sha256 -notmatch '^[0-9a-f]{64}$') {
        throw "Manifest evidence entry is missing or malformed: $evidenceName"
    }
}
$provenanceEvidence = @($manifestEvidence | Where-Object Name -ceq 'Provenance.intoto.json')[0]
if ([bool]$provenanceEvidence.Attested) { throw 'The packaged provenance is scaffolding and must not claim to be attested.' }

$assets = @($manifest.Assets)
if ($assets.Count -ne 2) { throw 'Manifest must list exactly one runtime candidate and one source archive.' }
$runtimeAsset = @($assets | Where-Object Role -ceq 'runtime-candidate')
$sourceAsset = @($assets | Where-Object Role -ceq 'source')
if ($runtimeAsset.Count -ne 1 -or $sourceAsset.Count -ne 1) { throw 'Manifest asset roles are invalid.' }
$runtimeAsset = $runtimeAsset[0]; $sourceAsset = $sourceAsset[0]
Assert-Equal "PCCrashDiagnostic-$ExpectedVersion-share-read-only-win-x64.zip" $runtimeAsset.Name 'Runtime asset name'
Assert-Equal "PCCrashDiagnostic-$ExpectedVersion-source.zip" $sourceAsset.Name 'Source asset name'
if ([bool]$manifest.ShareApproved) {
    if ([string]$manifest.ExactPackageVmEvidence.RuntimeZipSha256 -cne [string]$runtimeAsset.Sha256 -or
        [string]$manifest.ExactPackageVmEvidence.EvidenceSha256 -notmatch '^[0-9a-f]{64}$' -or
        [string]$manifest.ExactPackageVmEvidence.EvidenceArtifactId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') {
        throw 'Approved manifest exact-package VM evidence is missing or bound to different runtime bytes.'
    }
}

$expectedDirectoryFiles = @([string]$runtimeAsset.Name, [string]$sourceAsset.Name, 'ReleaseManifest.json', 'SHA256SUMS.txt')
$actualDirectoryFiles = @(Get-ChildItem -LiteralPath $root -File | ForEach-Object Name | Sort-Object)
if (@(Compare-Object ($expectedDirectoryFiles | Sort-Object) $actualDirectoryFiles).Count -ne 0) {
    throw 'Candidate directory must contain exactly the two ZIPs, ReleaseManifest.json, and SHA256SUMS.txt.'
}

$checksumMap = @{}
foreach ($line in @(Get-Content -LiteralPath $checksumsPath)) {
    if ($line -notmatch '^([0-9a-f]{64}) \*(.+)$') { throw "Malformed checksum line: $line" }
    if ($checksumMap.ContainsKey($Matches[2])) { throw "Duplicate checksum entry: $($Matches[2])" }
    $checksumMap[$Matches[2]] = $Matches[1]
}
if ($checksumMap.Count -ne 3) { throw 'SHA256SUMS.txt must contain exactly three entries.' }
foreach ($name in @([string]$runtimeAsset.Name, [string]$sourceAsset.Name, 'ReleaseManifest.json')) {
    $path = Join-Path $root $name
    Assert-NoReparsePoint -LiteralPath $path
    if (-not $checksumMap.ContainsKey($name) -or (Get-Sha256 $path) -cne $checksumMap[$name]) { throw "Checksum mismatch: $name" }
}
foreach ($asset in $assets) {
    $path = Join-Path $root $asset.Name
    Assert-Equal ([long]$asset.Size) (Get-Item -LiteralPath $path).Length "$($asset.Name) size"
    Assert-Equal ([string]$asset.Sha256) (Get-Sha256 $path) "$($asset.Name) hash"
}

$runtimePath = Join-Path $root $runtimeAsset.Name
$sourcePath = Join-Path $root $sourceAsset.Name
$runtimeEntries = @(Get-ZipEntries $runtimePath)
if ('PCCrashDiagnostic.exe' -notin $runtimeEntries) { throw 'Runtime ZIP is missing PCCrashDiagnostic.exe.' }
if ('PCCrashDiagnostic.ElevatedHelper.exe' -in $runtimeEntries -or @($runtimeEntries | Where-Object { $_ -like '*.exe' }).Count -ne 1) {
    throw 'ShareReadOnly runtime must contain exactly one executable and no elevated helper.'
}
if (@($runtimeEntries | Where-Object {
            [IO.Path]::GetExtension($_).ToLowerInvariant() -in @('.dmp', '.mdmp', '.hdmp', '.evtx', '.etl', '.trx',
                '.log', '.pfx', '.p12', '.snk', '.key')
        }).Count -ne 0) {
    throw 'ShareReadOnly runtime contains private diagnostic, raw test, log, or key material.'
}
foreach ($required in @('00-START-HERE.txt', 'BUILD-MANIFEST.json', 'TestEvidence.json', 'SBOM.spdx.json',
        'Provenance.intoto.json', 'CODE_SIGNING_POLICY.md', 'docs/BUILD_PROFILES.md', 'docs/SUPPORT_SUMMARY.md',
        'docs/RELEASE_PROCESS.md', 'docs/EXACT_PACKAGE_VM_CHECKLIST.md')) {
    if ($required -notin $runtimeEntries) { throw "Runtime ZIP is missing $required." }
}

$manifestPaths = @($manifest.RuntimePackageFiles | ForEach-Object Path)
if (@(Compare-Object ($runtimeEntries | Sort-Object) ($manifestPaths | Sort-Object)).Count -ne 0) {
    throw 'Runtime ZIP entries do not match RuntimePackageFiles.'
}

$sourceEntries = @(Get-ZipEntries $sourcePath)
if ($sourceEntries.Count -eq 0 -or @($sourceEntries | Where-Object { -not $_.StartsWith('PCCrashDiagnostic-source/', [StringComparison]::Ordinal) }).Count -ne 0) {
    throw 'Source ZIP entries must be under PCCrashDiagnostic-source/.'
}
foreach ($requiredSuffix in @('/PCCrashDiagnostic.sln', '/global.json', '/Directory.Build.props',
        '/PCCrashDiagnostic.Share.slnf', '/tools/Build-Release.ps1', '/tools/Verify-Release.ps1',
        '/tools/Finalize-Release.ps1', '/.config/dotnet-tools.json', '/.github/workflows/ci.yml')) {
    if (@($sourceEntries | Where-Object { $_.EndsWith($requiredSuffix, [StringComparison]::Ordinal) }).Count -ne 1) {
        throw "Source ZIP is missing exactly one entry ending in $requiredSuffix."
    }
}
if (@($sourceEntries | Where-Object { $_ -match '(^|/)(?:bin|obj|artifacts[^/]*|\.git)(/|$)' -or
            [IO.Path]::GetExtension($_).ToLowerInvariant() -in @('.dmp', '.mdmp', '.hdmp', '.evtx', '.etl', '.pfx', '.p12',
                '.snk', '.key', '.cer', '.zip', '.trx', '.log', '.exe', '.dll', '.pdb', '.bin', '.nupkg', '.snupkg', '.user', '.suo') -or
            [IO.Path]::GetFileName($_) -match '^(?:\.env(?:\..+)?|secrets\.json)$' }).Count -ne 0) {
    throw 'Source ZIP contains a forbidden generated, private, or nested-archive entry.'
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('PCCrashDiagnostic-verify-' + [Guid]::NewGuid().ToString('N'))
try {
    [IO.Compression.ZipFile]::ExtractToDirectory($runtimePath, $temporaryRoot)
    $exePath = Join-Path $temporaryRoot 'PCCrashDiagnostic.exe'
    Assert-PeAmd64 $exePath
    Assert-Equal ([string]$manifest.ExecutableSha256) (Get-Sha256 $exePath) 'Executable hash'
    $authPolicyScript = Join-Path $PSScriptRoot 'Test-AuthenticodePolicy.ps1'
    if ($isSignedCandidate) {
        $authPolicy = & $authPolicyScript -ExecutablePath $exePath -ExpectedState Signed `
            -ExpectedSignerThumbprint ([string]$manifest.SignerThumbprint) -ExpectedSignerSubject ([string]$manifest.SignerSubject) `
            -ExpectedSignerIssuer ([string]$manifest.SignerIssuer) -RequireRfc3161
    } else {
        $authPolicy = & $authPolicyScript -ExecutablePath $exePath -ExpectedState Unsigned
    }
    Assert-Equal ([string]$manifest.AuthenticodeStatus) ([string]$authPolicy.AuthenticodeStatus) 'Executable signature status'
    Assert-Equal $manifest.SignerThumbprint $authPolicy.SignerThumbprint 'Signer thumbprint'
    Assert-Equal $manifest.SignerSubject $authPolicy.SignerSubject 'Signer subject'
    Assert-Equal $manifest.SignerIssuer $authPolicy.SignerIssuer 'Signer issuer'
    Assert-Equal ([bool]$manifest.TimestampCertificatePresent) ([bool]$authPolicy.TimestampCertificatePresent) 'Timestamp-certificate presence'
    Assert-Equal ([bool]$manifest.Rfc3161TimestampVerified) ([bool]$authPolicy.Rfc3161TimestampVerified) 'RFC 3161 timestamp policy'

    $buildManifest = Get-Content -LiteralPath (Join-Path $temporaryRoot 'BUILD-MANIFEST.json') -Raw | ConvertFrom-Json
    Assert-Equal 3 $buildManifest.ManifestSchemaVersion 'Build-manifest schema'
    Assert-Equal $ExpectedVersion $buildManifest.Version 'Build-manifest version'
    Assert-Equal $ExpectedFeatureProfile $buildManifest.FeatureProfile 'Build-manifest profile'
    Assert-Equal $false ([bool]$buildManifest.ShareApproved) 'Build-manifest share gate'
    Assert-Equal $false ([bool]$buildManifest.PrivilegedOperationsEnabled) 'Build-manifest privileged gate'
    Assert-Equal $false ([bool]$buildManifest.ElevatedHelperIncluded) 'Build-manifest helper gate'
    Assert-ShareCapabilities $buildManifest.Capabilities 'Build manifest'
    Assert-Equal 'None' $buildManifest.Elevation 'Build-manifest elevation boundary'
    Assert-Equal 'None' $buildManifest.SettingsMutation 'Build-manifest settings boundary'
    Assert-Equal 'None' $buildManifest.ProtectedEvidence 'Build-manifest protected-evidence boundary'
    Assert-Equal 'ConsentOnlyMicrosoftSymbols' $buildManifest.Network 'Build-manifest network boundary'
    Assert-Equal 'Absent' $buildManifest.Helper 'Build-manifest helper state'
    Assert-Equal '10.0.400' $buildManifest.DotNetSdkVersion 'Build-manifest SDK'
    Assert-Equal '10.0.11' $buildManifest.RuntimeFrameworkVersion 'Build-manifest runtime'
    Assert-Equal $manifest.UnsignedSigningInputSha256 $buildManifest.UnsignedSigningInputSha256 'Build-manifest unsigned signing-input hash'
    Assert-Equal $manifest.SigningInputArtifactId $buildManifest.SigningInputArtifactId 'Build-manifest signing artifact ID'
    Assert-Equal $manifest.SourceRepository $buildManifest.SourceRepository 'Build-manifest source repository'
    Assert-Equal $manifest.SourceTag $buildManifest.SourceTag 'Build-manifest source tag'
    Assert-Equal ([bool]$manifest.SourceOriginVerified) ([bool]$buildManifest.SourceOriginVerified) 'Build-manifest source origin gate'
    Assert-Equal ([bool]$manifest.SourceTagVerified) ([bool]$buildManifest.SourceTagVerified) 'Build-manifest source tag gate'
    Assert-Equal ([bool]$manifest.ReproducibleBuildVerified) ([bool]$buildManifest.ReproducibleBuildVerified) 'Build-manifest reproducibility gate'
    Assert-Equal $manifest.ReproducibilityPeerSha256 $buildManifest.ReproducibilityPeerSha256 'Build-manifest reproducibility peer'

    $testEvidencePath = Join-Path $temporaryRoot 'TestEvidence.json'
    $testEvidence = Get-Content -LiteralPath $testEvidencePath -Raw | ConvertFrom-Json
    $testEvidenceProperties = @($testEvidence.PSObject.Properties.Name | Sort-Object)
    $expectedTestEvidenceProperties = @('FeatureProfile', 'GeneratedUtc', 'PackagedSmokePassed', 'Privacy', 'Product', 'RawTrx',
        'ReleaseAudits', 'SafetyBoundaryPassed', 'SchemaVersion', 'SourceCommit', 'SourceTreeState', 'TestResults', 'Version') | Sort-Object
    if (@(Compare-Object $expectedTestEvidenceProperties $testEvidenceProperties).Count -ne 0) {
        throw 'TestEvidence.json contains an unexpected or missing top-level property.'
    }
    $expectedCounterProperties = @('Aborted', 'Errors', 'Executed', 'Failed', 'Inconclusive', 'Passed', 'Skipped', 'Timeouts', 'Total') | Sort-Object
    $actualCounterProperties = @($testEvidence.TestResults.PSObject.Properties.Name | Sort-Object)
    $expectedRawTrxProperties = @('FileName', 'PubliclyPackaged', 'Sha256') | Sort-Object
    $actualRawTrxProperties = @($testEvidence.RawTrx.PSObject.Properties.Name | Sort-Object)
    if (@(Compare-Object $expectedCounterProperties $actualCounterProperties).Count -ne 0 -or
        @(Compare-Object $expectedRawTrxProperties $actualRawTrxProperties).Count -ne 0) {
        throw 'TestEvidence.json contains an unexpected result-counter or raw-TRX property.'
    }
    Assert-Equal 1 $testEvidence.SchemaVersion 'Test-evidence schema'
    Assert-Equal $ExpectedFeatureProfile $testEvidence.FeatureProfile 'Test-evidence profile'
    if ([int]$testEvidence.TestResults.Passed -le 0 -or [int]$testEvidence.TestResults.Failed -ne 0 -or
        [int]$testEvidence.TestResults.Errors -ne 0 -or -not [bool]$testEvidence.SafetyBoundaryPassed -or
        -not [bool]$testEvidence.PackagedSmokePassed -or
        -not [bool]$testEvidence.ReleaseAudits.DependencyVulnerabilityAuditPassed -or
        -not [bool]$testEvidence.ReleaseAudits.PublicIlAndResourceAuditPassed -or
        [int]$testEvidence.ReleaseAudits.AssemblyCount -ne 4 -or
        [int]$testEvidence.ReleaseAudits.PublishedExecutableCount -ne 1 -or
        [int]$testEvidence.ReleaseAudits.ForbiddenFindingCount -ne 0) {
        throw 'TestEvidence.json does not establish passing tests, smoke, dependency audit, and public IL/resource audit.'
    }
    if ([bool]$testEvidence.RawTrx.PubliclyPackaged -or [IO.Path]::GetFileName([string]$testEvidence.RawTrx.FileName) -cne [string]$testEvidence.RawTrx.FileName -or
        [string]$testEvidence.RawTrx.FileName -notmatch '\.trx$' -or [string]$testEvidence.RawTrx.Sha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'TestEvidence.json raw-TRX binding is malformed or claims the raw file is packaged.'
    }
    Assert-Equal ([string]$manifest.SourceCommit) ([string]$testEvidence.SourceCommit) 'Test-evidence source commit'
    Assert-Equal ([string]$manifest.SourceTreeState) ([string]$testEvidence.SourceTreeState) 'Test-evidence source-tree state'
    if ((Get-Content -LiteralPath $testEvidencePath -Raw) -match '(?i)[A-Z]:\\|\\Users\\|/home/') {
        throw 'TestEvidence.json contains an absolute local path.'
    }
    Assert-Equal ([string]$buildManifest.TestEvidenceSha256) (Get-Sha256 $testEvidencePath) 'Test-evidence hash'

    $sbomPath = Join-Path $temporaryRoot 'SBOM.spdx.json'
    $sbom = Get-Content -LiteralPath $sbomPath -Raw | ConvertFrom-Json
    Assert-Equal 'SPDX-2.2' $sbom.spdxVersion 'SBOM version'
    Assert-Equal 'SPDXRef-DOCUMENT' $sbom.SPDXID 'SBOM document identity'
    if (@($sbom.packages | Where-Object name -ceq 'PC Crash Diagnostic').Count -ne 1) { throw 'SBOM does not describe PC Crash Diagnostic.' }
    if (@($sbom.creationInfo.creators | Where-Object { [string]$_ -ceq 'Tool: Microsoft.SBOMTool-4.1.5' }).Count -ne 1) {
        throw 'SBOM was not generated by the pinned Microsoft SBOM Tool 4.1.5.'
    }
    foreach ($requiredPackage in @('System.Diagnostics.PerformanceCounter', 'System.Management')) {
        if (@($sbom.packages | Where-Object { [string]$_.name -ceq $requiredPackage -and [string]$_.versionInfo -ceq '10.0.11' }).Count -ne 1) {
            throw "SBOM is missing locked ShareReadOnly dependency: $requiredPackage 10.0.11"
        }
    }
    if ((Get-Content -LiteralPath $sbomPath -Raw) -match '(?i)[A-Z]:\\|\\Users\\|/home/') { throw 'SBOM contains an absolute local path.' }
    Assert-Equal ([string]$buildManifest.SbomSha256) (Get-Sha256 $sbomPath) 'SBOM hash'

    $provenancePath = Join-Path $temporaryRoot 'Provenance.intoto.json'
    $provenance = Get-Content -LiteralPath $provenancePath -Raw | ConvertFrom-Json
    Assert-Equal 'https://in-toto.io/Statement/v1' $provenance._type 'Provenance statement type'
    Assert-Equal 'https://slsa.dev/provenance/v1' $provenance.predicateType 'Provenance predicate type'
    Assert-Equal $ExpectedVersion $provenance.predicate.buildDefinition.externalParameters.version 'Provenance version'
    Assert-Equal $ExpectedFeatureProfile $provenance.predicate.buildDefinition.externalParameters.featureProfile 'Provenance profile'
    Assert-Equal ([string]$manifest.SourceTree) $provenance.predicate.buildDefinition.internalParameters.sourceTree 'Provenance source tree'
    Assert-Equal ([string]$manifest.SourceTreeState) $provenance.predicate.buildDefinition.internalParameters.sourceTreeState 'Provenance source-tree state'
    Assert-Equal $manifest.UnsignedSigningInputSha256 $provenance.predicate.buildDefinition.internalParameters.unsignedSigningInputSha256 'Provenance unsigned signing-input hash'
    Assert-Equal $manifest.SigningInputArtifactId $provenance.predicate.buildDefinition.internalParameters.signingInputArtifactId 'Provenance signing artifact ID'
    if ((Get-Content -LiteralPath $provenancePath -Raw) -match '(?i)[A-Z]:\\|\\Users\\|/home/') {
        throw 'Provenance contains an absolute local path.'
    }
    Assert-Equal 'https://github.com/brads93/PCCrashDiagnostic' $provenance.predicate.buildDefinition.externalParameters.sourceRepository 'Provenance source repository'
    Assert-Equal $manifest.SourceTag $provenance.predicate.buildDefinition.externalParameters.sourceTag 'Provenance source tag'
    Assert-Equal ([bool]$manifest.SourceOriginVerified) ([bool]$provenance.predicate.buildDefinition.internalParameters.sourceOriginVerified) 'Provenance source-origin gate'
    Assert-Equal ([bool]$manifest.SourceTagVerified) ([bool]$provenance.predicate.buildDefinition.internalParameters.sourceTagVerified) 'Provenance source-tag gate'
    Assert-Equal ([bool]$manifest.ReproducibleBuildVerified) ([bool]$provenance.predicate.buildDefinition.internalParameters.reproducibleBuildVerified) 'Provenance reproducibility gate'
    $gitMaterial = @($provenance.predicate.buildDefinition.resolvedDependencies | Where-Object uri -ceq 'git+https://github.com/brads93/PCCrashDiagnostic')
    if ($gitMaterial.Count -ne 1 -or [string]$gitMaterial[0].digest.sha1 -cne [string]$manifest.SourceCommit) {
        throw 'Provenance source-commit material does not match the release manifest.'
    }
    $expectedSubjects = [ordered]@{
        'PCCrashDiagnostic.exe' = Get-Sha256 $exePath
        'TestEvidence.json' = Get-Sha256 $testEvidencePath
        'SBOM.spdx.json' = Get-Sha256 $sbomPath
    }
    foreach ($subjectName in $expectedSubjects.Keys) {
        $subject = @($provenance.subject | Where-Object name -ceq $subjectName)
        if ($subject.Count -ne 1 -or [string]$subject[0].digest.sha256 -cne $expectedSubjects[$subjectName]) {
            throw "Provenance subject does not match packaged bytes: $subjectName"
        }
    }
    Assert-Equal ([string]$buildManifest.ProvenanceSha256) (Get-Sha256 $provenancePath) 'Provenance hash'

    foreach ($evidenceEntry in $manifestEvidence) {
        Assert-Equal ([string]$evidenceEntry.Sha256) (Get-Sha256 (Join-Path $temporaryRoot ([string]$evidenceEntry.Name))) "Manifest evidence hash for $($evidenceEntry.Name)"
    }

    foreach ($item in @($manifest.RuntimePackageFiles)) {
        $path = Join-Path $temporaryRoot ([string]$item.Path).Replace('/', [IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Runtime file is missing: $($item.Path)" }
        Assert-Equal ([long]$item.Size) (Get-Item -LiteralPath $path).Length "$($item.Path) size"
        Assert-Equal ([string]$item.Sha256) (Get-Sha256 $path) "$($item.Path) hash"
    }

    if ($RunSmokeTest) {
        $smokeRoot = Join-Path $temporaryRoot 'smoke-data'; New-Item -ItemType Directory -Path $smokeRoot -Force | Out-Null
        $info = [Diagnostics.ProcessStartInfo]::new(); $info.FileName = $exePath
        $info.Arguments = "--smoke-test --data-root `"$smokeRoot`""; $info.UseShellExecute = $false; $info.CreateNoWindow = $true
        $process = [Diagnostics.Process]::Start($info)
        if ($null -eq $process) { throw 'Could not launch packaged smoke test.' }
        try {
            if (-not $process.WaitForExit(60000)) { $process.Kill(); throw 'Packaged smoke test timed out.' }
            if ($process.ExitCode -ne 0) { throw "Packaged smoke test exited with code $($process.ExitCode)." }
        } finally { $process.Dispose() }
        $marker = Get-Content -LiteralPath (Join-Path $smokeRoot 'smoke-test.json') -Raw | ConvertFrom-Json
        Assert-Equal 'passed' $marker.Status 'Smoke status'
        Assert-Equal $ExpectedVersion $marker.ToolVersion 'Smoke version'
        Assert-Equal $ExpectedFeatureProfile $marker.FeatureProfile 'Smoke feature profile'
        Assert-Equal $false ([bool]$marker.PrivilegedOperationsEnabled) 'Smoke privileged gate'
        Assert-Equal '10.0.11' $marker.RuntimeVersion 'Smoke runtime version'
    }

    Write-Host "ShareReadOnly candidate verified: $root" -ForegroundColor Green
    Write-Host "Candidate state: $($manifest.CandidateState)"
    if (-not [bool]$manifest.ShareApproved) { Write-Host 'Not approved for sharing: external signature/timestamp and exact-package VM gates remain.' -ForegroundColor Yellow }
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) { Remove-Item -LiteralPath $temporaryRoot -Recurse -Force }
}
