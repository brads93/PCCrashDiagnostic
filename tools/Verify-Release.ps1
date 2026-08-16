[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ArtifactsRoot,

    [ValidateSet('3.1.0-beta.1', '3.1.0-beta.2')]
    [string]$ExpectedVersion = '3.1.0-beta.2',

    [switch]$RequireSignature,

    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$ExpectedSignerThumbprint,

    [switch]$RunSmokeTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$productName = 'PC Crash Diagnostic'
$releaseChannel = 'beta'
$assetPrefix = 'PCCrashDiagnostic'
$sourcePackageRoot = 'PCCrashDiagnostic-source'
$mainExecutableName = 'PCCrashDiagnostic.exe'
$optionalElevatedHelperName = 'PCCrashDiagnostic.ElevatedHelper.exe'
$solutionName = 'PCCrashDiagnostic.sln'
$expectedReleaseStage = if ($ExpectedVersion -ceq '3.1.0-beta.1') { 'Beta1' } else { 'Beta2' }
$expectedBeta2Features = $expectedReleaseStage -ceq 'Beta2'
$expectedWerLocalDumpCapture = $false
$sourceRootAllowlist = @(
    '00-START-HERE.txt',
    '.gitignore',
    $solutionName,
    'CHANGELOG.md',
    'CONTRIBUTING.md',
    'Directory.Build.props',
    'global.json',
    'LICENSE',
    'PRIVACY.md',
    'README.md',
    'SECURITY.md',
    'THIRD_PARTY_NOTICES.md'
)
$sourceDirectoryExtensionAllowlist = [ordered]@{
    'src' = @('.cs', '.csproj', '.json', '.manifest', '.resx', '.xaml')
    'tests' = @('.cs', '.csproj', '.json', '.xml')
}
$sourceExactPathAllowlist = @(
    'docs/DEVELOPMENT.md',
    'docs/REPORT_FORMAT.md',
    'licenses/DOTNET-LIBRARY-LICENSE.txt',
    'licenses/DOTNET-RUNTIME-MIT-LICENSE.txt',
    'licenses/DOTNET-RUNTIME-THIRD-PARTY-NOTICES.txt',
    'licenses/DOTNET-WINDOWS-LICENSE-INFORMATION.md',
    'licenses/DOTNET-WPF-MIT-LICENSE.txt',
    'licenses/DOTNET-WPF-THIRD-PARTY-NOTICES.txt',
    'licenses/WINDOWS-SDK-LICENSE.md',
    'tools/Build-Release.ps1',
    'tools/Test-SyntheticScenarios.ps1',
    'tools/Test-SafetyBoundary.ps1',
    'tools/Test-ReleaseIdentity.ps1',
    'tools/Verify-Release.ps1'
)
$runtimeBaseRequiredFiles = @(
    '00-START-HERE.txt',
    $mainExecutableName,
    'BUILD-MANIFEST.json',
    'CHANGELOG.md',
    'CONTRIBUTING.md',
    'docs/REPORT_FORMAT.md',
    'LICENSE',
    'licenses/DOTNET-LIBRARY-LICENSE.txt',
    'licenses/DOTNET-RUNTIME-MIT-LICENSE.txt',
    'licenses/DOTNET-RUNTIME-THIRD-PARTY-NOTICES.txt',
    'licenses/DOTNET-WINDOWS-LICENSE-INFORMATION.md',
    'licenses/DOTNET-WPF-MIT-LICENSE.txt',
    'licenses/DOTNET-WPF-THIRD-PARTY-NOTICES.txt',
    'licenses/WINDOWS-SDK-LICENSE.md',
    'PRIVACY.md',
    'README.md',
    'SECURITY.md',
    'THIRD_PARTY_NOTICES.md'
)

if ($RequireSignature -and [string]::IsNullOrWhiteSpace($ExpectedSignerThumbprint)) {
    throw '-RequireSignature also requires -ExpectedSignerThumbprint with the pinned 40-hex certificate thumbprint.'
}
if (-not $RequireSignature -and -not [string]::IsNullOrWhiteSpace($ExpectedSignerThumbprint)) {
    throw '-ExpectedSignerThumbprint is valid only together with -RequireSignature.'
}
$normalizedExpectedSignerThumbprint = if ([string]::IsNullOrWhiteSpace($ExpectedSignerThumbprint)) {
    $null
} else {
    $ExpectedSignerThumbprint.ToUpperInvariant()
}

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$LiteralPath)
    return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-Equal {
    param(
        [Parameter(Mandatory)][AllowNull()]$Expected,
        [Parameter(Mandatory)][AllowNull()]$Actual,
        [Parameter(Mandatory)][string]$Description
    )
    if ([string]$Expected -cne [string]$Actual) {
        throw "$Description mismatch. Expected '$Expected'; found '$Actual'."
    }
}

function Assert-ExecutableVersion {
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][string]$Version,
        [Parameter(Mandatory)][string]$Description
    )

    $versionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($LiteralPath)
    Assert-Equal -Expected '3.1.0.0' -Actual $versionInfo.FileVersion -Description "$Description file version"
    $escapedVersion = [regex]::Escape($Version)
    if ([string]$versionInfo.ProductVersion -notmatch "^$escapedVersion(?:\+[^\s]+)?$") {
        throw "$Description product version mismatch. Expected '$Version' with at most a source-revision suffix; found '$($versionInfo.ProductVersion)'."
    }
}

function Assert-ObjectProperties {
    param(
        [Parameter(Mandatory)]$InputObject,
        [Parameter(Mandatory)][string[]]$Names,
        [Parameter(Mandatory)][string]$Description
    )

    $presentNames = @($InputObject.PSObject.Properties.Name)
    foreach ($name in $Names) {
        if (-not ($presentNames -contains $name)) {
            throw "$Description is missing required property '$name'."
        }
    }
}

function Assert-AllowedSourcePath {
    param([Parameter(Mandatory)][string]$RelativePath)

    $normalized = $RelativePath.Replace('\', '/').TrimStart('/')
    if ([string]::IsNullOrWhiteSpace($normalized) -or
        $normalized -match '(^|/)\.\.(/|$)' -or
        $normalized.Contains(':')) {
        throw "Unsafe source-package path '$RelativePath'."
    }

    $leafName = [IO.Path]::GetFileName($normalized)
    $extension = [IO.Path]::GetExtension($leafName)
    $rejectedExtensions = @(
        '.7z', '.cer', '.crt', '.der', '.dll', '.dmp', '.etl', '.evtx', '.exe',
        '.gz', '.hdmp', '.key', '.log', '.mdmp', '.p12', '.pdb', '.pem', '.pfx',
        '.rar', '.snk', '.tar', '.trx', '.zip'
    )
    $rejectedNames = @(
        '.npmrc', '.pypirc', 'ACTIVE', 'Artifacts.json', 'Collection-Status.json',
        'credentials.json', 'id_ed25519', 'id_rsa', 'Manifest.json', 'NuGet.Config',
        'Performance-Samples.csv', 'Reliability.json', 'Report.json', 'secrets.json',
        'SUMMARY.txt', 'Windows-Event-Groups.json', 'Windows-Events.json'
    )
    if ($leafName -match '^(?i:\.env)(?:$|\.)' -or
        $rejectedExtensions -contains $extension -or
        $rejectedNames -contains $leafName -or
        $normalized -match '(^|/)(?i:diagnostic-data|dumps?|exports?|reports?|sessions?)(/|$)') {
        throw "Sensitive or generated file is forbidden in the source package: '$normalized'."
    }

    if ($sourceRootAllowlist -contains $normalized -or $sourceExactPathAllowlist -contains $normalized) {
        return
    }

    $separator = $normalized.IndexOf('/')
    if ($separator -lt 1) {
        throw "Source-package root file is not allowlisted: '$normalized'."
    }

    $directory = $normalized.Substring(0, $separator)
    if (-not $sourceDirectoryExtensionAllowlist.Contains($directory) -or
        -not ($sourceDirectoryExtensionAllowlist[$directory] -contains $extension)) {
        throw "Source-package path is outside the explicit allowlist: '$normalized'."
    }
}

function Assert-SafeZip {
    param([Parameter(Mandatory)][string]$LiteralPath)

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($LiteralPath)
    try {
        $entryNames = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $archive.Entries) {
            $name = $entry.FullName.Replace('\', '/')
            if ([string]::IsNullOrWhiteSpace($name) -or
                $name.StartsWith('/') -or
                $name -match '(^|/)\.\.(/|$)' -or
                $name.Contains(':')) {
                throw "Unsafe ZIP entry '$name' in '$LiteralPath'."
            }
            if (-not $entryNames.Add($name)) {
                throw "Duplicate ZIP entry '$name' in '$LiteralPath'."
            }
            $unixFileType = (($entry.ExternalAttributes -shr 16) -band 0xF000)
            $windowsAttributes = ($entry.ExternalAttributes -band 0xFFFF)
            if ($unixFileType -eq 0xA000 -or
                ($windowsAttributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Symbolic-link or reparse-point ZIP entry '$name' is forbidden in '$LiteralPath'."
            }
        }
        return @($archive.Entries | ForEach-Object { $_.FullName.Replace('\', '/') })
    } finally {
        $archive.Dispose()
    }
}

function Get-PeMachine {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $stream = [IO.File]::Open($LiteralPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $reader = [IO.BinaryReader]::new($stream)
    try {
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5A4D) {
            throw "Not a valid PE file: $LiteralPath"
        }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadUInt32()
        if ($peOffset -gt ($stream.Length - 6)) { throw "Invalid PE header offset: $LiteralPath" }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { throw "Missing PE signature: $LiteralPath" }
        return $reader.ReadUInt16()
    } finally {
        $reader.Dispose()
        $stream.Dispose()
    }
}

function Expand-CheckedZip {
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][string]$DestinationPath
    )

    [void](Assert-SafeZip -LiteralPath $LiteralPath)
    [IO.Compression.ZipFile]::ExtractToDirectory($LiteralPath, $DestinationPath)
}

$artifactsRootFull = [IO.Path]::GetFullPath($ArtifactsRoot)
if (-not (Test-Path -LiteralPath $artifactsRootFull -PathType Container)) {
    throw "Artifacts directory does not exist: $artifactsRootFull"
}

$manifestPath = Join-Path $artifactsRootFull 'ReleaseManifest.json'
$checksumsPath = Join-Path $artifactsRootFull 'SHA256SUMS.txt'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $checksumsPath -PathType Leaf)) {
    throw 'ReleaseManifest.json and SHA256SUMS.txt are required.'
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
Assert-ObjectProperties -InputObject $manifest -Description 'ReleaseManifest.json' -Names @(
    'ManifestSchemaVersion', 'Product', 'Version', 'ReleaseStage', 'Beta2FeaturesEnabled', 'WerLocalDumpCaptureEnabled',
    'ReleaseChannel', 'ReleaseLabel',
    'PublisherTrust', 'TrustNotice', 'ChecksumAlgorithm', 'Configuration', 'RuntimeIdentifier',
    'ExecutableName', 'ExecutableSha256', 'AuthenticodeStatus', 'SignerSubject',
    'SignerThumbprint', 'TimestampSignerSubject', 'TimestampSignerThumbprint',
    'OptionalElevatedHelper', 'TestsExecuted', 'RuntimePackageFiles', 'Assets'
)
Assert-Equal -Expected 2 -Actual $manifest.ManifestSchemaVersion -Description 'Manifest schema version'
Assert-Equal -Expected $productName -Actual $manifest.Product -Description 'Product'
if (-not [string]::IsNullOrWhiteSpace($ExpectedVersion)) {
    Assert-Equal -Expected $ExpectedVersion -Actual $manifest.Version -Description 'Version'
}
Assert-Equal -Expected $expectedReleaseStage -Actual $manifest.ReleaseStage -Description 'Release stage'
Assert-Equal -Expected $expectedBeta2Features -Actual $manifest.Beta2FeaturesEnabled -Description 'Beta 2 feature flag'
Assert-Equal -Expected $expectedWerLocalDumpCapture -Actual $manifest.WerLocalDumpCaptureEnabled -Description 'WER LocalDumps distribution gate'
Assert-Equal -Expected $releaseChannel -Actual $manifest.ReleaseChannel -Description 'Release channel'
Assert-Equal -Expected 'SHA-256' -Actual $manifest.ChecksumAlgorithm -Description 'Checksum algorithm'
Assert-Equal -Expected 'win-x64' -Actual $manifest.RuntimeIdentifier -Description 'Runtime identifier'
Assert-Equal -Expected $mainExecutableName -Actual $manifest.ExecutableName -Description 'Executable name'
Assert-Equal -Expected 'Release' -Actual $manifest.Configuration -Description 'Build configuration'
if (-not [bool]$manifest.TestsExecuted) {
    throw 'A public release must record a successful test run.'
}

switch ([string]$manifest.PublisherTrust) {
    'unsigned' {
        Assert-Equal -Expected 'UNSIGNED BETA' -Actual $manifest.ReleaseLabel -Description 'Unsigned beta label'
        Assert-Equal -Expected 'NotSigned' -Actual $manifest.AuthenticodeStatus -Description 'Unsigned beta Authenticode status'
        Assert-Equal -Expected $null -Actual $manifest.SignerSubject -Description 'Unsigned beta signer subject'
        Assert-Equal -Expected $null -Actual $manifest.SignerThumbprint -Description 'Unsigned beta signer thumbprint'
        Assert-Equal -Expected $null -Actual $manifest.TimestampSignerSubject -Description 'Unsigned beta timestamp signer subject'
        Assert-Equal -Expected $null -Actual $manifest.TimestampSignerThumbprint -Description 'Unsigned beta timestamp signer thumbprint'
        Assert-Equal -Expected 'Unsigned beta. Verify SHA-256 through a trusted independent channel before running.' -Actual $manifest.TrustNotice -Description 'Unsigned beta trust notice'
        if ($RequireSignature) {
            throw 'The manifest labels this release unsigned, but signature verification was required.'
        }
    }
    'authenticode-pinned' {
        Assert-Equal -Expected 'SIGNED BETA' -Actual $manifest.ReleaseLabel -Description 'Pinned beta label'
        Assert-Equal -Expected 'Valid' -Actual $manifest.AuthenticodeStatus -Description 'Pinned beta Authenticode status'
        Assert-Equal -Expected 'Authenticode signature and pinned signer thumbprint verified.' -Actual $manifest.TrustNotice -Description 'Pinned beta trust notice'
        if (-not $RequireSignature) {
            throw 'A manifest may claim authenticode-pinned trust only when the verifier is given a pinned signer thumbprint.'
        }
    }
    'signature-present-unverified' {
        Assert-Equal -Expected 'BETA - SIGNATURE NOT PINNED' -Actual $manifest.ReleaseLabel -Description 'Unpinned-signature beta label'
        Assert-Equal -Expected 'A signature is present but publisher identity was not pinned. Verify SHA-256 through a trusted independent channel.' -Actual $manifest.TrustNotice -Description 'Unpinned-signature trust notice'
        if ($RequireSignature) {
            throw 'A release requiring a pinned signature cannot be labeled signature-present-unverified.'
        }
    }
    default {
        throw "Unknown PublisherTrust value '$($manifest.PublisherTrust)'."
    }
}

$runtimeRequiredFiles = @($runtimeBaseRequiredFiles) + $optionalElevatedHelperName
$helperManifest = $manifest.OptionalElevatedHelper
if ($null -eq $helperManifest) {
    throw "Version $ExpectedVersion must include '$optionalElevatedHelperName' and its manifest metadata."
}
Assert-ObjectProperties -InputObject $helperManifest -Description 'OptionalElevatedHelper' -Names @(
    'Name', 'Sha256', 'EmbeddedBindingSha256', 'AuthenticodeStatus'
)
Assert-Equal -Expected $optionalElevatedHelperName -Actual $helperManifest.Name -Description 'Optional elevated helper name'
if ([string]$helperManifest.Sha256 -notmatch '^[0-9a-f]{64}$') {
    throw 'Optional elevated helper SHA-256 must be 64 lowercase hexadecimal characters.'
}
Assert-Equal -Expected $helperManifest.Sha256 -Actual $helperManifest.EmbeddedBindingSha256 -Description 'Main-app embedded helper binding'
if ([string]$manifest.PublisherTrust -eq 'unsigned' -and
    $null -ne $helperManifest -and
    [string]$helperManifest.AuthenticodeStatus -ne 'NotSigned') {
    throw 'A release with a signed or malformed optional helper cannot be labeled unsigned.'
}
if ([string]$manifest.PublisherTrust -eq 'signature-present-unverified' -and
    [string]$manifest.AuthenticodeStatus -eq 'NotSigned' -and
    ($null -eq $helperManifest -or [string]$helperManifest.AuthenticodeStatus -eq 'NotSigned')) {
    throw 'A wholly unsigned release cannot be labeled signature-present-unverified.'
}

$assets = @($manifest.Assets)
if ($assets.Count -ne 2) { throw 'The release manifest must list exactly a runtime ZIP and a source ZIP.' }
$runtimeAsset = @($assets | Where-Object Role -eq 'runtime')
$sourceAsset = @($assets | Where-Object Role -eq 'source')
if ($runtimeAsset.Count -ne 1 -or $sourceAsset.Count -ne 1) {
    throw 'The release manifest must contain exactly one runtime asset and one source asset.'
}
$runtimeAsset = $runtimeAsset[0]
$sourceAsset = $sourceAsset[0]
$safeVersion = ([string]$manifest.Version) -replace '[^A-Za-z0-9._-]', '-'
Assert-Equal -Expected "$assetPrefix-$safeVersion-win-x64.zip" -Actual $runtimeAsset.Name -Description 'Runtime asset name'
Assert-Equal -Expected "$assetPrefix-$safeVersion-source.zip" -Actual $sourceAsset.Name -Description 'Source asset name'

$expectedReleaseNames = @(
    [string]$runtimeAsset.Name,
    [string]$sourceAsset.Name,
    'ReleaseManifest.json',
    'SHA256SUMS.txt'
)
$actualReleaseFiles = @(Get-ChildItem -LiteralPath $artifactsRootFull -File -Force)
$actualReleaseDirectories = @(Get-ChildItem -LiteralPath $artifactsRootFull -Directory -Force)
if ($actualReleaseDirectories.Count -ne 0 -or $actualReleaseFiles.Count -ne $expectedReleaseNames.Count) {
    throw 'The release directory must contain exactly the runtime ZIP, source ZIP, ReleaseManifest.json, and SHA256SUMS.txt.'
}
foreach ($name in $expectedReleaseNames) {
    if (@($actualReleaseFiles | Where-Object Name -ceq $name).Count -ne 1) {
        throw "Release file set is missing or duplicates '$name'."
    }
}

foreach ($asset in $assets) {
    if ([IO.Path]::GetFileName([string]$asset.Name) -cne [string]$asset.Name) {
        throw "Asset name must not contain a path: $($asset.Name)"
    }
    $assetPath = Join-Path $artifactsRootFull ([string]$asset.Name)
    if (-not (Test-Path -LiteralPath $assetPath -PathType Leaf)) {
        throw "Missing release asset: $($asset.Name)"
    }
    Assert-Equal -Expected $asset.Size -Actual (Get-Item -LiteralPath $assetPath).Length -Description "$($asset.Name) size"
    Assert-Equal -Expected ([string]$asset.Sha256).ToLowerInvariant() -Actual (Get-Sha256 -LiteralPath $assetPath) -Description "$($asset.Name) SHA-256"
}

$checksumMap = @{}
foreach ($line in (Get-Content -LiteralPath $checksumsPath)) {
    if ([string]::IsNullOrWhiteSpace($line)) { continue }
    if ($line -notmatch '^([0-9a-fA-F]{64}) \*([^\\/]+)$') {
        throw "Invalid SHA256SUMS.txt line: $line"
    }
    if ($checksumMap.ContainsKey($Matches[2])) {
        throw "SHA256SUMS.txt contains duplicate entry '$($Matches[2])'."
    }
    $checksumMap[$Matches[2]] = $Matches[1].ToLowerInvariant()
}

foreach ($name in @([string]$runtimeAsset.Name, [string]$sourceAsset.Name, 'ReleaseManifest.json')) {
    if (-not $checksumMap.ContainsKey($name)) { throw "SHA256SUMS.txt is missing '$name'." }
    Assert-Equal -Expected $checksumMap[$name] -Actual (Get-Sha256 -LiteralPath (Join-Path $artifactsRootFull $name)) -Description "$name checksum file entry"
}
if ($checksumMap.Count -ne 3) { throw 'SHA256SUMS.txt must contain exactly the two assets and ReleaseManifest.json.' }

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ('PCCrashDiagnostic-Verify-' + [Guid]::NewGuid().ToString('N'))
$runtimeExtract = Join-Path $temporaryRoot 'runtime'
$sourceExtract = Join-Path $temporaryRoot 'source'
New-Item -ItemType Directory -Path $runtimeExtract, $sourceExtract -Force | Out-Null

try {
    $runtimeZipPath = Join-Path $artifactsRootFull ([string]$runtimeAsset.Name)
    $sourceZipPath = Join-Path $artifactsRootFull ([string]$sourceAsset.Name)
    Expand-CheckedZip -LiteralPath $runtimeZipPath -DestinationPath $runtimeExtract
    Expand-CheckedZip -LiteralPath $sourceZipPath -DestinationPath $sourceExtract

    $runtimeFiles = @(Get-ChildItem -LiteralPath $runtimeExtract -File -Recurse)
    $runtimeDirectories = @(
        Get-ChildItem -LiteralPath $runtimeExtract -Directory -Recurse |
            ForEach-Object {
                $_.FullName.Substring($runtimeExtract.Length).TrimStart([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar).Replace('\', '/')
            }
    )
    $requiredRuntimeDirectories = @('docs', 'licenses')
    if ($runtimeDirectories.Count -ne $requiredRuntimeDirectories.Count) {
        throw 'Runtime ZIP must contain exactly the docs and licenses directories.'
    }
    foreach ($directory in $requiredRuntimeDirectories) {
        if (@($runtimeDirectories | Where-Object { $_ -ceq $directory }).Count -ne 1) {
            throw "Runtime ZIP is missing required directory '$directory' or contains an unexpected directory."
        }
    }

    $expectedRuntimeFiles = @($manifest.RuntimePackageFiles)
    if ($expectedRuntimeFiles.Count -ne $runtimeRequiredFiles.Count) {
        throw "Runtime manifest must list exactly $($runtimeRequiredFiles.Count) allowlisted payload files."
    }
    if ($runtimeFiles.Count -ne $expectedRuntimeFiles.Count) {
        throw "Runtime file count mismatch. Expected $($expectedRuntimeFiles.Count); found $($runtimeFiles.Count)."
    }
    $runtimeManifestPaths = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($expectedFile in $expectedRuntimeFiles) {
        $relativePath = ([string]$expectedFile.Path).Replace('\', '/')
        if ([string]::IsNullOrWhiteSpace($relativePath) -or
            $relativePath.StartsWith('/') -or
            $relativePath -match '(^|/)\.\.(/|$)' -or
            $relativePath.Contains(':')) {
            throw "Unsafe runtime manifest path: $($expectedFile.Path)"
        }
        if (-not $runtimeManifestPaths.Add($relativePath)) {
            throw "Runtime manifest contains duplicate path '$relativePath'."
        }
        $actualPath = Join-Path $runtimeExtract $relativePath
        if (-not (Test-Path -LiteralPath $actualPath -PathType Leaf)) {
            throw "Runtime ZIP is missing '$($expectedFile.Path)'."
        }
        Assert-Equal -Expected $expectedFile.Size -Actual (Get-Item -LiteralPath $actualPath).Length -Description "$($expectedFile.Path) size"
        Assert-Equal -Expected ([string]$expectedFile.Sha256).ToLowerInvariant() -Actual (Get-Sha256 -LiteralPath $actualPath) -Description "$($expectedFile.Path) SHA-256"
    }

    foreach ($requiredName in $runtimeRequiredFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $runtimeExtract $requiredName) -PathType Leaf)) {
            throw "Runtime ZIP is missing required file '$requiredName'."
        }
    }

    $executablePath = Join-Path $runtimeExtract $mainExecutableName
    Assert-Equal -Expected ([string]$manifest.ExecutableSha256).ToLowerInvariant() -Actual (Get-Sha256 -LiteralPath $executablePath) -Description 'Packaged executable SHA-256'
    Assert-Equal -Expected '34404' -Actual (Get-PeMachine -LiteralPath $executablePath) -Description 'Packaged executable PE machine (AMD64)'
    Assert-ExecutableVersion -LiteralPath $executablePath -Version $ExpectedVersion -Description 'Packaged executable'

    $buildManifestPath = Join-Path $runtimeExtract 'BUILD-MANIFEST.json'
    $buildManifest = Get-Content -LiteralPath $buildManifestPath -Raw | ConvertFrom-Json
    Assert-ObjectProperties -InputObject $buildManifest -Description 'BUILD-MANIFEST.json' -Names @(
        'ManifestSchemaVersion', 'Product', 'Version', 'ReleaseStage', 'Beta2FeaturesEnabled', 'WerLocalDumpCaptureEnabled',
        'ReleaseChannel', 'ReleaseLabel',
        'PublisherTrust', 'TrustNotice', 'ChecksumAlgorithm', 'Configuration', 'RuntimeIdentifier',
        'ExecutableName', 'ExecutableSha256', 'AuthenticodeStatus', 'SignerSubject',
        'SignerThumbprint', 'TimestampSignerSubject', 'TimestampSignerThumbprint',
        'OptionalElevatedHelper', 'TestsExecuted', 'SelfContained', 'SingleFile'
    )
    Assert-Equal -Expected 2 -Actual $buildManifest.ManifestSchemaVersion -Description 'Runtime build-manifest schema version'
    Assert-Equal -Expected $manifest.Product -Actual $buildManifest.Product -Description 'Runtime build-manifest product'
    Assert-Equal -Expected $manifest.Version -Actual $buildManifest.Version -Description 'Runtime build-manifest version'
    Assert-Equal -Expected $manifest.ReleaseStage -Actual $buildManifest.ReleaseStage -Description 'Runtime build-manifest release stage'
    Assert-Equal -Expected $manifest.Beta2FeaturesEnabled -Actual $buildManifest.Beta2FeaturesEnabled -Description 'Runtime build-manifest Beta 2 feature flag'
    Assert-Equal -Expected $manifest.WerLocalDumpCaptureEnabled -Actual $buildManifest.WerLocalDumpCaptureEnabled -Description 'Runtime build-manifest WER LocalDumps distribution gate'
    Assert-Equal -Expected $manifest.ReleaseChannel -Actual $buildManifest.ReleaseChannel -Description 'Runtime build-manifest release channel'
    Assert-Equal -Expected $manifest.ReleaseLabel -Actual $buildManifest.ReleaseLabel -Description 'Runtime build-manifest release label'
    Assert-Equal -Expected $manifest.PublisherTrust -Actual $buildManifest.PublisherTrust -Description 'Runtime build-manifest publisher trust'
    Assert-Equal -Expected $manifest.TrustNotice -Actual $buildManifest.TrustNotice -Description 'Runtime build-manifest trust notice'
    Assert-Equal -Expected $manifest.ChecksumAlgorithm -Actual $buildManifest.ChecksumAlgorithm -Description 'Runtime build-manifest checksum algorithm'
    Assert-Equal -Expected $manifest.RuntimeIdentifier -Actual $buildManifest.RuntimeIdentifier -Description 'Runtime build-manifest RID'
    Assert-Equal -Expected $manifest.ExecutableName -Actual $buildManifest.ExecutableName -Description 'Runtime build-manifest executable name'
    Assert-Equal -Expected $manifest.ExecutableSha256 -Actual $buildManifest.ExecutableSha256 -Description 'Runtime build-manifest executable hash'
    Assert-Equal -Expected 'Release' -Actual $buildManifest.Configuration -Description 'Runtime build-manifest configuration'
    if (-not [bool]$buildManifest.TestsExecuted) {
        throw 'Runtime build manifest must record a successful test run.'
    }
    if (-not [bool]$buildManifest.SelfContained -or -not [bool]$buildManifest.SingleFile) {
        throw 'Runtime build manifest must declare a self-contained single-file build.'
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $executablePath
    Assert-Equal -Expected $manifest.AuthenticodeStatus -Actual ([string]$signature.Status) -Description 'Authenticode status'
    $actualSignerSubject = if ($null -ne $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
    $actualSignerThumbprint = if ($null -ne $signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint.ToUpperInvariant() } else { $null }
    $actualTimestampSignerSubject = if ($null -ne $signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.Subject } else { $null }
    $actualTimestampSignerThumbprint = if ($null -ne $signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.Thumbprint.ToUpperInvariant() } else { $null }
    Assert-Equal -Expected $manifest.SignerSubject -Actual $actualSignerSubject -Description 'Authenticode signer subject'
    Assert-Equal -Expected $manifest.SignerThumbprint -Actual $actualSignerThumbprint -Description 'Authenticode signer thumbprint'
    Assert-Equal -Expected $manifest.TimestampSignerSubject -Actual $actualTimestampSignerSubject -Description 'Timestamp signer subject'
    Assert-Equal -Expected $manifest.TimestampSignerThumbprint -Actual $actualTimestampSignerThumbprint -Description 'Timestamp signer thumbprint'
    Assert-Equal -Expected $buildManifest.SignerSubject -Actual $actualSignerSubject -Description 'Runtime build-manifest signer subject'
    Assert-Equal -Expected $buildManifest.SignerThumbprint -Actual $actualSignerThumbprint -Description 'Runtime build-manifest signer thumbprint'
    Assert-Equal -Expected $buildManifest.TimestampSignerSubject -Actual $actualTimestampSignerSubject -Description 'Runtime build-manifest timestamp signer subject'
    Assert-Equal -Expected $buildManifest.TimestampSignerThumbprint -Actual $actualTimestampSignerThumbprint -Description 'Runtime build-manifest timestamp signer thumbprint'
    if ($RequireSignature) {
        if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or $null -eq $signature.SignerCertificate) {
            throw "A valid Authenticode signature is required; status is $($signature.Status)."
        }
        if ($actualSignerThumbprint -cne $normalizedExpectedSignerThumbprint) {
            throw "Authenticode signer thumbprint mismatch. Expected '$normalizedExpectedSignerThumbprint'; found '$actualSignerThumbprint'."
        }
        if ($null -eq $signature.TimeStamperCertificate) {
            throw 'A countersignature timestamp certificate is required for signed public releases.'
        }
    }

    if ($null -eq $buildManifest.OptionalElevatedHelper) {
        throw 'Runtime build manifest is missing OptionalElevatedHelper metadata.'
    }
    Assert-ObjectProperties -InputObject $buildManifest.OptionalElevatedHelper -Description 'Runtime OptionalElevatedHelper' -Names @(
        'Name', 'Sha256', 'EmbeddedBindingSha256', 'AuthenticodeStatus'
    )
    Assert-Equal -Expected $helperManifest.Name -Actual $buildManifest.OptionalElevatedHelper.Name -Description 'Runtime build-manifest helper name'
    Assert-Equal -Expected $helperManifest.Sha256 -Actual $buildManifest.OptionalElevatedHelper.Sha256 -Description 'Runtime build-manifest helper hash'
    Assert-Equal -Expected $helperManifest.EmbeddedBindingSha256 -Actual $buildManifest.OptionalElevatedHelper.EmbeddedBindingSha256 -Description 'Runtime build-manifest embedded helper binding'
    Assert-Equal -Expected $helperManifest.AuthenticodeStatus -Actual $buildManifest.OptionalElevatedHelper.AuthenticodeStatus -Description 'Runtime build-manifest helper Authenticode status'

    $helperPath = Join-Path $runtimeExtract $optionalElevatedHelperName
    Assert-Equal -Expected ([string]$helperManifest.Sha256).ToLowerInvariant() -Actual (Get-Sha256 -LiteralPath $helperPath) -Description 'Optional elevated helper SHA-256'
    Assert-Equal -Expected '34404' -Actual (Get-PeMachine -LiteralPath $helperPath) -Description 'Optional elevated helper PE machine (AMD64)'
    Assert-ExecutableVersion -LiteralPath $helperPath -Version $ExpectedVersion -Description 'Optional elevated helper'
    $actualHelperSignature = Get-AuthenticodeSignature -LiteralPath $helperPath
    Assert-Equal -Expected $helperManifest.AuthenticodeStatus -Actual ([string]$actualHelperSignature.Status) -Description 'Optional elevated helper Authenticode status'
    if ($RequireSignature) {
        if ($actualHelperSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
            $null -eq $actualHelperSignature.SignerCertificate) {
            throw "A valid Authenticode signature is required for '$optionalElevatedHelperName'."
        }
        if ($actualHelperSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -cne $normalizedExpectedSignerThumbprint) {
            throw "Authenticode signer thumbprint mismatch for '$optionalElevatedHelperName'."
        }
        if ($null -eq $actualHelperSignature.TimeStamperCertificate) {
            throw "A countersignature timestamp certificate is required for '$optionalElevatedHelperName'."
        }
    }

    $sourceEntries = @(Assert-SafeZip -LiteralPath $sourceZipPath)
    foreach ($entryName in $sourceEntries) {
        if (-not $entryName.StartsWith("$sourcePackageRoot/", [StringComparison]::Ordinal)) {
            throw "Source ZIP entry is outside the required package root: '$entryName'."
        }
        $relativePath = $entryName.Substring($sourcePackageRoot.Length + 1)
        Assert-AllowedSourcePath -RelativePath $relativePath
    }
    foreach ($requiredSuffix in @(
            '/00-START-HERE.txt',
            "/$solutionName",
            '/LICENSE',
            '/README.md',
            '/src/BF6CrashDiagnostic.App/BF6CrashDiagnostic.App.csproj',
            '/src/BF6CrashDiagnostic.Core/BF6CrashDiagnostic.Core.csproj',
            '/tests/BF6CrashDiagnostic.Tests/BF6CrashDiagnostic.Tests.csproj',
            '/docs/DEVELOPMENT.md',
            '/tools/Build-Release.ps1',
            '/tools/Test-SyntheticScenarios.ps1',
            '/tools/Test-SafetyBoundary.ps1',
            '/tools/Test-ReleaseIdentity.ps1',
            '/tools/Verify-Release.ps1')) {
        if (@($sourceEntries | Where-Object { $_.EndsWith($requiredSuffix, [StringComparison]::Ordinal) }).Count -ne 1) {
            throw "Source ZIP is missing expected entry ending in '$requiredSuffix'."
        }
    }

    if ($RunSmokeTest) {
        $bindingProcessInfo = [Diagnostics.ProcessStartInfo]::new()
        $bindingProcessInfo.FileName = $executablePath
        $bindingProcessInfo.Arguments = '--verify-helper-binding'
        $bindingProcessInfo.UseShellExecute = $false
        $bindingProcessInfo.CreateNoWindow = $true
        $bindingProcess = [Diagnostics.Process]::Start($bindingProcessInfo)
        if ($null -eq $bindingProcess) { throw 'Could not start the packaged helper-binding verification.' }
        try {
            if (-not $bindingProcess.WaitForExit(60000)) {
                $bindingProcess.Kill()
                throw 'The packaged helper-binding verification did not finish within 60 seconds.'
            }
            if ($bindingProcess.ExitCode -ne 0) {
                throw "The packaged helper-binding verification exited with code $($bindingProcess.ExitCode)."
            }
        } finally {
            $bindingProcess.Dispose()
        }

        $smokeDataRoot = Join-Path $temporaryRoot 'smoke data'
        New-Item -ItemType Directory -Path $smokeDataRoot -Force | Out-Null
        $processInfo = [Diagnostics.ProcessStartInfo]::new()
        $processInfo.FileName = $executablePath
        $escapedDataRoot = $smokeDataRoot.Replace('"', '\"')
        $processInfo.Arguments = "--smoke-test --data-root `"$escapedDataRoot`""
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $true
        $process = [Diagnostics.Process]::Start($processInfo)
        if ($null -eq $process) { throw 'Could not start the packaged EXE smoke test.' }
        try {
            if (-not $process.WaitForExit(60000)) {
                $process.Kill()
                throw 'The packaged EXE smoke test did not finish within 60 seconds.'
            }
            if ($process.ExitCode -ne 0) {
                throw "The packaged EXE smoke test exited with code $($process.ExitCode)."
            }
        } finally {
            $process.Dispose()
        }

        $smokeMarkerPath = Join-Path $smokeDataRoot 'smoke-test.json'
        if (-not (Test-Path -LiteralPath $smokeMarkerPath -PathType Leaf)) {
            throw 'The packaged EXE smoke test did not write its completion marker.'
        }
        $smokeMarker = Get-Content -LiteralPath $smokeMarkerPath -Raw | ConvertFrom-Json
        Assert-Equal -Expected 'passed' -Actual $smokeMarker.Status -Description 'Packaged smoke-test status'
        Assert-Equal -Expected $ExpectedVersion -Actual $smokeMarker.ToolVersion -Description 'Packaged tool version'
        Assert-Equal -Expected $expectedBeta2Features -Actual $smokeMarker.Beta2FeaturesEnabled -Description 'Packaged release stage'
        Assert-Equal -Expected $expectedWerLocalDumpCapture -Actual $smokeMarker.WerLocalDumpCaptureEnabled -Description 'Packaged WER LocalDumps distribution gate'
    }

    Write-Host "Release verified: $artifactsRootFull" -ForegroundColor Green
    Write-Host "Authenticode status: $($signature.Status)"
    Write-Host "Runtime SHA-256: $($runtimeAsset.Sha256)"
    if ($RunSmokeTest) {
        Write-Host 'Packaged executable smoke test: executed by explicit opt-in.'
    } else {
        Write-Host 'Packaged executable smoke test: not run (static verification only).'
    }
    Write-Host 'Important: same-directory manifests and checksums prove consistency, not publisher identity. Compare the runtime SHA-256 with a value obtained through a trusted, independent channel before running it.'
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}
