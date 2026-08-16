[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$RepoRoot,

    [Parameter(Mandatory)]
    [string[]]$SubjectPaths,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [ValidateSet('ShareReadOnly')]
    [string]$FeatureProfile = 'ShareReadOnly',

    [ValidatePattern('^3\.2\.0-beta\.1$')]
    [string]$Version = '3.2.0-beta.1',

    [string]$BuilderId = 'local:unattested',

    [string]$InvocationId,

    [bool]$AuthenticodeVerified = $false,

    [bool]$Rfc3161TimestampVerified = $false,

    [bool]$ExactPackageVmEvidenceVerified = $false,

    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$UnsignedSigningInputSha256,

    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')]
    [string]$SigningInputArtifactId,

    [bool]$ReproducibleBuildVerified = $false,

    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ReproducibilityPeerSha256,

    [ValidatePattern('^https://github\.com/brads93/PCCrashDiagnostic$')]
    [string]$SourceRepository = 'https://github.com/brads93/PCCrashDiagnostic',

    [ValidatePattern('^v3\.2\.0-beta\.1$')]
    [string]$SourceTag,

    [bool]$SourceOriginVerified = $false,

    [bool]$SourceTagVerified = $false,

    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$ExpectedSourceCommit,

    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$ExpectedSourceTree,

    [ValidateSet('clean', 'dirty')]
    [string]$ExpectedSourceTreeState,

    [DateTimeOffset]$GeneratedUtc = [DateTimeOffset]::UtcNow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoFull = [IO.Path]::GetFullPath($RepoRoot)
if (-not (Test-Path -LiteralPath $repoFull -PathType Container)) { throw "Repository not found: $repoFull" }

$git = Get-Command git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($null -eq $git) { throw 'Git is required to generate release provenance.' }
$commit = ((& $git.Source -C $repoFull rev-parse HEAD 2>$null) -join '').Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') { throw 'Could not resolve the provenance source commit.' }
$tree = ((& $git.Source -C $repoFull rev-parse 'HEAD^{tree}' 2>$null) -join '').Trim().ToLowerInvariant()
if ($LASTEXITCODE -ne 0 -or $tree -notmatch '^[0-9a-f]{40}$') { throw 'Could not resolve the provenance source tree.' }
$status = @(& $git.Source -C $repoFull status --porcelain --untracked-files=normal 2>$null)
if ($LASTEXITCODE -ne 0) { throw 'Could not resolve the provenance source-tree state.' }
$treeState = if ($status.Count -eq 0) { 'clean' } else { 'dirty' }
$actualOrigin = ((& $git.Source -C $repoFull remote get-url origin 2>$null) -join '').Trim()
$actualOriginVerified = $LASTEXITCODE -eq 0 -and $actualOrigin -ceq $SourceRepository
$actualTag = ((& $git.Source -C $repoFull describe --tags --exact-match HEAD 2>$null) -join '').Trim()
$actualTagVerified = $LASTEXITCODE -eq 0 -and $actualTag -ceq "v$Version"
if ($SourceOriginVerified -and -not $actualOriginVerified) { throw 'Provenance cannot verify the claimed exact source origin.' }
if ($SourceTagVerified -and (-not $actualTagVerified -or $SourceTag -cne $actualTag)) { throw 'Provenance cannot verify the claimed exact source tag.' }
if ($ReproducibleBuildVerified -and
    ([string]::IsNullOrWhiteSpace($UnsignedSigningInputSha256) -or [string]::IsNullOrWhiteSpace($ReproducibilityPeerSha256) -or
     $UnsignedSigningInputSha256.ToLowerInvariant() -cne $ReproducibilityPeerSha256.ToLowerInvariant())) {
    throw 'Reproducible-build provenance requires two matching unsigned signing-input hashes.'
}
if (-not [string]::IsNullOrWhiteSpace($ExpectedSourceCommit) -and $commit -cne $ExpectedSourceCommit.ToLowerInvariant()) {
    throw 'The provenance source commit changed after release metadata was captured.'
}
if (-not [string]::IsNullOrWhiteSpace($ExpectedSourceTree) -and $tree -cne $ExpectedSourceTree.ToLowerInvariant()) {
    throw 'The provenance source tree changed after release metadata was captured.'
}
if (-not [string]::IsNullOrWhiteSpace($ExpectedSourceTreeState) -and $treeState -cne $ExpectedSourceTreeState) {
    throw 'The provenance source-tree state changed after release metadata was captured.'
}

$subjects = @()
foreach ($path in $SubjectPaths) {
    $full = [IO.Path]::GetFullPath($path)
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "Provenance subject not found: $full" }
    $subjects += [ordered]@{
        name = [IO.Path]::GetFileName($full)
        digest = [ordered]@{ sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
}

$materialFiles = @(
    'global.json',
    'Directory.Build.props',
    'PCCrashDiagnostic.sln',
    'PCCrashDiagnostic.Share.slnf',
    'tools/Build-Release.ps1',
    'tools/Verify-Release.ps1',
    'tools/Test-SafetyBoundary.ps1',
    'tools/Test-ReleaseIdentity.ps1',
    'tools/Test-AuthenticodePolicy.ps1',
    'tools/Test-PublicArtifactAudit.ps1',
    'tools/New-TestEvidence.ps1',
    'tools/New-ReleaseSbom.ps1',
    'tools/New-ReleaseProvenance.ps1',
    'tools/Finalize-Release.ps1',
    '.config/release/BuildManifest.schema.json',
    '.config/release/ReleaseManifest.schema.json',
    '.config/release/TestEvidence.schema.json',
    '.config/release/ExactPackageVmEvidence.schema.json',
    '.config/dotnet-tools.json',
    '.config/signpath/share-read-only-artifact-configuration.xml',
    '.config/signpath/share-read-only-source-policy.template.yml',
    '.github/workflows/signpath-share-read-only.yml',
    'src/PCCrashDiagnostic.Contracts/packages.lock.json',
    'src/PCCrashDiagnostic.Core/packages.lock.json',
    'src/PCCrashDiagnostic.LocalTools/packages.lock.json',
    'src/PCCrashDiagnostic.App/packages.lock.json',
    'tests/PCCrashDiagnostic.Share.Tests/packages.lock.json'
)

$materials = @()
foreach ($relative in @($materialFiles | Sort-Object -Unique)) {
    $full = if ([IO.Path]::IsPathRooted($relative)) { $relative } else { Join-Path $repoFull $relative }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "Required provenance material is missing: $relative" }
    $name = $full.Substring($repoFull.Length).TrimStart([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar).Replace('\', '/')
    $materials += [ordered]@{
        uri = "file:./$name"
        digest = [ordered]@{ sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant() }
    }
}

$materials += [ordered]@{
    uri = "git+$SourceRepository"
    digest = [ordered]@{ sha1 = $commit }
}

$statement = [ordered]@{
    _type = 'https://in-toto.io/Statement/v1'
    subject = $subjects
    predicateType = 'https://slsa.dev/provenance/v1'
    predicate = [ordered]@{
        buildDefinition = [ordered]@{
            buildType = 'https://pc-crash-diagnostic.invalid/build-types/share-read-only/v1'
            externalParameters = [ordered]@{
                version = $Version
                featureProfile = $FeatureProfile
                runtimeIdentifier = 'win-x64'
                configuration = 'Release'
                sourceRepository = $SourceRepository
                sourceTag = if ($SourceTagVerified) { $SourceTag } else { $null }
            }
            internalParameters = [ordered]@{
                sourceTreeState = $treeState
                sourceTree = $tree
                sourceOriginVerified = $SourceOriginVerified
                sourceTagVerified = $SourceTagVerified
                authenticodeVerified = $AuthenticodeVerified
                rfc3161TimestampVerified = $Rfc3161TimestampVerified
                exactPackageVmEvidenceVerified = $ExactPackageVmEvidenceVerified
                reproducibleBuildVerified = $ReproducibleBuildVerified
                reproducibilityPeerSha256 = if ([string]::IsNullOrWhiteSpace($ReproducibilityPeerSha256)) { $null } else { $ReproducibilityPeerSha256.ToLowerInvariant() }
                unsignedSigningInputSha256 = if ([string]::IsNullOrWhiteSpace($UnsignedSigningInputSha256)) { $null } else { $UnsignedSigningInputSha256.ToLowerInvariant() }
                signingInputArtifactId = if ([string]::IsNullOrWhiteSpace($SigningInputArtifactId)) { $null } else { $SigningInputArtifactId }
                capabilities = [ordered]@{
                    profile = 'ShareReadOnly'; standardEvidence = $true; targetMonitoring = $true
                    crashReadinessReadOnly = $true; accessibleDumpMetadata = $true; localHistory = $true
                    safeSummaryExport = $true; technicalReportExport = $true; recycleBinDeletion = $true
                    dumpChk = $true; winDbg = $true; microsoftSymbolsAfterConsent = $true
                    elevatedHelper = $false; settingsApply = $false; settingsRestore = $false
                    werLocalDumps = $false; protectedEvidence = $false; protectedDumpStaging = $false; dumpPackaging = $false
                }
                elevation = 'None'; settingsMutation = 'None'; protectedEvidence = 'None'
                network = 'ConsentOnlyMicrosoftSymbols'; helper = 'Absent'
            }
            resolvedDependencies = $materials
        }
        runDetails = [ordered]@{
            builder = [ordered]@{ id = $BuilderId }
            metadata = [ordered]@{
                invocationId = if ([string]::IsNullOrWhiteSpace($InvocationId)) { $null } else { $InvocationId }
                startedOn = $null
                finishedOn = $GeneratedUtc.ToUniversalTime().ToString('o')
            }
            byproducts = @()
        }
    }
}

$outputFull = [IO.Path]::GetFullPath($OutputPath)
$parent = Split-Path -Parent $outputFull
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}
$json = ($statement | ConvertTo-Json -Depth 14).Replace("`r`n", "`n").TrimEnd() + "`n"
[IO.File]::WriteAllText($outputFull, $json, [Text.UTF8Encoding]::new($false))
Write-Host "Unattested SLSA provenance statement written: $outputFull"
Write-Host 'This file is evidence scaffolding, not a signed attestation or a SLSA-level claim.'
