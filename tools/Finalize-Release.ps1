[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$CandidateRoot,
    [Parameter(Mandatory)][string]$VmEvidencePath,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ExpectedRuntimeZipSha256,
    [Parameter(Mandatory)][string]$OutputRoot,
    [Parameter(Mandatory)][switch]$ApproveForSharing
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $ApproveForSharing) { throw 'Finalization requires the explicit -ApproveForSharing switch after human evidence review.' }
$candidateFull = [IO.Path]::GetFullPath($CandidateRoot)
$evidenceFull = [IO.Path]::GetFullPath($VmEvidencePath)
$outputFull = [IO.Path]::GetFullPath($OutputRoot)
if (-not (Test-Path -LiteralPath $candidateFull -PathType Container)) { throw "Candidate directory not found: $candidateFull" }
if (-not (Test-Path -LiteralPath $evidenceFull -PathType Leaf)) { throw "VM evidence not found: $evidenceFull" }

$verifyScript = Join-Path $PSScriptRoot 'Verify-Release.ps1'
& $verifyScript -ArtifactsRoot $candidateFull
if ($LASTEXITCODE -ne 0) { throw 'The signed candidate failed verification before promotion.' }

$manifestPath = Join-Path $candidateFull 'ReleaseManifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ([string]$manifest.CandidateState -cne 'SignedAwaitingExactPackageVmEvidence' -or [bool]$manifest.ShareApproved -or
    [string]$manifest.AuthenticodeStatus -cne 'Valid' -or -not [bool]$manifest.Rfc3161TimestampVerified -or
    -not [bool]$manifest.ReproducibleBuildVerified -or -not [bool]$manifest.SourceOriginVerified -or
    -not [bool]$manifest.SourceTagVerified -or [bool]$manifest.ExactPackageVmEvidenceVerified) {
    throw 'Only a fully signed, RFC3161-verified, reproducible exact-tag candidate awaiting VM evidence can be promoted.'
}
$runtimeAsset = @($manifest.Assets | Where-Object Role -ceq 'runtime-candidate')
$sourceAsset = @($manifest.Assets | Where-Object Role -ceq 'source')
if ($runtimeAsset.Count -ne 1 -or $sourceAsset.Count -ne 1) { throw 'Candidate asset list is invalid.' }
$runtimePath = Join-Path $candidateFull ([string]$runtimeAsset[0].Name)
$sourcePath = Join-Path $candidateFull ([string]$sourceAsset[0].Name)
$runtimeHash = (Get-FileHash -LiteralPath $runtimePath -Algorithm SHA256).Hash.ToLowerInvariant()
$expectedHash = $ExpectedRuntimeZipSha256.ToLowerInvariant()
if ($runtimeHash -cne $expectedHash -or [string]$runtimeAsset[0].Sha256 -cne $expectedHash) {
    throw 'The explicit runtime ZIP hash does not match the signed candidate bytes.'
}

$evidenceText = Get-Content -LiteralPath $evidenceFull -Raw
if ($evidenceText -match '(?i)[A-Z]:\\|\\Users\\|/home/') { throw 'VM evidence contains an absolute local path.' }
$evidence = $evidenceText | ConvertFrom-Json
if ($evidence -isnot [pscustomobject]) { throw 'VM evidence must be one JSON object.' }
$requiredProperties = @(
    'EvidenceSchemaVersion', 'Product', 'Version', 'FeatureProfile', 'RuntimeZipFileName', 'RuntimeZipSize',
    'RuntimeZipSha256', 'ReleaseManifestSha256', 'ExecutableSha256', 'SourceCommit', 'SourceTag',
    'WindowsEdition', 'WindowsBuild', 'WindowsArchitecture', 'VmSnapshotId', 'AuthenticodeStatus',
    'SignerSubject', 'SignerIssuer', 'SignerThumbprint', 'Rfc3161TimestampVerified', 'TimestampAuthority',
    'DefenderScanPassed', 'StandardUserLaunchPassed', 'NoUacPromptObserved', 'ReadOnlyBoundaryPassed',
    'RequiredFunctionalChecksPassed', 'NoUnexpectedNetworkObserved', 'NoPersistenceObserved',
    'NoSettingsMutationObserved', 'NoUnexpectedChildProcessesObserved', 'ExportPrivacyChecksPassed',
    'SmokeRuntimeVersion', 'OverallResult', 'EvidenceArtifactId', 'TesterId', 'ReviewerId', 'TestedUtc', 'ReviewedUtc'
)
$unexpectedProperties = @(Compare-Object -ReferenceObject @($requiredProperties | Sort-Object) `
        -DifferenceObject @($evidence.PSObject.Properties.Name | Sort-Object) -CaseSensitive)
if ($unexpectedProperties.Count -ne 0) {
    throw 'VM evidence fields do not exactly match the sanitized evidence schema.'
}
$requiredTrue = @(
    'Rfc3161TimestampVerified', 'DefenderScanPassed', 'StandardUserLaunchPassed', 'NoUacPromptObserved',
    'ReadOnlyBoundaryPassed', 'RequiredFunctionalChecksPassed', 'NoUnexpectedNetworkObserved',
    'NoPersistenceObserved', 'NoSettingsMutationObserved', 'NoUnexpectedChildProcessesObserved',
    'ExportPrivacyChecksPassed'
)
$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ([int]$evidence.EvidenceSchemaVersion -ne 1 -or [string]$evidence.Product -cne 'PC Crash Diagnostic' -or
    [string]$evidence.Version -cne '3.2.0-beta.1' -or [string]$evidence.FeatureProfile -cne 'ShareReadOnly' -or
    [string]$evidence.RuntimeZipFileName -cne [string]$runtimeAsset[0].Name -or
    [long]$evidence.RuntimeZipSize -ne [long]$runtimeAsset[0].Size -or
    [string]$evidence.RuntimeZipSha256 -cne $expectedHash -or
    [string]$evidence.ReleaseManifestSha256 -cne $manifestHash -or
    [string]$evidence.ExecutableSha256 -cne [string]$manifest.ExecutableSha256 -or
    [string]$evidence.SourceCommit -cne [string]$manifest.SourceCommit -or
    [string]$evidence.SourceTag -cne 'v3.2.0-beta.1' -or [string]$evidence.WindowsArchitecture -cne 'x64' -or
    [string]$evidence.WindowsEdition -match '(?i)[A-Z]:\\|\\Users\\|/home/' -or
    [string]$evidence.WindowsEdition -notmatch '^.{1,128}$' -or
    [string]$evidence.WindowsBuild -notmatch '^(?:10\.0\.)?[0-9]{5}(?:\.[0-9]+){0,2}$' -or
    [string]$evidence.VmSnapshotId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
    [string]$evidence.AuthenticodeStatus -cne 'Valid' -or
    [string]$evidence.SignerSubject -cne [string]$manifest.SignerSubject -or
    [string]$evidence.SignerIssuer -cne [string]$manifest.SignerIssuer -or
    [string]$evidence.SignerThumbprint -cne [string]$manifest.SignerThumbprint -or
    [string]$evidence.TimestampAuthority -cne [string]$manifest.TimestampSubject -or
    [string]$evidence.SmokeRuntimeVersion -cne '10.0.11' -or [string]$evidence.OverallResult -cne 'Passed' -or
    [string]$evidence.EvidenceArtifactId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
    [string]$evidence.TesterId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
    [string]$evidence.ReviewerId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' -or
    [string]$evidence.TesterId -ceq [string]$evidence.ReviewerId -or
    @($requiredTrue | Where-Object { -not [bool]$evidence.PSObject.Properties[$_].Value }).Count -ne 0) {
    throw 'Exact-package VM evidence is incomplete, failed, or bound to different bytes/source.'
}
$testedUtc = [DateTimeOffset]::MinValue
$reviewedUtc = [DateTimeOffset]::MinValue
if (-not [DateTimeOffset]::TryParse([string]$evidence.TestedUtc, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind, [ref]$testedUtc) -or
    -not [DateTimeOffset]::TryParse([string]$evidence.ReviewedUtc, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind, [ref]$reviewedUtc) -or
    $reviewedUtc -lt $testedUtc) {
    throw 'VM evidence test/review timestamps are invalid or out of order.'
}

$approvedRoot = Join-Path $outputFull '3.2.0-beta.1-share-read-only-approvedforsharing'
if (Test-Path -LiteralPath $approvedRoot) { throw "Approved output already exists: $approvedRoot" }
New-Item -ItemType Directory -Path $outputFull -Force | Out-Null
$approvedStage = Join-Path $outputFull ('.finalize-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $approvedStage | Out-Null
try {
    Copy-Item -LiteralPath $runtimePath -Destination (Join-Path $approvedStage $runtimeAsset[0].Name)
    Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $approvedStage $sourceAsset[0].Name)

    $manifest.CandidateState = 'ApprovedForSharing'
    $manifest.ShareApproved = $true
    $manifest.ShareApprovalBlockers = @()
    $manifest.ExactPackageVmEvidenceVerified = $true
    $manifest | Add-Member -NotePropertyName ApprovedUtc -NotePropertyValue ([DateTimeOffset]::UtcNow.ToString('o')) -Force
    $manifest | Add-Member -NotePropertyName ExactPackageVmEvidence -NotePropertyValue ([ordered]@{
            EvidenceArtifactId = [string]$evidence.EvidenceArtifactId
            EvidenceSha256 = (Get-FileHash -LiteralPath $evidenceFull -Algorithm SHA256).Hash.ToLowerInvariant()
            RuntimeZipSha256 = $expectedHash
            ReviewedUtc = $reviewedUtc.ToUniversalTime().ToString('o')
        }) -Force
    $approvedManifestPath = Join-Path $approvedStage 'ReleaseManifest.json'
    $json = ($manifest | ConvertTo-Json -Depth 20).Replace("`r`n", "`n").TrimEnd() + "`n"
    [IO.File]::WriteAllText($approvedManifestPath, $json, [Text.UTF8Encoding]::new($false))

    $checksumLines = @()
    foreach ($name in @([string]$runtimeAsset[0].Name, [string]$sourceAsset[0].Name, 'ReleaseManifest.json')) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $approvedStage $name) -Algorithm SHA256).Hash.ToLowerInvariant()
        $checksumLines += "$hash *$name"
    }
    [IO.File]::WriteAllText((Join-Path $approvedStage 'SHA256SUMS.txt'), (($checksumLines -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))

    if ((Get-FileHash -LiteralPath (Join-Path $approvedStage $runtimeAsset[0].Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $runtimeHash) {
        throw 'Promotion changed the VM-tested runtime ZIP bytes.'
    }
    & $verifyScript -ArtifactsRoot $approvedStage -RequireShareApproved
    if ($LASTEXITCODE -ne 0) { throw 'Approved candidate failed final verification.' }
    [IO.Directory]::Move($approvedStage, $approvedRoot)
} finally {
    if (Test-Path -LiteralPath $approvedStage) {
        if ([IO.Path]::GetFileName($approvedStage) -notmatch '^\.finalize-[0-9a-f]{32}$') {
            throw "Refusing to clean an unexpected finalization path: $approvedStage"
        }
        Remove-Item -LiteralPath $approvedStage -Recurse -Force
    }
}
Write-Host "Approved-for-sharing bytes finalized without repacking the VM-tested runtime ZIP: $approvedRoot" -ForegroundColor Green
