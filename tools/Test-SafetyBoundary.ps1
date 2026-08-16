[CmdletBinding()]
param(
    [string]$RepoRoot,
    [ValidateSet('ShareReadOnly', 'FullDiagnostic', 'WerResearch')]
    [string]$ExpectedFeatureProfile = 'ShareReadOnly'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Join-Path $PSScriptRoot '..'
}
$repoRootFull = [IO.Path]::GetFullPath($RepoRoot)
$violations = [Collections.Generic.List[string]]::new()

function Read-RequiredText {
    param([Parameter(Mandatory)][string]$RelativePath)
    $path = Join-Path $repoRootFull $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        $violations.Add("Required safety input is missing: $RelativePath")
        return ''
    }
    return Get-Content -LiteralPath $path -Raw
}

function Require-Literal {
    param([string]$Text, [string]$Literal, [string]$Description)
    if ($Text.IndexOf($Literal, [StringComparison]::Ordinal) -lt 0) {
        $violations.Add("$Description is missing: $Literal")
    }
}

function Reject-Pattern {
    param([string]$Text, [string]$Pattern, [string]$Description)
    if ($Text -match $Pattern) { $violations.Add($Description) }
}

$buildProps = Read-RequiredText 'Directory.Build.props'
$capabilities = Read-RequiredText 'src\PCCrashDiagnostic.Contracts\ProductCapabilities.cs'
$shareFilter = Read-RequiredText 'PCCrashDiagnostic.Share.slnf'
$fullFilter = Read-RequiredText 'PCCrashDiagnostic.Full.slnf'
$shareProjectGraph = @(
    Read-RequiredText 'src\PCCrashDiagnostic.Contracts\PCCrashDiagnostic.Contracts.csproj'
    Read-RequiredText 'src\PCCrashDiagnostic.Core\PCCrashDiagnostic.Core.csproj'
    Read-RequiredText 'src\PCCrashDiagnostic.LocalTools\PCCrashDiagnostic.LocalTools.csproj'
    Read-RequiredText 'src\PCCrashDiagnostic.App\PCCrashDiagnostic.App.csproj'
    Read-RequiredText 'tests\PCCrashDiagnostic.Share.Tests\PCCrashDiagnostic.Share.Tests.csproj'
) -join "`n"
$appManifest = Read-RequiredText 'src\PCCrashDiagnostic.App\app.manifest'
$buildRelease = Read-RequiredText 'tools\Build-Release.ps1'
$verifyRelease = Read-RequiredText 'tools\Verify-Release.ps1'
$finalizeRelease = Read-RequiredText 'tools\Finalize-Release.ps1'
$buildManifestSchema = Read-RequiredText '.config\release\BuildManifest.schema.json'
$releaseManifestSchema = Read-RequiredText '.config\release\ReleaseManifest.schema.json'
$testEvidenceSchema = Read-RequiredText '.config\release\TestEvidence.schema.json'
$vmEvidenceSchema = Read-RequiredText '.config\release\ExactPackageVmEvidence.schema.json'
$toolManifest = Read-RequiredText '.config\dotnet-tools.json'
$signPathArtifact = Read-RequiredText '.config\signpath\share-read-only-artifact-configuration.xml'
$signPathSourcePolicy = Read-RequiredText '.config\signpath\share-read-only-source-policy.template.yml'
$signingWorkflow = Read-RequiredText '.github\workflows\signpath-share-read-only.yml'
$ciWorkflow = Read-RequiredText '.github\workflows\ci.yml'
foreach ($schemaText in @($buildManifestSchema, $releaseManifestSchema, $testEvidenceSchema, $vmEvidenceSchema, $toolManifest)) {
    try { $schemaText | ConvertFrom-Json | Out-Null } catch { $violations.Add("Release JSON schema does not parse: $($_.Exception.Message)") }
}
try { [xml]$signPathArtifact | Out-Null } catch { $violations.Add("SignPath artifact configuration does not parse: $($_.Exception.Message)") }

foreach ($script in Get-ChildItem -LiteralPath (Join-Path $repoRootFull 'tools') -Filter '*.ps1' -File) {
    $tokens = $null
    $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$parseErrors)
    foreach ($parseError in @($parseErrors)) {
        $violations.Add("PowerShell syntax error in $($script.Name): $($parseError.Message)")
    }
}

foreach ($contract in @(
        @($buildProps, '<PCCrashDiagnosticVersion Condition="''$(PCCrashDiagnosticVersion)'' == ''''">3.2.0-beta.1</PCCrashDiagnosticVersion>', 'fixed release version'),
        @($buildProps, '<PCCrashDiagnosticFeatureProfile Condition="''$(PCCrashDiagnosticFeatureProfile)'' == ''''">ShareReadOnly</PCCrashDiagnosticFeatureProfile>', 'safe default profile'),
        @($buildProps, '<PCCrashDiagnosticWerLocalDumpCapture Condition="''$(PCCrashDiagnosticWerLocalDumpCapture)'' == ''''">Disabled</PCCrashDiagnosticWerLocalDumpCapture>', 'safe WER default'),
        @($buildProps, '<PCCrashDiagnosticRuntimeVersion Condition="''$(PCCrashDiagnosticRuntimeVersion)'' == ''''">10.0.11</PCCrashDiagnosticRuntimeVersion>', 'serviced runtime pin'),
        @($buildProps, '''$(PCCrashDiagnosticFeatureProfile)'' == ''WerResearch'' and ''$(PCCrashDiagnosticWerLocalDumpCapture)'' == ''Enabled''', 'WER compile-time isolation'),
        @($capabilities, 'if (capabilities.Profile == ProductFeatureProfile.ShareReadOnly && capabilities.HasAnyPrivilegedCapability)', 'ShareReadOnly invariant'),
        @($capabilities, 'ElevatedHelper: privileged', 'capability construction'),
        @($appManifest, 'requestedExecutionLevel level="asInvoker"', 'standard-user application manifest'),
        @($shareFilter, 'src/PCCrashDiagnostic.App/PCCrashDiagnostic.App.csproj', 'ShareReadOnly application graph'),
        @($buildRelease, "[ValidateSet('ShareReadOnly')][string]`$FeatureProfile = 'ShareReadOnly'", 'release profile allowlist'),
        @($buildRelease, "`$solutionPath = Join-Path `$repoRoot 'PCCrashDiagnostic.Share.slnf'", 'release solution filter'),
        @($buildRelease, "`$mainExecutableName = 'PCCrashDiagnostic.exe'", 'single executable identity'),
        @($buildRelease, "`$requiredRuntimeVersion = '10.0.11'", 'release runtime pin'),
        @($buildRelease, 'smokeMarker.RuntimeVersion', 'runtime smoke assertion'),
        @($buildRelease, 'PrivilegedOperationsEnabled = $false', 'runtime manifest privilege gate'),
        @($buildRelease, 'ElevatedHelperIncluded = $false', 'runtime manifest helper gate'),
        @($buildRelease, 'WerLocalDumpCaptureEnabled = $false', 'runtime manifest WER gate'),
        @($buildRelease, 'ManifestSchemaVersion = 3', 'release manifest schema'),
        @($buildRelease, 'Capabilities = $capabilities', 'compiled capability manifest'),
        @($buildRelease, "Elevation = 'None'", 'no-elevation manifest state'),
        @($buildRelease, "Network = 'ConsentOnlyMicrosoftSymbols'", 'consent-only network manifest state'),
        @($buildManifestSchema, '"ManifestSchemaVersion": { "const": 3 }', 'build-manifest schema 3 contract'),
        @($releaseManifestSchema, '"ManifestSchemaVersion": { "const": 3 }', 'release-manifest schema 3 contract'),
        @($vmEvidenceSchema, '"ReleaseManifestSha256": { "$ref": "#/$defs/sha256" }', 'VM evidence release-manifest binding'),
        @($vmEvidenceSchema, '"Rfc3161TimestampVerified": { "const": true }', 'VM evidence RFC 3161 gate'),
        @($signPathArtifact, '<parameter name="product-version" required="true" />', 'SignPath ProductVersion parameter'),
        @($signPathArtifact, 'product-version="${product-version}"', 'SignPath ProductVersion restriction'),
        @($signPathSourcePolicy, 'github-policies:', 'SignPath GitHub source-policy root'),
        @($signPathSourcePolicy, 'require_github_hosted: true', 'SignPath GitHub-hosted runner policy'),
        @($signPathSourcePolicy, 'disallow_reruns: true', 'SignPath rerun policy'),
        @($signingWorkflow, 'if ($env:GITHUB_REF -cne', 'SignPath tag gate environment binding'),
        @($signingWorkflow, 'product-version: "${{ steps.stage.outputs.product_version }}"', 'SignPath ProductVersion workflow binding'),
        @($signingWorkflow, '-ExpectedSignerSubject $env:EXPECTED_SIGNER_SUBJECT', 'SignPath signer-subject environment binding'),
        @($ciWorkflow, '-warnaserror:NU1901,NU1902,NU1903,NU1904', 'CI fail-closed NuGet vulnerability audit'),
        @($ciWorkflow, './tools/Test-PublicArtifactAudit.ps1', 'CI public IL/resource audit'),
        @($ciWorkflow, '-DependencyVulnerabilityAuditPassed $true', 'CI sanitized vulnerability-audit evidence'),
        @($buildRelease, 'ShareApproved = $false', 'external share gate'),
        @($buildRelease, 'authenticodePolicy.Rfc3161TimestampVerified', 'RFC 3161 signature gate'),
        @($buildRelease, 'ExactPackageVmEvidenceVerified = $false', 'external VM gate'),
        @($verifyRelease, "Assert-Equal 'PCCrashDiagnostic.exe' `$manifest.ExecutableName 'Executable name'", 'verifier executable identity'),
        @($verifyRelease, 'ShareReadOnly runtime must contain exactly one executable and no elevated helper.', 'verifier helper exclusion'),
        @($verifyRelease, "throw 'This artifact remains a candidate and is not approved for sharing.'", 'verifier share gate'),
        @($finalizeRelease, '[string]$evidence.SignerThumbprint -cne [string]$manifest.SignerThumbprint', 'VM signer binding'),
        @($finalizeRelease, "[string]`$evidence.TimestampAuthority -cne [string]`$manifest.TimestampSubject", 'VM timestamp-authority binding')
    )) {
    Require-Literal -Text $contract[0] -Literal $contract[1] -Description $contract[2]
}

if ($ExpectedFeatureProfile -ceq 'ShareReadOnly') {
    Reject-Pattern -Text ($shareFilter + "`n" + $shareProjectGraph) `
        -Pattern '(?i)PCCrashDiagnostic\.(?:Privileged|ElevatedHelper)|BF6CrashDiagnostic\.App' `
        -Description 'The ShareReadOnly solution/project graph references a privileged or legacy application project.'
    Require-Literal -Text $fullFilter -Literal 'src/PCCrashDiagnostic.Privileged/PCCrashDiagnostic.Privileged.csproj' -Description 'FullDiagnostic privileged graph'
    Require-Literal -Text $toolManifest -Literal '"version": "4.1.5"' -Description 'pinned Microsoft SBOM Tool'
    $capabilityBindings = [ordered]@{
        ElevatedHelper = 'privileged'
        SettingsApply = 'privileged'
        SettingsRestore = 'privileged'
        WerLocalDumps = 'wer'
        ProtectedEvidence = 'privileged'
        ProtectedDumpStaging = 'privileged'
        DumpPackaging = 'privileged'
    }
    foreach ($privilegedCapability in $capabilityBindings.Keys) {
        $binding = $capabilityBindings[$privilegedCapability]
        if ($capabilities -notmatch "(?m)^\s*${privilegedCapability}:\s*${binding}[,);]*\s*$") {
            $violations.Add("$privilegedCapability must derive only from its restricted profile flag")
        }
    }
    Reject-Pattern -Text $buildRelease -Pattern '(?i)Start-Process[^\r\n]+-Verb\s+RunAs' `
        -Description 'Build-Release.ps1 must never elevate during release construction.'
    Reject-Pattern -Text $signingWorkflow -Pattern '\$\{\{\s*github\.ref\s*\}\}' `
        -Description 'The signing workflow must not interpolate the selected Git ref into PowerShell source.'
}

$releaseToolText = $buildRelease + "`n" + $verifyRelease + "`n" + $finalizeRelease
foreach ($forbidden in @(
        @('(?i)\b(?:Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|curl(?:\.exe)?|wget(?:\.exe)?)\b', 'release tooling must not download inputs'),
        @('(?i)\b(?:Set-MpPreference|DisableRealtimeMonitoring|nointegritychecks|testsigning)\b', 'release tooling must not weaken security controls'),
        @('(?i)\b(?:sfc|dism|chkdsk|verifier)\.exe\b', 'release tooling must not invoke repair or Driver Verifier tools'),
        @('(?i)\b(?:shutdown\.exe|Restart-Computer|Stop-Computer)\b', 'release tooling must not reboot or shut down Windows'),
        @('(?i)\b(?:NtRaiseHardError|NotMyFault|CrashOnCtrlScroll|KeBugCheck)\b', 'release tooling must not create a deliberate crash')
    )) {
    Reject-Pattern -Text $releaseToolText -Pattern $forbidden[0] -Description $forbidden[1]
}

$workflowRoot = Join-Path $repoRootFull '.github\workflows'
if (Test-Path -LiteralPath $workflowRoot -PathType Container) {
    foreach ($workflow in Get-ChildItem -LiteralPath $workflowRoot -Filter '*.yml' -File) {
        $text = Get-Content -LiteralPath $workflow.FullName -Raw
        foreach ($match in [regex]::Matches($text, '(?m)^\s*uses:\s*([^\s#]+)')) {
            $reference = $match.Groups[1].Value
            if ($reference -notmatch '@[0-9a-f]{40}$') {
                $violations.Add("Workflow action is not pinned to a full commit SHA in $($workflow.Name): $reference")
            }
        }
        Reject-Pattern -Text $text -Pattern '(?i)\b(?:gh|github-cli)(?:\.exe)?\s+release\b|softprops/action-gh-release|ncipollo/release-action' `
            -Description "Workflow $($workflow.Name) must not publish a GitHub release."
        Reject-Pattern -Text $text -Pattern '(?im)^\s*(?:run:\s*)?git\s+push\b' `
            -Description "Workflow $($workflow.Name) must not push Git state."
    }
}

if ($violations.Count -ne 0) {
    throw ("Safety-boundary validation failed:`n - " + ($violations -join "`n - "))
}

Write-Host "Safety boundary passed for profile $ExpectedFeatureProfile." -ForegroundColor Green
Write-Host 'This is a static source/release-policy check; it is not exact-package VM evidence.'
