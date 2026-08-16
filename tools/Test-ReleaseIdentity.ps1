[CmdletBinding()]
param(
    [string]$RepoRoot,
    [switch]$RequireRepositoryIdentity,
    [switch]$RequireExactReleaseSource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepoRoot)) { $RepoRoot = Join-Path $PSScriptRoot '..' }
$repoRootFull = [IO.Path]::GetFullPath($RepoRoot)

function Read-RequiredText {
    param([Parameter(Mandatory)][string]$RelativePath)
    $path = Join-Path $repoRootFull $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required identity input is missing: $RelativePath" }
    return Get-Content -LiteralPath $path -Raw
}

function Assert-Contains {
    param([string]$Text, [string]$Literal, [string]$Description)
    if ($Text.IndexOf($Literal, [StringComparison]::Ordinal) -lt 0) {
        throw "$Description is missing required literal '$Literal'."
    }
}

foreach ($script in Get-ChildItem -LiteralPath (Join-Path $repoRootFull 'tools') -Filter '*.ps1' -File) {
    $tokens = $null
    $parseErrors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$parseErrors)
    if (@($parseErrors).Count -ne 0) { throw "PowerShell syntax error in $($script.Name): $($parseErrors[0].Message)" }
}

$propsText = Read-RequiredText 'Directory.Build.props'
$globalJsonText = Read-RequiredText 'global.json'
$capabilityText = Read-RequiredText 'src\PCCrashDiagnostic.Contracts\ProductCapabilities.cs'
$appProjectText = Read-RequiredText 'src\PCCrashDiagnostic.App\PCCrashDiagnostic.App.csproj'
$appManifestText = Read-RequiredText 'src\PCCrashDiagnostic.App\app.manifest'
$buildText = Read-RequiredText 'tools\Build-Release.ps1'
$verifyText = Read-RequiredText 'tools\Verify-Release.ps1'

[xml]$props = $propsText
$defaultVersion = [string](@($props.Project.PropertyGroup.PCCrashDiagnosticVersion)[0].InnerText)
$defaultProfile = [string](@($props.Project.PropertyGroup.PCCrashDiagnosticFeatureProfile)[0].InnerText)
$runtimeVersion = [string](@($props.Project.PropertyGroup.PCCrashDiagnosticRuntimeVersion)[0].InnerText)
if ($defaultVersion -cne '3.2.0-beta.1' -or $defaultProfile -cne 'ShareReadOnly' -or $runtimeVersion -cne '10.0.11') {
    throw "Default build identity must be 3.2.0-beta.1/ShareReadOnly/runtime 10.0.11; found '$defaultVersion/$defaultProfile/$runtimeVersion'."
}

$globalJson = $globalJsonText | ConvertFrom-Json
if ([string]$globalJson.sdk.version -cne '10.0.400') {
    throw "global.json must pin SDK 10.0.400; found '$($globalJson.sdk.version)'."
}
if ([string]$globalJson.sdk.rollForward -cne 'disable' -or [bool]$globalJson.sdk.allowPrerelease) {
    throw 'global.json must disable SDK roll-forward and prerelease SDK selection.'
}

foreach ($required in @(
        @($capabilityText, 'public const string Version = "3.2.0-beta.1";', 'compiled product version'),
        @($capabilityText, 'ProductCapabilities capabilities = Create(ProductFeatureProfile.ShareReadOnly, privileged: false, wer: false);', 'ShareReadOnly capability mapping'),
        @($appProjectText, '<AssemblyName>PCCrashDiagnostic</AssemblyName>', 'application assembly name'),
        @($appProjectText, '<Product>PC Crash Diagnostic</Product>', 'application product name'),
        @($appManifestText, 'version="3.2.0.0" name="PCCrashDiagnostic.ShareReadOnly"', 'application manifest version and profile identity'),
        @($appManifestText, 'requestedExecutionLevel level="asInvoker"', 'application execution level'),
        @($buildText, "`$requiredSdkVersion = '10.0.400'", 'release SDK identity'),
        @($buildText, "`$requiredRuntimeVersion = '10.0.11'", 'release runtime identity'),
        @($buildText, "`$sourceRepository = 'https://github.com/brads93/PCCrashDiagnostic'", 'release repository identity'),
        @($buildText, "[ValidateSet('ShareReadOnly')][string]`$FeatureProfile = 'ShareReadOnly'", 'release profile identity'),
        @($buildText, "`$sourcePackageRoot = 'PCCrashDiagnostic-source'", 'source archive identity'),
        @($buildText, "`$solutionPath = Join-Path `$repoRoot 'PCCrashDiagnostic.Share.slnf'", 'ShareReadOnly solution filter'),
        @($buildText, "`$mainExecutableName = 'PCCrashDiagnostic.exe'", 'runtime executable identity'),
        @($verifyText, "[ValidateSet('3.2.0-beta.1')][string]`$ExpectedVersion = '3.2.0-beta.1'", 'verifier version identity')
    )) {
    Assert-Contains -Text $required[0] -Literal $required[1] -Description $required[2]
}

$combined = $buildText + "`n" + $verifyText
foreach ($legacy in @('3.1.0-beta.1', '3.1.0-beta.2', 'PCCrashDiagnosticStage',
        'friend-beta', 'BF6CrashDiagnostic-source')) {
    if ($combined.IndexOf($legacy, [StringComparison]::Ordinal) -ge 0) {
        throw "Release tooling retains legacy active-release identity '$legacy'."
    }
}

if ($RequireRepositoryIdentity) {
    $git = Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $inside = (& $git.Source -C $repoRootFull rev-parse --is-inside-work-tree 2>$null) -join ''
    if ($LASTEXITCODE -ne 0 -or $inside.Trim() -cne 'true') { throw 'The workspace is not a Git work tree.' }
    $commit = ((& $git.Source -C $repoRootFull rev-parse HEAD) -join '').Trim()
    if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-fA-F]{40}$') { throw 'Git HEAD could not be resolved.' }
}
if ($RequireExactReleaseSource) {
    $git = Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $origin = ((& $git.Source -C $repoRootFull remote get-url origin 2>$null) -join '').Trim()
    if ($LASTEXITCODE -ne 0 -or $origin -cne 'https://github.com/brads93/PCCrashDiagnostic') {
        throw "Exact release origin must be https://github.com/brads93/PCCrashDiagnostic; found '$origin'."
    }
    $tag = ((& $git.Source -C $repoRootFull describe --tags --exact-match HEAD 2>$null) -join '').Trim()
    if ($LASTEXITCODE -ne 0 -or $tag -cne 'v3.2.0-beta.1') { throw 'Exact release source must be tag v3.2.0-beta.1.' }
}

Write-Host 'Release identity checks passed for PC Crash Diagnostic 3.2.0-beta.1 ShareReadOnly.' -ForegroundColor Green
