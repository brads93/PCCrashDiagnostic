[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TrxPath,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [ValidateSet('ShareReadOnly', 'FullDiagnostic', 'WerResearch')]
    [string]$FeatureProfile = 'ShareReadOnly',

    [ValidatePattern('^3\.2\.0-beta\.1$')]
    [string]$Version = '3.2.0-beta.1',

    [string]$SourceCommit,

    [ValidateSet('clean', 'dirty', 'unknown')]
    [string]$SourceTreeState = 'unknown',

    [bool]$SafetyBoundaryPassed = $true,

    [bool]$PackagedSmokePassed = $false,

    [bool]$DependencyVulnerabilityAuditPassed = $false,

    [Parameter(Mandatory)]
    [string]$PublicArtifactAuditPath,

    [DateTimeOffset]$GeneratedUtc = [DateTimeOffset]::UtcNow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$trxFull = [IO.Path]::GetFullPath($TrxPath)
if (-not (Test-Path -LiteralPath $trxFull -PathType Leaf)) {
    throw "TRX file not found: $trxFull"
}

[xml]$trx = Get-Content -LiteralPath $trxFull -Raw
$namespace = [Xml.XmlNamespaceManager]::new($trx.NameTable)
$namespace.AddNamespace('t', 'http://microsoft.com/schemas/VisualStudio/TeamTest/2010')
$counters = $trx.SelectSingleNode('/t:TestRun/t:ResultSummary/t:Counters', $namespace)
if ($null -eq $counters) {
    throw 'The TRX file does not contain ResultSummary/Counters.'
}

function Read-Counter {
    param([Parameter(Mandatory)][string]$Name)

    $attribute = $counters.Attributes[$Name]
    if ($null -eq $attribute) { return 0 }

    $value = 0
    if (-not [int]::TryParse($attribute.Value, [ref]$value) -or $value -lt 0) {
        throw "TRX counter '$Name' is invalid."
    }
    return $value
}

$summary = [ordered]@{
    Total = Read-Counter total
    Executed = Read-Counter executed
    Passed = Read-Counter passed
    Failed = Read-Counter failed
    Errors = Read-Counter error
    Timeouts = Read-Counter timeout
    Aborted = Read-Counter aborted
    Inconclusive = Read-Counter inconclusive
    Skipped = Read-Counter notExecuted
}

if ($summary.Failed -ne 0 -or $summary.Errors -ne 0 -or
    $summary.Timeouts -ne 0 -or $summary.Aborted -ne 0) {
    throw 'The TRX file contains failed, errored, timed-out, or aborted tests.'
}
if ($summary.Total -le 0 -or $summary.Passed -le 0) {
    throw 'The TRX file does not establish that any test passed.'
}
$publicAuditFull = [IO.Path]::GetFullPath($PublicArtifactAuditPath)
if (-not (Test-Path -LiteralPath $publicAuditFull -PathType Leaf)) { throw "Public artifact audit not found: $publicAuditFull" }
$publicAuditText = Get-Content -LiteralPath $publicAuditFull -Raw
if ($publicAuditText -match '(?i)[A-Z]:\\|\\Users\\|/home/') { throw 'Public artifact audit contains an absolute local path.' }
$publicAudit = $publicAuditText | ConvertFrom-Json
if (-not $DependencyVulnerabilityAuditPassed -or -not [bool]$publicAudit.PublicIlAndResourceAuditPassed -or
    [int]$publicAudit.ForbiddenFindingCount -ne 0 -or [int]$publicAudit.PublishedExecutableCount -ne 1) {
    throw 'Required dependency vulnerability or public IL/resource audit did not pass.'
}

$evidence = [ordered]@{
    SchemaVersion = 1
    Product = 'PC Crash Diagnostic'
    Version = $Version
    FeatureProfile = $FeatureProfile
    GeneratedUtc = $GeneratedUtc.ToUniversalTime().ToString('o')
    SourceCommit = if ([string]::IsNullOrWhiteSpace($SourceCommit)) { $null } else { $SourceCommit.ToLowerInvariant() }
    SourceTreeState = $SourceTreeState
    TestResults = $summary
    SafetyBoundaryPassed = $SafetyBoundaryPassed
    PackagedSmokePassed = $PackagedSmokePassed
    ReleaseAudits = [ordered]@{
        DependencyVulnerabilityAuditPassed = $DependencyVulnerabilityAuditPassed
        PublicIlAndResourceAuditPassed = [bool]$publicAudit.PublicIlAndResourceAuditPassed
        AssemblyCount = [int]$publicAudit.AssemblyCount
        AssemblyReferenceCount = [int]$publicAudit.AssemblyReferenceCount
        TypeReferenceCount = [int]$publicAudit.TypeReferenceCount
        ManifestResourceCount = [int]$publicAudit.ManifestResourceCount
        PublishedExecutableCount = [int]$publicAudit.PublishedExecutableCount
        ForbiddenFindingCount = [int]$publicAudit.ForbiddenFindingCount
    }
    RawTrx = [ordered]@{
        PubliclyPackaged = $false
        FileName = [IO.Path]::GetFileName($trxFull)
        Sha256 = (Get-FileHash -LiteralPath $trxFull -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    Privacy = 'Test names, machine names, usernames, and absolute paths are intentionally excluded. The raw TRX remains a restricted CI artifact.'
}

$outputFull = [IO.Path]::GetFullPath($OutputPath)
$parent = Split-Path -Parent $outputFull
if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
}

$json = ($evidence | ConvertTo-Json -Depth 8).Replace("`r`n", "`n").TrimEnd() + "`n"
[IO.File]::WriteAllText($outputFull, $json, [Text.UTF8Encoding]::new($false))
Write-Host "Sanitized test evidence written: $outputFull"
