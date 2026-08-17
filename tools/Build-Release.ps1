[CmdletBinding()]
param(
    [ValidateSet('Release')][string]$Configuration = 'Release',
    [ValidateSet('win-x64')][string]$RuntimeIdentifier = 'win-x64',
    [string]$OutputRoot,
    [string]$DotNetPath = 'dotnet',
    [string]$SbomRuntimeHostPath,
    [string]$BuildTimestampUtc,
    [ValidateSet('3.2.0-beta.1')][string]$Version = '3.2.0-beta.1',
    [ValidateSet('ShareReadOnly')][string]$FeatureProfile = 'ShareReadOnly',
    [string]$PrebuiltExecutable,
    [ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$ExpectedSignerThumbprint,
    [string]$ExpectedSignerSubject,
    [string]$ExpectedSignerIssuer,
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$UnsignedSigningInputSha256,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')][string]$SigningInputArtifactId,
    [bool]$ReproducibleBuildVerified = $false,
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$ReproducibilityPeerSha256,
    [string]$BuilderId = 'local:unattested',
    [string]$InvocationId,
    [switch]$RequireExactTag,
    [switch]$AllowDirtyControlledBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$requiredSdkVersion = '10.0.400'
$requiredRuntimeVersion = '10.0.11'
$productName = 'PC Crash Diagnostic'
$sourceRepository = 'https://github.com/brads93/PCCrashDiagnostic'
$profileSlug = 'share-read-only'
$assetPrefix = 'PCCrashDiagnostic'
$sourcePackageRoot = 'PCCrashDiagnostic-source'
$mainExecutableName = 'PCCrashDiagnostic.exe'
$solutionPath = Join-Path $repoRoot 'PCCrashDiagnostic.Share.slnf'
$appProjectPath = Join-Path $repoRoot 'src\PCCrashDiagnostic.App\PCCrashDiagnostic.App.csproj'
$verifyScriptPath = Join-Path $PSScriptRoot 'Verify-Release.ps1'
$safetyScriptPath = Join-Path $PSScriptRoot 'Test-SafetyBoundary.ps1'
$identityScriptPath = Join-Path $PSScriptRoot 'Test-ReleaseIdentity.ps1'
$testEvidenceScriptPath = Join-Path $PSScriptRoot 'New-TestEvidence.ps1'
$sbomScriptPath = Join-Path $PSScriptRoot 'New-ReleaseSbom.ps1'
$provenanceScriptPath = Join-Path $PSScriptRoot 'New-ReleaseProvenance.ps1'
$authenticodePolicyScriptPath = Join-Path $PSScriptRoot 'Test-AuthenticodePolicy.ps1'
$publicArtifactAuditScriptPath = Join-Path $PSScriptRoot 'Test-PublicArtifactAudit.ps1'
$toolManifestPath = Join-Path $repoRoot '.config\dotnet-tools.json'

foreach ($required in @($solutionPath, $appProjectPath, $verifyScriptPath, $safetyScriptPath, $identityScriptPath,
        $testEvidenceScriptPath, $sbomScriptPath, $provenanceScriptPath, $authenticodePolicyScriptPath,
        $publicArtifactAuditScriptPath, $toolManifestPath)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) { throw "Required release input not found: $required" }
}
if ([string]::IsNullOrWhiteSpace($OutputRoot)) { $OutputRoot = Join-Path $repoRoot 'artifacts\candidates' }
if ([string]::IsNullOrWhiteSpace($PrebuiltExecutable) -and
    (-not [string]::IsNullOrWhiteSpace($ExpectedSignerThumbprint) -or
     -not [string]::IsNullOrWhiteSpace($ExpectedSignerSubject) -or
     -not [string]::IsNullOrWhiteSpace($ExpectedSignerIssuer))) {
    throw 'Signer-policy values are valid only with -PrebuiltExecutable.'
}
if (-not [string]::IsNullOrWhiteSpace($PrebuiltExecutable) -and
    ([string]::IsNullOrWhiteSpace($ExpectedSignerThumbprint) -or
     [string]::IsNullOrWhiteSpace($ExpectedSignerSubject) -or
     [string]::IsNullOrWhiteSpace($ExpectedSignerIssuer))) {
    throw 'A prebuilt signed executable requires exact signer thumbprint, subject, and issuer policy values.'
}
if (-not [string]::IsNullOrWhiteSpace($PrebuiltExecutable) -and
    ([string]::IsNullOrWhiteSpace($UnsignedSigningInputSha256) -or [string]::IsNullOrWhiteSpace($SigningInputArtifactId))) {
    throw 'A prebuilt signed executable requires its unsigned signing-input SHA-256 and signing artifact ID.'
}
if ([string]::IsNullOrWhiteSpace($PrebuiltExecutable) -and
    (-not [string]::IsNullOrWhiteSpace($UnsignedSigningInputSha256) -or -not [string]::IsNullOrWhiteSpace($SigningInputArtifactId) -or
     $ReproducibleBuildVerified -or -not [string]::IsNullOrWhiteSpace($ReproducibilityPeerSha256))) {
    throw 'Signing-input and reproducibility identity are valid only with -PrebuiltExecutable.'
}
if (-not [string]::IsNullOrWhiteSpace($PrebuiltExecutable) -and
    (-not $ReproducibleBuildVerified -or [string]::IsNullOrWhiteSpace($ReproducibilityPeerSha256) -or
     $ReproducibilityPeerSha256.ToLowerInvariant() -cne $UnsignedSigningInputSha256.ToLowerInvariant())) {
    throw 'A signed candidate requires two matching unsigned builds and their common signing-input SHA-256.'
}
if (-not [string]::IsNullOrWhiteSpace($PrebuiltExecutable) -and $AllowDirtyControlledBuild) {
    throw 'A signed candidate cannot be finalized from a dirty source tree.'
}

if (Test-Path -LiteralPath $DotNetPath -PathType Leaf) {
    $resolvedDotNet = (Resolve-Path -LiteralPath $DotNetPath).Path
} else {
    $dotnet = Get-Command $DotNetPath -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $dotnet) { throw "Could not locate '$DotNetPath'." }
    $resolvedDotNet = $dotnet.Source
}

function Invoke-DotNet {
    param([Parameter(Mandatory)][string[]]$Arguments)
    & $resolvedDotNet @Arguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet $($Arguments -join ' ') exited with code $LASTEXITCODE." }
}
function Get-Sha256 {
    param([Parameter(Mandatory)][string]$LiteralPath)
    return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Write-Utf8NoBom {
    param([Parameter(Mandatory)][string]$LiteralPath, [Parameter(Mandatory)][string]$Content)
    $normalized = $Content.Replace("`r`n", "`n").TrimEnd([char[]]"`r`n") + "`n"
    [IO.File]::WriteAllText($LiteralPath, $normalized, [Text.UTF8Encoding]::new($false))
}
function Resolve-BuildTime {
    if (-not [string]::IsNullOrWhiteSpace($BuildTimestampUtc)) {
        $parsed = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse($BuildTimestampUtc, [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
            throw 'BuildTimestampUtc must be an ISO-8601 timestamp.'
        }
        return $parsed.ToUniversalTime()
    }
    if (-not [string]::IsNullOrWhiteSpace($env:SOURCE_DATE_EPOCH)) {
        $seconds = [long]0
        if (-not [long]::TryParse($env:SOURCE_DATE_EPOCH, [ref]$seconds) -or $seconds -lt 0) {
            throw 'SOURCE_DATE_EPOCH must be a non-negative integer.'
        }
        return [DateTimeOffset]::FromUnixTimeSeconds($seconds)
    }
    return [DateTimeOffset]::UtcNow
}
function Assert-NoReparsePoint {
    param([Parameter(Mandatory)][string]$LiteralPath)
    $current = [IO.Path]::GetFullPath($LiteralPath)
    while (-not [string]::IsNullOrWhiteSpace($current)) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Release input traverses a reparse point: $current" }
        }
        $parent = Split-Path -Parent $current
        if ($parent -ceq $current) { break }
        $current = $parent
    }
}
function New-DeterministicZip {
    param([Parameter(Mandatory)][object[]]$Files, [Parameter(Mandatory)][string]$DestinationPath,
        [Parameter(Mandatory)][DateTimeOffset]$EntryTimestamp)
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zipTime = $EntryTimestamp.ToUniversalTime()
    $minimum = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
    $maximum = [DateTimeOffset]::new(2107, 12, 31, 23, 59, 58, [TimeSpan]::Zero)
    if ($zipTime -lt $minimum) { $zipTime = $minimum }
    if ($zipTime -gt $maximum) { $zipTime = $maximum }
    $zipTime = $zipTime.AddSeconds(-($zipTime.Second % 2)).AddTicks(-($zipTime.Ticks % [TimeSpan]::TicksPerSecond))
    $stream = [IO.File]::Open($DestinationPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            foreach ($file in @($Files | Sort-Object EntryName)) {
                $entryName = ([string]$file.EntryName).Replace('\', '/')
                $segments = @($entryName.Split('/'))
                if ([string]::IsNullOrWhiteSpace($entryName) -or $entryName.StartsWith('/') -or $entryName.Contains(':') -or
                    $segments.Count -eq 0 -or @($segments | Where-Object { [string]::IsNullOrWhiteSpace($_) -or $_ -in @('.', '..') }).Count -ne 0 -or
                    $entryName.IndexOfAny([char[]]@(0, 10, 13)) -ge 0) { throw "Unsafe ZIP entry name: $entryName" }
                $entry = $archive.CreateEntry($entryName, [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $zipTime
                $input = [IO.File]::OpenRead([string]$file.FullName)
                try { $output = $entry.Open(); try { $input.CopyTo($output) } finally { $output.Dispose() } } finally { $input.Dispose() }
            }
        } finally { $archive.Dispose() }
    } finally { $stream.Dispose() }
}
function Get-GitMetadata {
    $git = Get-Command git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $git) { throw 'Git is required for a v3.2 release candidate.' }
    $inside = & $git.Source -C $repoRoot rev-parse --is-inside-work-tree 2>$null
    if ($LASTEXITCODE -ne 0 -or ($inside -join '').Trim() -cne 'true') { throw 'The source tree is not a Git work tree.' }
    $commit = ((& $git.Source -C $repoRoot rev-parse HEAD) -join '').Trim().ToLowerInvariant()
    $tree = ((& $git.Source -C $repoRoot rev-parse 'HEAD^{tree}') -join '').Trim().ToLowerInvariant()
    if ($commit -notmatch '^[0-9a-f]{40}$' -or $tree -notmatch '^[0-9a-f]{40}$') { throw 'Could not resolve Git commit/tree identity.' }
    $status = @(& $git.Source -C $repoRoot status --porcelain --untracked-files=normal)
    if ($LASTEXITCODE -ne 0) { throw 'Could not determine source-tree state.' }
    $state = if ($status.Count -eq 0) { 'clean' } else { 'dirty' }
    if ($state -ne 'clean' -and -not $AllowDirtyControlledBuild) {
        throw 'Release candidates require a clean Git tree. -AllowDirtyControlledBuild is only for an unsigned local test candidate.'
    }
    if ($state -ne 'clean' -and $AllowDirtyControlledBuild) {
        $untracked = @(& $git.Source -C $repoRoot ls-files --others --exclude-standard)
        if ($LASTEXITCODE -ne 0) { throw 'Could not enumerate untracked source files.' }
        if ($untracked.Count -ne 0) {
            throw '-AllowDirtyControlledBuild permits modified tracked files only. Track or remove every untracked file before building so the source ZIP can describe the compiled bytes.'
        }
    }
    $origin = ((& $git.Source -C $repoRoot remote get-url origin 2>$null) -join '').Trim()
    $originResolved = $LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($origin)
    $originVerified = $originResolved -and $origin -ceq $sourceRepository
    $tag = ((& $git.Source -C $repoRoot describe --tags --exact-match HEAD 2>$null) -join '').Trim()
    $tagVerified = $LASTEXITCODE -eq 0 -and $tag -ceq "v$Version"
    if ($RequireExactTag -or $signedInput) {
        if (-not $originVerified) { throw "Signed releases require exact origin $sourceRepository; found '$origin'." }
        if (-not $tagVerified) { throw "The signed candidate must be built from exact tag v$Version." }
    }
    return [pscustomobject]@{
        Git = $git.Source; Commit = $commit; Tree = $tree; State = $state
        Repository = $sourceRepository; OriginVerified = $originVerified
        Tag = if ($tagVerified) { $tag } else { $null }; TagVerified = $tagVerified
    }
}
function Get-TrackedSourceFiles {
    param([Parameter(Mandatory)]$GitMetadata)
    $paths = @(& $GitMetadata.Git -C $repoRoot ls-files)
    if ($LASTEXITCODE -ne 0 -or $paths.Count -eq 0) { throw 'git ls-files returned no source files.' }
    $forbidden = @('.dmp', '.mdmp', '.hdmp', '.evtx', '.etl', '.pfx', '.p12', '.snk', '.key', '.cer',
        '.zip', '.trx', '.log', '.exe', '.dll', '.pdb', '.bin', '.nupkg', '.snupkg', '.user', '.suo')
    foreach ($relative in @($paths | Sort-Object -Unique)) {
        $normalized = ([string]$relative).Replace('\', '/')
        if ($normalized.StartsWith('/') -or $normalized.Contains('../') -or $normalized.Contains(':') -or
            $normalized -match '(^|/)(?:\.git|bin|obj|artifacts[^/]*)(/|$)') { throw "Tracked source path is unsafe: $normalized" }
        if ($forbidden -contains [IO.Path]::GetExtension($normalized).ToLowerInvariant()) { throw "Forbidden release extension: $normalized" }
        if ([IO.Path]::GetFileName($normalized) -match '^(?:\.env(?:\..+)?|secrets\.json)$') { throw "Forbidden private source filename: $normalized" }
        $full = [IO.Path]::GetFullPath((Join-Path $repoRoot $normalized))
        if (-not $full.StartsWith($repoRoot + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
            -not (Test-Path -LiteralPath $full -PathType Leaf)) { throw "Tracked source file is missing or escapes the repository: $normalized" }
        Assert-NoReparsePoint -LiteralPath $full
        [pscustomobject]@{ FullName = $full; EntryName = "$sourcePackageRoot/$normalized" }
    }
}
function Get-PayloadManifest {
    param([Parameter(Mandatory)][string]$Root)
    return @(Get-ChildItem -LiteralPath $Root -File -Recurse | Sort-Object FullName | ForEach-Object {
            [ordered]@{
                Path = $_.FullName.Substring($Root.Length).TrimStart([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar).Replace('\', '/')
                Size = $_.Length
                Sha256 = Get-Sha256 -LiteralPath $_.FullName
            }
        })
}

$signedInput = -not [string]::IsNullOrWhiteSpace($PrebuiltExecutable)
$buildTime = Resolve-BuildTime
$gitMetadata = Get-GitMetadata
$candidateState = if ($signedInput) { 'SignedAwaitingExactPackageVmEvidence' } elseif ($gitMetadata.State -eq 'clean') { 'UnsignedCandidate' } else { 'UnsignedDirtyLocalCandidate' }
$capabilities = [ordered]@{
    Profile = 'ShareReadOnly'
    StandardEvidence = $true
    TargetMonitoring = $true
    CrashReadinessReadOnly = $true
    AccessibleDumpMetadata = $true
    LocalHistory = $true
    SafeSummaryExport = $true
    TechnicalReportExport = $true
    RecycleBinDeletion = $true
    DumpChk = $true
    WinDbg = $true
    MicrosoftSymbolsAfterConsent = $true
    ElevatedHelper = $false
    SettingsApply = $false
    SettingsRestore = $false
    WerLocalDumps = $false
    ProtectedEvidence = $false
    ProtectedDumpStaging = $false
    DumpPackaging = $false
}
$releaseFolderName = "$Version-$profileSlug-$($candidateState.ToLowerInvariant())"
$outputRootFull = [IO.Path]::GetFullPath($OutputRoot)
$releaseRoot = Join-Path $outputRootFull $releaseFolderName
if (Test-Path -LiteralPath $releaseRoot) { throw "Candidate directory already exists: $releaseRoot" }
New-Item -ItemType Directory -Path $outputRootFull -Force | Out-Null
Assert-NoReparsePoint -LiteralPath $outputRootFull
$workingRoot = Join-Path $outputRootFull ('.work-' + [Guid]::NewGuid().ToString('N'))
$dotnetArtifacts = Join-Path $workingRoot 'dotnet-artifacts'
$publishRoot = Join-Path $workingRoot 'publish'
$runtimeStage = Join-Path $workingRoot 'runtime-stage'
$releaseStage = Join-Path $workingRoot 'candidate'
$testResults = Join-Path $workingRoot 'test-results'
New-Item -ItemType Directory -Path $workingRoot, $publishRoot, $runtimeStage, $releaseStage, $testResults -Force | Out-Null

try {
    $sdkVersion = ((& $resolvedDotNet --version) -join '').Trim()
    if ($LASTEXITCODE -ne 0 -or $sdkVersion -cne $requiredSdkVersion) { throw "The release requires .NET SDK $requiredSdkVersion exactly; found '$sdkVersion'." }
    Push-Location $repoRoot
    try {
        & $safetyScriptPath -RepoRoot $repoRoot -ExpectedFeatureProfile $FeatureProfile
        $identityParameters = @{ RepoRoot = $repoRoot; RequireRepositoryIdentity = $true }
        if ($signedInput -or $RequireExactTag) { $identityParameters.RequireExactReleaseSource = $true }
        & $identityScriptPath @identityParameters
        $properties = @("-p:PCCrashDiagnosticVersion=$Version", "-p:PCCrashDiagnosticFeatureProfile=$FeatureProfile",
            '-p:PCCrashDiagnosticWerLocalDumpCapture=Disabled', "-p:PCCrashDiagnosticRuntimeVersion=$requiredRuntimeVersion")
        Invoke-DotNet -Arguments @('tool', 'restore', '--tool-manifest', $toolManifestPath)
        Invoke-DotNet -Arguments (@('restore', $solutionPath, '--locked-mode', '--artifacts-path', $dotnetArtifacts) + $properties)
        Invoke-DotNet -Arguments (@('restore', $appProjectPath, '-r', $RuntimeIdentifier, '--locked-mode',
                '--artifacts-path', $dotnetArtifacts, '-p:NuGetAudit=true', '-p:NuGetAuditMode=all',
                '-p:NuGetAuditLevel=low', '-warnaserror:NU1901,NU1902,NU1903,NU1904') + $properties)
        Invoke-DotNet -Arguments (@('test', $solutionPath, '-c', $Configuration, '--no-restore', '--artifacts-path', $dotnetArtifacts,
                '--logger', 'trx;LogFileName=release-tests.trx', '--results-directory', $testResults) + $properties)
        if ($signedInput) {
            $signedFull = [IO.Path]::GetFullPath($PrebuiltExecutable)
            if (-not (Test-Path -LiteralPath $signedFull -PathType Leaf) -or [IO.Path]::GetFileName($signedFull) -cne $mainExecutableName) {
                throw "Prebuilt executable must be a file named $mainExecutableName."
            }
            Assert-NoReparsePoint -LiteralPath $signedFull
            Copy-Item -LiteralPath $signedFull -Destination (Join-Path $publishRoot $mainExecutableName)
        } else {
            $pathMap = "$repoRoot=/_/src%2C$workingRoot=/_/build"
            Invoke-DotNet -Arguments (@('publish', $appProjectPath, '-c', $Configuration, '-r', $RuntimeIdentifier,
                    '--self-contained', 'true', '--no-restore', '--artifacts-path', $dotnetArtifacts, '-o', $publishRoot,
                    '-p:PublishSingleFile=true', '-p:IncludeNativeLibrariesForSelfExtract=true', '-p:EnableCompressionInSingleFile=true',
                    '-p:PublishTrimmed=false', '-p:Deterministic=true', '-p:ContinuousIntegrationBuild=true', "-p:PathMap=$pathMap") + $properties)
        }
    } finally { Pop-Location }

    $publishedExe = Join-Path $publishRoot $mainExecutableName
    if (-not (Test-Path -LiteralPath $publishedExe -PathType Leaf)) { throw "Publish did not create $mainExecutableName." }
    if (@(Get-ChildItem -LiteralPath $publishRoot -Filter '*.exe' -File | Where-Object Name -cne $mainExecutableName).Count -ne 0 -or
        (Test-Path -LiteralPath (Join-Path $publishRoot 'PCCrashDiagnostic.ElevatedHelper.exe'))) {
        throw 'The ShareReadOnly publish output contains an elevated helper or unexpected executable.'
    }
    if ($signedInput) {
        $authenticodePolicy = & $authenticodePolicyScriptPath -ExecutablePath $publishedExe -ExpectedState Signed `
            -ExpectedSignerThumbprint $ExpectedSignerThumbprint -ExpectedSignerSubject $ExpectedSignerSubject `
            -ExpectedSignerIssuer $ExpectedSignerIssuer -RequireRfc3161
    } else {
        $authenticodePolicy = & $authenticodePolicyScriptPath -ExecutablePath $publishedExe -ExpectedState Unsigned
    }
    if ($null -eq $authenticodePolicy -or -not [bool]$authenticodePolicy.MetadataVerified) {
        throw 'Executable signature/metadata policy did not return a verified result.'
    }

    Copy-Item -LiteralPath $publishedExe -Destination (Join-Path $runtimeStage $mainExecutableName)
    foreach ($name in @('00-START-HERE.txt', 'README.md', 'LICENSE', 'PRIVACY.md', 'SECURITY.md', 'THIRD_PARTY_NOTICES.md',
            'CHANGELOG.md', 'CONTRIBUTING.md', 'CODE_SIGNING_POLICY.md')) {
        $source = Join-Path $repoRoot $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Required runtime document missing: $name" }
        Copy-Item -LiteralPath $source -Destination (Join-Path $runtimeStage $name)
    }
    $runtimeDocs = Join-Path $runtimeStage 'docs'; $runtimeLicenses = Join-Path $runtimeStage 'licenses'
    New-Item -ItemType Directory -Path $runtimeDocs, $runtimeLicenses -Force | Out-Null
    foreach ($name in @('REPORT_FORMAT.md', 'BUILD_PROFILES.md', 'SUPPORT_SUMMARY.md', 'RELEASE_PROCESS.md', 'EXACT_PACKAGE_VM_CHECKLIST.md')) {
        Copy-Item -LiteralPath (Join-Path $repoRoot "docs\$name") -Destination (Join-Path $runtimeDocs $name)
    }
    foreach ($name in @('DOTNET-LIBRARY-LICENSE.txt', 'DOTNET-RUNTIME-MIT-LICENSE.txt', 'DOTNET-RUNTIME-THIRD-PARTY-NOTICES.txt',
            'DOTNET-WINDOWS-LICENSE-INFORMATION.md', 'DOTNET-WPF-MIT-LICENSE.txt', 'DOTNET-WPF-THIRD-PARTY-NOTICES.txt', 'WINDOWS-SDK-LICENSE.md')) {
        Copy-Item -LiteralPath (Join-Path $repoRoot "licenses\$name") -Destination (Join-Path $runtimeLicenses $name)
    }

    $smokeRoot = Join-Path $workingRoot 'smoke-data'; New-Item -ItemType Directory -Path $smokeRoot -Force | Out-Null
    $smoke = [Diagnostics.ProcessStartInfo]::new(); $smoke.FileName = $publishedExe
    $smoke.Arguments = "--smoke-test --data-root `"$smokeRoot`""; $smoke.UseShellExecute = $false; $smoke.CreateNoWindow = $true
    $process = [Diagnostics.Process]::Start($smoke)
    if ($null -eq $process) { throw 'Could not start the ShareReadOnly smoke test.' }
    try {
        if (-not $process.WaitForExit(60000)) { $process.Kill(); throw 'ShareReadOnly smoke test timed out.' }
        if ($process.ExitCode -ne 0) { throw "ShareReadOnly smoke test exited with code $($process.ExitCode)." }
    } finally { $process.Dispose() }
    $smokeMarkerPath = Join-Path $smokeRoot 'smoke-test.json'
    if (-not (Test-Path -LiteralPath $smokeMarkerPath -PathType Leaf)) { throw 'Smoke test did not create smoke-test.json.' }
    $smokeMarker = Get-Content -LiteralPath $smokeMarkerPath -Raw | ConvertFrom-Json
    if ([string]$smokeMarker.Status -cne 'passed' -or [string]$smokeMarker.ToolVersion -cne $Version -or
        [string]$smokeMarker.FeatureProfile -cne $FeatureProfile -or [bool]$smokeMarker.PrivilegedOperationsEnabled) {
        throw 'Smoke marker does not establish the ShareReadOnly build identity.'
    }
    if ([string]$smokeMarker.RuntimeVersion -cne $requiredRuntimeVersion) {
        throw "Smoke marker does not establish the required .NET runtime $requiredRuntimeVersion."
    }

    $publicArtifactAuditPath = Join-Path $testResults 'public-artifact-audit.json'
    & $publicArtifactAuditScriptPath -RestoreArtifactsRoot $dotnetArtifacts -PublishRoot $publishRoot `
        -OutputPath $publicArtifactAuditPath
    $testEvidencePath = Join-Path $runtimeStage 'TestEvidence.json'
    & $testEvidenceScriptPath -TrxPath (Join-Path $testResults 'release-tests.trx') -OutputPath $testEvidencePath `
        -FeatureProfile $FeatureProfile -Version $Version -SourceCommit $gitMetadata.Commit -SourceTreeState $gitMetadata.State `
        -SafetyBoundaryPassed $true -PackagedSmokePassed $true -DependencyVulnerabilityAuditPassed $true `
        -PublicArtifactAuditPath $publicArtifactAuditPath -GeneratedUtc $buildTime
    $sbomPath = Join-Path $runtimeStage 'SBOM.spdx.json'
    $sbomParameters = @{
        RepoRoot = $repoRoot; PayloadRoot = $runtimeStage; RestoreArtifactsRoot = $dotnetArtifacts
        DotNetPath = $resolvedDotNet; OutputPath = $sbomPath; FeatureProfile = $FeatureProfile
        Version = $Version; SourceCommit = $gitMetadata.Commit; GeneratedUtc = $buildTime
    }
    if (-not [string]::IsNullOrWhiteSpace($SbomRuntimeHostPath)) {
        $sbomParameters.SbomRuntimeHostPath = $SbomRuntimeHostPath
    }
    & $sbomScriptPath @sbomParameters
    $provenancePath = Join-Path $runtimeStage 'Provenance.intoto.json'
    $provenanceParameters = @{
        RepoRoot = $repoRoot; SubjectPaths = @($publishedExe, $testEvidencePath, $sbomPath)
        OutputPath = $provenancePath; FeatureProfile = $FeatureProfile; Version = $Version; BuilderId = $BuilderId
        InvocationId = $InvocationId; AuthenticodeVerified = [bool]$signedInput
        Rfc3161TimestampVerified = [bool]$authenticodePolicy.Rfc3161TimestampVerified
        ExactPackageVmEvidenceVerified = $false; ReproducibleBuildVerified = $ReproducibleBuildVerified
        SourceRepository = $sourceRepository; SourceOriginVerified = $gitMetadata.OriginVerified
        SourceTagVerified = $gitMetadata.TagVerified; ExpectedSourceCommit = $gitMetadata.Commit
        ExpectedSourceTree = $gitMetadata.Tree; ExpectedSourceTreeState = $gitMetadata.State; GeneratedUtc = $buildTime
    }
    if (-not [string]::IsNullOrWhiteSpace($gitMetadata.Tag)) {
        $provenanceParameters.SourceTag = $gitMetadata.Tag
    }
    if ($signedInput) {
        $provenanceParameters.UnsignedSigningInputSha256 = $UnsignedSigningInputSha256
        $provenanceParameters.SigningInputArtifactId = $SigningInputArtifactId
        $provenanceParameters.ReproducibilityPeerSha256 = $ReproducibilityPeerSha256
    }
    & $provenanceScriptPath @provenanceParameters

    $buildManifest = [ordered]@{
        ManifestSchemaVersion = 3; Product = $productName; Version = $Version; FeatureProfile = $FeatureProfile
        CandidateState = $candidateState; ShareApproved = $false; PrivilegedOperationsEnabled = $false
        ElevatedHelperIncluded = $false; WerLocalDumpCaptureEnabled = $false; Configuration = $Configuration
        Capabilities = $capabilities; Elevation = 'None'; SettingsMutation = 'None'; ProtectedEvidence = 'None'
        Network = 'ConsentOnlyMicrosoftSymbols'; Helper = 'Absent'
        TargetFramework = 'net10.0-windows10.0.19041.0'; RuntimeIdentifier = $RuntimeIdentifier
        DotNetSdkVersion = $sdkVersion; RuntimeFrameworkVersion = $requiredRuntimeVersion; BuiltUtc = $buildTime.ToString('o')
        SourceRepository = $sourceRepository; SourceOriginVerified = $gitMetadata.OriginVerified
        SourceTag = $gitMetadata.Tag; SourceTagVerified = $gitMetadata.TagVerified
        SourceCommit = $gitMetadata.Commit; SourceTree = $gitMetadata.Tree; SourceTreeState = $gitMetadata.State
        ExecutableName = $mainExecutableName; ExecutableSha256 = Get-Sha256 -LiteralPath $publishedExe
        AuthenticodeStatus = [string]$authenticodePolicy.AuthenticodeStatus
        SignerSubject = $authenticodePolicy.SignerSubject; SignerIssuer = $authenticodePolicy.SignerIssuer
        SignerThumbprint = $authenticodePolicy.SignerThumbprint
        TimestampSubject = $authenticodePolicy.TimestampSubject; TimestampIssuer = $authenticodePolicy.TimestampIssuer
        UnsignedSigningInputSha256 = if ($signedInput) { $UnsignedSigningInputSha256.ToLowerInvariant() } else { $null }
        SigningInputArtifactId = if ($signedInput) { $SigningInputArtifactId } else { $null }
        ReproducibleBuildVerified = $ReproducibleBuildVerified
        ReproducibilityPeerSha256 = if ($signedInput) { $ReproducibilityPeerSha256.ToLowerInvariant() } else { $null }
        TimestampCertificatePresent = [bool]$authenticodePolicy.TimestampCertificatePresent
        Rfc3161TimestampVerified = [bool]$authenticodePolicy.Rfc3161TimestampVerified
        ExactPackageVmEvidenceVerified = $false; TestsExecuted = $true
        TestEvidenceSha256 = Get-Sha256 -LiteralPath $testEvidencePath; SbomSha256 = Get-Sha256 -LiteralPath $sbomPath
        ProvenanceSha256 = Get-Sha256 -LiteralPath $provenancePath; Files = Get-PayloadManifest -Root $runtimeStage
    }
    Write-Utf8NoBom -LiteralPath (Join-Path $runtimeStage 'BUILD-MANIFEST.json') -Content ($buildManifest | ConvertTo-Json -Depth 12)

    $runtimeZipName = "$assetPrefix-$Version-$profileSlug-$RuntimeIdentifier.zip"; $sourceZipName = "$assetPrefix-$Version-source.zip"
    $runtimeZipPath = Join-Path $releaseStage $runtimeZipName; $sourceZipPath = Join-Path $releaseStage $sourceZipName
    $runtimeFiles = @(Get-ChildItem -LiteralPath $runtimeStage -File -Recurse | ForEach-Object {
            [pscustomobject]@{ FullName = $_.FullName; EntryName = $_.FullName.Substring($runtimeStage.Length).TrimStart([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar).Replace('\', '/') }
        })
    New-DeterministicZip -Files $runtimeFiles -DestinationPath $runtimeZipPath -EntryTimestamp $buildTime
    New-DeterministicZip -Files @(Get-TrackedSourceFiles -GitMetadata $gitMetadata) -DestinationPath $sourceZipPath -EntryTimestamp $buildTime
    $finalGitMetadata = Get-GitMetadata
    if ($finalGitMetadata.Commit -cne $gitMetadata.Commit -or $finalGitMetadata.Tree -cne $gitMetadata.Tree -or
        $finalGitMetadata.State -cne $gitMetadata.State) {
        throw 'Git source identity changed while the release candidate was being built.'
    }

    $releaseManifest = [ordered]@{
        ManifestSchemaVersion = 3; Product = $productName; Version = $Version; FeatureProfile = $FeatureProfile
        CandidateState = $candidateState; ShareApproved = $false
        ShareApprovalBlockers = @($(if (-not $signedInput) { 'Authenticode signature is absent.' }),
            $(if ($gitMetadata.State -ne 'clean') { 'The source tree was dirty; this is a local engineering candidate only.' }),
            $(if (-not $gitMetadata.OriginVerified) { 'The exact GitHub origin is not verified.' }),
            $(if (-not $gitMetadata.TagVerified) { "The exact v$Version source tag is not verified." }),
            $(if (-not $ReproducibleBuildVerified) { 'Two isolated unsigned builds have not produced an identical signing input.' }),
            $(if (-not [bool]$authenticodePolicy.Rfc3161TimestampVerified) { 'RFC 3161 timestamp verification is not complete.' }),
            'Exact-package disposable-VM evidence remains an external release gate.') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        PrivilegedOperationsEnabled = $false; ElevatedHelperIncluded = $false; WerLocalDumpCaptureEnabled = $false
        Capabilities = $capabilities; Elevation = 'None'; SettingsMutation = 'None'; ProtectedEvidence = 'None'
        Network = 'ConsentOnlyMicrosoftSymbols'; Helper = 'Absent'
        Configuration = $Configuration; BuiltUtc = $buildTime.ToString('o'); TargetFramework = 'net10.0-windows10.0.19041.0'
        RuntimeIdentifier = $RuntimeIdentifier; DotNetSdkVersion = $sdkVersion; RuntimeFrameworkVersion = $requiredRuntimeVersion
        SourceRepository = $sourceRepository; SourceOriginVerified = $gitMetadata.OriginVerified
        SourceTag = $gitMetadata.Tag; SourceTagVerified = $gitMetadata.TagVerified
        SourceCommit = $gitMetadata.Commit; SourceTree = $gitMetadata.Tree; SourceTreeState = $gitMetadata.State
        ExecutableName = $mainExecutableName; ExecutableSha256 = Get-Sha256 -LiteralPath $publishedExe
        AuthenticodeStatus = [string]$authenticodePolicy.AuthenticodeStatus
        SignerSubject = $authenticodePolicy.SignerSubject; SignerIssuer = $authenticodePolicy.SignerIssuer
        SignerThumbprint = $authenticodePolicy.SignerThumbprint
        TimestampSubject = $authenticodePolicy.TimestampSubject; TimestampIssuer = $authenticodePolicy.TimestampIssuer
        UnsignedSigningInputSha256 = if ($signedInput) { $UnsignedSigningInputSha256.ToLowerInvariant() } else { $null }
        SigningInputArtifactId = if ($signedInput) { $SigningInputArtifactId } else { $null }
        ReproducibleBuildVerified = $ReproducibleBuildVerified
        ReproducibilityPeerSha256 = if ($signedInput) { $ReproducibilityPeerSha256.ToLowerInvariant() } else { $null }
        TimestampCertificatePresent = [bool]$authenticodePolicy.TimestampCertificatePresent
        Rfc3161TimestampVerified = [bool]$authenticodePolicy.Rfc3161TimestampVerified
        ExactPackageVmEvidenceVerified = $false; TestsExecuted = $true; RuntimePackageFiles = Get-PayloadManifest -Root $runtimeStage
        Evidence = @(
            [ordered]@{ Name = 'TestEvidence.json'; Sha256 = Get-Sha256 -LiteralPath $testEvidencePath },
            [ordered]@{ Name = 'SBOM.spdx.json'; Sha256 = Get-Sha256 -LiteralPath $sbomPath },
            [ordered]@{ Name = 'Provenance.intoto.json'; Sha256 = Get-Sha256 -LiteralPath $provenancePath; Attested = $false })
        Assets = @(
            [ordered]@{ Role = 'runtime-candidate'; Name = $runtimeZipName; Size = (Get-Item $runtimeZipPath).Length; Sha256 = Get-Sha256 $runtimeZipPath },
            [ordered]@{ Role = 'source'; Name = $sourceZipName; Size = (Get-Item $sourceZipPath).Length; Sha256 = Get-Sha256 $sourceZipPath })
    }
    $manifestPath = Join-Path $releaseStage 'ReleaseManifest.json'
    Write-Utf8NoBom -LiteralPath $manifestPath -Content ($releaseManifest | ConvertTo-Json -Depth 14)
    $checksumItems = @($releaseManifest.Assets) + @([ordered]@{ Name = 'ReleaseManifest.json'; Sha256 = Get-Sha256 $manifestPath })
    Set-Content -LiteralPath (Join-Path $releaseStage 'SHA256SUMS.txt') -Value @($checksumItems | Sort-Object Name | ForEach-Object { "$($_.Sha256) *$($_.Name)" }) -Encoding ASCII

    & $verifyScriptPath -ArtifactsRoot $releaseStage -ExpectedVersion $Version -ExpectedFeatureProfile $FeatureProfile -RunSmokeTest
    [IO.Directory]::Move($releaseStage, $releaseRoot)
    Write-Host "ShareReadOnly candidate created: $releaseRoot" -ForegroundColor Green
    Write-Host "Candidate state: $candidateState"
    Write-Host 'ShareApproved remains false until external RFC 3161 and exact-package VM evidence gates pass.'
} finally {
    if (Test-Path -LiteralPath $workingRoot) { Remove-Item -LiteralPath $workingRoot -Recurse -Force }
}
