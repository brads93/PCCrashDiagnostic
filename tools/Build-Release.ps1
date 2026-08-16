[CmdletBinding()]
param(
    [ValidateSet('Release')]
    [string]$Configuration = 'Release',

    [ValidateSet('win-x64')]
    [string]$RuntimeIdentifier = 'win-x64',

    [string]$OutputRoot,

    [string]$DotNetPath = 'dotnet',

    [string]$BuildTimestampUtc,

    [ValidateSet('3.1.0-beta.1', '3.1.0-beta.2')]
    [string]$Version = '3.1.0-beta.2',

    [switch]$RequireSignature,

    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$ExpectedSignerThumbprint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$requiredSdkVersion = '10.0.302'
$expectedVersion = $Version
$releaseStageName = if ($Version -ceq '3.1.0-beta.1') { 'Beta1' } else { 'Beta2' }
$werLocalDumpCapture = 'Disabled'
$productName = 'PC Crash Diagnostic'
$releaseChannel = 'beta'
$assetPrefix = 'PCCrashDiagnostic'
$sourcePackageRoot = 'PCCrashDiagnostic-source'
$mainExecutableName = 'PCCrashDiagnostic.exe'
$optionalElevatedHelperName = 'PCCrashDiagnostic.ElevatedHelper.exe'
$solutionName = 'PCCrashDiagnostic.sln'
$solutionPath = Join-Path $repoRoot $solutionName
$appProjectPath = Join-Path $repoRoot 'src\BF6CrashDiagnostic.App\BF6CrashDiagnostic.App.csproj'
$helperProjectPath = Join-Path $repoRoot 'src\PCCrashDiagnostic.ElevatedHelper\PCCrashDiagnostic.ElevatedHelper.csproj'
$verifyScriptPath = Join-Path $PSScriptRoot 'Verify-Release.ps1'
$safetyScriptPath = Join-Path $PSScriptRoot 'Test-SafetyBoundary.ps1'
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
$runtimeLicenseFiles = @(
    'DOTNET-LIBRARY-LICENSE.txt',
    'DOTNET-RUNTIME-MIT-LICENSE.txt',
    'DOTNET-RUNTIME-THIRD-PARTY-NOTICES.txt',
    'DOTNET-WINDOWS-LICENSE-INFORMATION.md',
    'DOTNET-WPF-MIT-LICENSE.txt',
    'DOTNET-WPF-THIRD-PARTY-NOTICES.txt',
    'WINDOWS-SDK-LICENSE.md'
)

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path $repoRoot 'artifacts'
}

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

$outputRootFull = [IO.Path]::GetFullPath($OutputRoot)
$pathComparison = if ($env:OS -eq 'Windows_NT') {
    [StringComparison]::OrdinalIgnoreCase
} else {
    [StringComparison]::Ordinal
}

if ($outputRootFull.Equals($repoRoot, $pathComparison) -or
    $repoRoot.StartsWith($outputRootFull.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar, $pathComparison)) {
    throw 'OutputRoot cannot be the repository root or one of its parent directories.'
}

if (-not (Test-Path -LiteralPath $solutionPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $appProjectPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $helperProjectPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $verifyScriptPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $safetyScriptPath -PathType Leaf)) {
    throw 'The repository is incomplete. The solution, application and helper projects, and release scripts are required.'
}

if (Test-Path -LiteralPath $DotNetPath -PathType Leaf) {
    $resolvedDotNet = (Resolve-Path -LiteralPath $DotNetPath).Path
} else {
    $dotNetCommand = Get-Command -Name $DotNetPath -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $dotNetCommand) {
        throw "Could not find '$DotNetPath'. Install the .NET SDK pinned by global.json or pass -DotNetPath."
    }
    $resolvedDotNet = $dotNetCommand.Source
}

function Invoke-DotNet {
    param([Parameter(Mandatory)][string[]]$Arguments)

    Write-Host ("dotnet " + ($Arguments -join ' '))
    & $resolvedDotNet @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet exited with code $LASTEXITCODE."
    }
}

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$LiteralPath)
    return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory)][string]$LiteralPath,
        [Parameter(Mandatory)][string]$Content
    )

    $normalized = $Content.Replace("`r`n", "`n").TrimEnd([char[]]"`r`n") + "`n"
    [IO.File]::WriteAllText($LiteralPath, $normalized, [Text.UTF8Encoding]::new($false))
}

function Resolve-BuildTime {
    if (-not [string]::IsNullOrWhiteSpace($BuildTimestampUtc)) {
        $parsed = [DateTimeOffset]::MinValue
        if (-not [DateTimeOffset]::TryParse(
                $BuildTimestampUtc,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal,
                [ref]$parsed)) {
            throw 'BuildTimestampUtc must be an ISO-8601 timestamp.'
        }
        return $parsed.ToUniversalTime()
    }

    if (-not [string]::IsNullOrWhiteSpace($env:SOURCE_DATE_EPOCH)) {
        $epochSeconds = [long]0
        if (-not [long]::TryParse($env:SOURCE_DATE_EPOCH, [ref]$epochSeconds) -or $epochSeconds -lt 0) {
            throw 'SOURCE_DATE_EPOCH must be a non-negative integer.'
        }
        return [DateTimeOffset]::FromUnixTimeSeconds($epochSeconds)
    }

    return [DateTimeOffset]::UtcNow
}

function New-DeterministicZip {
    param(
        [Parameter(Mandatory)][object[]]$Files,
        [Parameter(Mandatory)][string]$DestinationPath,
        [Parameter(Mandatory)][DateTimeOffset]$EntryTimestamp
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $zipTime = $EntryTimestamp.ToUniversalTime()
    $minimumZipTime = [DateTimeOffset]::new(1980, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
    $maximumZipTime = [DateTimeOffset]::new(2107, 12, 31, 23, 59, 58, [TimeSpan]::Zero)
    if ($zipTime -lt $minimumZipTime) { $zipTime = $minimumZipTime }
    if ($zipTime -gt $maximumZipTime) { $zipTime = $maximumZipTime }
    $zipTime = $zipTime.AddSeconds(-($zipTime.Second % 2)).AddTicks(-$zipTime.Ticks % [TimeSpan]::TicksPerSecond)

    $parent = Split-Path -Parent $DestinationPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $fileStream = [IO.File]::Open($DestinationPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new($fileStream, [IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            foreach ($file in ($Files | Sort-Object EntryName)) {
                $entryName = ([string]$file.EntryName).Replace('\', '/')
                if ($entryName.StartsWith('/') -or $entryName.Contains('../') -or $entryName.Contains(':')) {
                    throw "Unsafe ZIP entry name: $entryName"
                }

                $entry = $archive.CreateEntry($entryName, [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $zipTime
                $input = [IO.File]::OpenRead([string]$file.FullName)
                try {
                    $output = $entry.Open()
                    try { $input.CopyTo($output) } finally { $output.Dispose() }
                } finally {
                    $input.Dispose()
                }
            }
        } finally {
            $archive.Dispose()
        }
    } finally {
        $fileStream.Dispose()
    }
}

function Get-GitMetadata {
    $metadata = [ordered]@{
        Commit = $null
        TreeState = 'unknown'
    }

    $git = Get-Command -Name 'git.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $git -or -not (Test-Path -LiteralPath (Join-Path $repoRoot '.git'))) {
        return $metadata
    }

    $commit = & $git.Source -C $repoRoot rev-parse HEAD 2>$null
    if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace(($commit -join ''))) {
        $metadata.Commit = ($commit -join '').Trim()
    }

    $status = & $git.Source -C $repoRoot status --porcelain --untracked-files=normal 2>$null
    if ($LASTEXITCODE -eq 0) {
        $metadata.TreeState = if (@($status).Count -eq 0) { 'clean' } else { 'dirty' }
    }

    return $metadata
}

function Test-GeneratedPathSegment {
    param([Parameter(Mandatory)][string]$RelativePath)

    $segments = $RelativePath.Replace('\', '/') -split '/'
    return @($segments | Where-Object {
            $_ -match '^(?i:\.git|\.vs|\.idea|bin|obj|TestResults)$' -or
            $_ -match '^(?i:artifacts)(?:$|[-._])' -or
            $_ -match '^(?i:\.work-).*'
        }).Count -gt 0
}

function Assert-NoReparsePoint {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $fullPath = [IO.Path]::GetFullPath($LiteralPath)
    $repoPrefix = $repoRoot.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($repoPrefix, $pathComparison)) {
        throw "Source-package path escapes the repository: '$fullPath'."
    }

    $current = $fullPath
    while (-not $current.Equals($repoRoot, $pathComparison)) {
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse points and symbolic links are forbidden in release inputs: '$current'."
        }
        $current = Split-Path -Parent $current
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

function Get-SourcePackageFiles {
    $sourceFiles = New-Object System.Collections.Generic.List[object]

    foreach ($relative in $sourceRootAllowlist) {
        $fullName = Join-Path $repoRoot $relative
        if (-not (Test-Path -LiteralPath $fullName -PathType Leaf)) {
            throw "Required source-package file is missing: '$relative'."
        }
        Assert-NoReparsePoint -LiteralPath $fullName
        Assert-AllowedSourcePath -RelativePath $relative
        $sourceFiles.Add([pscustomobject]@{
                FullName = $fullName
                EntryName = "$sourcePackageRoot/$($relative.Replace('\', '/'))"
            })
    }

    foreach ($relative in $sourceExactPathAllowlist) {
        $fullName = Join-Path $repoRoot $relative
        if (-not (Test-Path -LiteralPath $fullName -PathType Leaf)) {
            throw "Required source-package file is missing: '$relative'."
        }
        Assert-NoReparsePoint -LiteralPath $fullName
        Assert-AllowedSourcePath -RelativePath $relative
        $sourceFiles.Add([pscustomobject]@{
                FullName = $fullName
                EntryName = "$sourcePackageRoot/$($relative.Replace('\', '/'))"
            })
    }

    foreach ($directory in $sourceDirectoryExtensionAllowlist.Keys) {
        $directoryPath = Join-Path $repoRoot $directory
        if (-not (Test-Path -LiteralPath $directoryPath -PathType Container)) {
            throw "Required source-package directory is missing: '$directory'."
        }
        Assert-NoReparsePoint -LiteralPath $directoryPath

        foreach ($file in (Get-ChildItem -LiteralPath $directoryPath -File -Recurse -Force)) {
            $fullName = [IO.Path]::GetFullPath($file.FullName)
            $relative = $fullName.Substring($repoRoot.Length).TrimStart([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
            if (Test-GeneratedPathSegment -RelativePath $relative) { continue }
            Assert-NoReparsePoint -LiteralPath $fullName
            Assert-AllowedSourcePath -RelativePath $relative

            $sourceFiles.Add([pscustomobject]@{
                    FullName = $fullName
                    EntryName = "$sourcePackageRoot/$($relative.Replace('\', '/'))"
                })
        }
    }

    $duplicateEntry = @($sourceFiles | Group-Object EntryName | Where-Object Count -ne 1 | Select-Object -First 1)
    if ($duplicateEntry.Count -ne 0) {
        throw "Duplicate source-package entry selected: '$($duplicateEntry[0].Name)'."
    }

    return $sourceFiles.ToArray()
}

[xml]$appProject = Get-Content -LiteralPath $appProjectPath -Raw
$version = $expectedVersion
$targetFramework = [string](($appProject.Project.PropertyGroup | Where-Object { $_.TargetFramework } | Select-Object -First 1).TargetFramework)
$assemblyName = [string](($appProject.Project.PropertyGroup | Where-Object { $_.AssemblyName } | Select-Object -First 1).AssemblyName)
if ([string]::IsNullOrWhiteSpace($assemblyName)) {
    throw 'The application project must define AssemblyName.'
}
if (($assemblyName + '.exe') -cne $mainExecutableName) {
    throw "The active release must publish '$mainExecutableName'; the application project declares '$assemblyName.exe'."
}

$sourceFiles = @(Get-SourcePackageFiles)
if ($sourceFiles.Count -eq 0) { throw 'No source files were selected for the source package.' }

$buildTime = Resolve-BuildTime
$releaseRoot = Join-Path $outputRootFull $version
if (Test-Path -LiteralPath $releaseRoot) {
    throw "Release directory already exists: $releaseRoot"
}

New-Item -ItemType Directory -Path $outputRootFull -Force | Out-Null
$workingRoot = Join-Path $outputRootFull ('.work-' + [Guid]::NewGuid().ToString('N'))
$dotnetArtifactsRoot = Join-Path $workingRoot 'dotnet-artifacts'
# MSBuild treats a raw comma in -p:Name=Value as another property separator.
# %2C survives argument parsing and becomes the comma required by C# PathMap.
$deterministicPathMap = "$repoRoot=/_/src%2C$workingRoot=/_/build"
$publishRoot = Join-Path $workingRoot 'publish'
$helperPublishRoot = Join-Path $workingRoot 'helper-publish'
$runtimeStage = Join-Path $workingRoot 'runtime-stage'
$releaseStage = Join-Path $workingRoot 'release'
New-Item -ItemType Directory -Path $publishRoot, $helperPublishRoot, $runtimeStage, $releaseStage -Force | Out-Null

try {
    $sdkVersion = (& $resolvedDotNet --version)
    if ($LASTEXITCODE -ne 0) { throw "dotnet --version exited with code $LASTEXITCODE." }
    $sdkVersion = ($sdkVersion -join '').Trim()
    if ($sdkVersion -cne $requiredSdkVersion) {
        throw "The release requires .NET SDK $requiredSdkVersion exactly; found '$sdkVersion'."
    }

    Push-Location $repoRoot
    try {
        & $safetyScriptPath -RepoRoot $repoRoot
        Invoke-DotNet -Arguments @(
            'restore', $solutionPath,
            '--locked-mode',
            '--artifacts-path', $dotnetArtifactsRoot,
            ("-p:PCCrashDiagnosticVersion=$version"),
            ("-p:PCCrashDiagnosticStage=$releaseStageName"),
            ("-p:PCCrashDiagnosticWerLocalDumpCapture=$werLocalDumpCapture")
        )

        $testResults = Join-Path $workingRoot 'test-results'
        Invoke-DotNet -Arguments @(
            'test', $solutionPath,
            '-c', $Configuration,
            '--no-restore',
            '--artifacts-path', $dotnetArtifactsRoot,
            ("-p:PCCrashDiagnosticVersion=$version"),
            ("-p:PCCrashDiagnosticStage=$releaseStageName"),
            ("-p:PCCrashDiagnosticWerLocalDumpCapture=$werLocalDumpCapture"),
            '--logger', 'trx;LogFileName=release-tests.trx',
            '--results-directory', $testResults
        )

        Invoke-DotNet -Arguments @(
            'publish', $helperProjectPath,
            '-c', $Configuration,
            '-r', $RuntimeIdentifier,
            '--self-contained', 'true',
            '--no-restore',
            '--artifacts-path', $dotnetArtifactsRoot,
            '-o', $helperPublishRoot,
            '-p:PublishSingleFile=true',
            '-p:IncludeNativeLibrariesForSelfExtract=true',
            '-p:EnableCompressionInSingleFile=true',
            '-p:PublishTrimmed=false',
            '-p:Deterministic=true',
            '-p:ContinuousIntegrationBuild=true',
            ("-p:PCCrashDiagnosticVersion=$version"),
            ("-p:PCCrashDiagnosticStage=$releaseStageName"),
            ("-p:PCCrashDiagnosticWerLocalDumpCapture=$werLocalDumpCapture"),
            ("-p:PathMap=$deterministicPathMap")
        )

        $helperPublishExe = Join-Path $helperPublishRoot $optionalElevatedHelperName
        $helperPublishedExecutables = @(Get-ChildItem -LiteralPath $helperPublishRoot -Filter '*.exe' -File)
        if (-not (Test-Path -LiteralPath $helperPublishExe -PathType Leaf) -or
            $helperPublishedExecutables.Count -ne 1 -or
            $helperPublishedExecutables[0].Name -cne $optionalElevatedHelperName) {
            throw "Helper publish output must contain exactly '$optionalElevatedHelperName'."
        }
        $expectedHelperSha256 = Get-Sha256 -LiteralPath $helperPublishExe

        Invoke-DotNet -Arguments @(
            'publish', $appProjectPath,
            '-c', $Configuration,
            '-r', $RuntimeIdentifier,
            '--self-contained', 'true',
            '--no-restore',
            '--artifacts-path', $dotnetArtifactsRoot,
            '-o', $publishRoot,
            '-p:PublishSingleFile=true',
            '-p:IncludeNativeLibrariesForSelfExtract=true',
            '-p:EnableCompressionInSingleFile=true',
            '-p:PublishTrimmed=false',
            '-p:Deterministic=true',
            '-p:ContinuousIntegrationBuild=true',
            ("-p:PCCrashDiagnosticVersion=$version"),
            ("-p:PCCrashDiagnosticStage=$releaseStageName"),
            ("-p:PCCrashDiagnosticWerLocalDumpCapture=$werLocalDumpCapture"),
            ("-p:ExpectedElevatedHelperSha256=$expectedHelperSha256"),
            ("-p:PathMap=$deterministicPathMap")
        )
    } finally {
        Pop-Location
    }

    $helperPublishExe = Join-Path $helperPublishRoot $optionalElevatedHelperName
    $helperPublishedExecutables = @(Get-ChildItem -LiteralPath $helperPublishRoot -Filter '*.exe' -File)
    if (-not (Test-Path -LiteralPath $helperPublishExe -PathType Leaf) -or
        $helperPublishedExecutables.Count -ne 1 -or
        $helperPublishedExecutables[0].Name -cne $optionalElevatedHelperName) {
        throw "Helper publish output must contain exactly '$optionalElevatedHelperName'."
    }
    Copy-Item -LiteralPath $helperPublishExe -Destination (Join-Path $publishRoot $optionalElevatedHelperName)

    $publishedExe = Join-Path $publishRoot $mainExecutableName
    if (-not (Test-Path -LiteralPath $publishedExe -PathType Leaf)) {
        throw "Publish did not create the expected executable: $publishedExe"
    }

    $publishedExecutables = @(Get-ChildItem -LiteralPath $publishRoot -Filter '*.exe' -File)
    $unexpectedExecutables = @($publishedExecutables | Where-Object {
            $_.Name -cne $mainExecutableName -and $_.Name -cne $optionalElevatedHelperName
        })
    if (@($publishedExecutables | Where-Object Name -ceq $mainExecutableName).Count -ne 1 -or
        @($publishedExecutables | Where-Object Name -ceq $optionalElevatedHelperName).Count -ne 1 -or
        $unexpectedExecutables.Count -ne 0) {
        throw "Publish output must contain exactly '$mainExecutableName' and '$optionalElevatedHelperName'."
    }
    $publishedHelper = Join-Path $publishRoot $optionalElevatedHelperName
    $hasElevatedHelper = Test-Path -LiteralPath $publishedHelper -PathType Leaf
    if (-not $hasElevatedHelper) {
        throw "Publish did not create the required one-shot helper: $publishedHelper"
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $publishedExe
    $helperSignature = if ($hasElevatedHelper) {
        Get-AuthenticodeSignature -LiteralPath $publishedHelper
    } else {
        $null
    }
    if ($RequireSignature) {
        if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or $null -eq $signature.SignerCertificate) {
            throw "A valid Authenticode signature is required; status is $($signature.Status)."
        }
        if ($signature.SignerCertificate.Thumbprint.ToUpperInvariant() -cne $normalizedExpectedSignerThumbprint) {
            throw "Authenticode signer thumbprint mismatch. Expected '$normalizedExpectedSignerThumbprint'; found '$($signature.SignerCertificate.Thumbprint)'."
        }
        if ($null -eq $signature.TimeStamperCertificate) {
            throw 'A countersignature timestamp certificate is required for signed public releases.'
        }
        if ($hasElevatedHelper) {
            if ($helperSignature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
                $null -eq $helperSignature.SignerCertificate) {
                throw "A valid Authenticode signature is required for '$optionalElevatedHelperName'; status is $($helperSignature.Status)."
            }
            if ($helperSignature.SignerCertificate.Thumbprint.ToUpperInvariant() -cne $normalizedExpectedSignerThumbprint) {
                throw "Authenticode signer thumbprint mismatch for '$optionalElevatedHelperName'."
            }
            if ($null -eq $helperSignature.TimeStamperCertificate) {
                throw "A countersignature timestamp certificate is required for '$optionalElevatedHelperName'."
            }
        }
    }

    $publisherTrust = if ($RequireSignature) {
        'authenticode-pinned'
    } elseif ($signature.Status -eq [Management.Automation.SignatureStatus]::NotSigned -and
        (-not $hasElevatedHelper -or
         $helperSignature.Status -eq [Management.Automation.SignatureStatus]::NotSigned)) {
        'unsigned'
    } else {
        'signature-present-unverified'
    }
    $releaseLabel = switch ($publisherTrust) {
        'authenticode-pinned' { 'SIGNED BETA' }
        'unsigned' { 'UNSIGNED BETA' }
        default { 'BETA - SIGNATURE NOT PINNED' }
    }
    $trustNotice = switch ($publisherTrust) {
        'authenticode-pinned' { 'Authenticode signature and pinned signer thumbprint verified.' }
        'unsigned' { 'Unsigned beta. Verify SHA-256 through a trusted independent channel before running.' }
        default { 'A signature is present but publisher identity was not pinned. Verify SHA-256 through a trusted independent channel.' }
    }

    Copy-Item -LiteralPath $publishedExe -Destination (Join-Path $runtimeStage $mainExecutableName)
    if ($hasElevatedHelper) {
        Copy-Item -LiteralPath $publishedHelper -Destination (Join-Path $runtimeStage $optionalElevatedHelperName)
    }
    foreach ($name in @('00-START-HERE.txt', 'README.md', 'LICENSE', 'PRIVACY.md', 'SECURITY.md', 'THIRD_PARTY_NOTICES.md', 'CHANGELOG.md', 'CONTRIBUTING.md')) {
        $sourcePath = Join-Path $repoRoot $name
        Assert-NoReparsePoint -LiteralPath $sourcePath
        Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $runtimeStage $name)
    }
    $runtimeDocsStage = Join-Path $runtimeStage 'docs'
    $runtimeLicensesStage = Join-Path $runtimeStage 'licenses'
    New-Item -ItemType Directory -Path $runtimeDocsStage, $runtimeLicensesStage -Force | Out-Null
    foreach ($name in @('REPORT_FORMAT.md')) {
        $sourcePath = Join-Path $repoRoot (Join-Path 'docs' $name)
        Assert-NoReparsePoint -LiteralPath $sourcePath
        Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $runtimeDocsStage $name)
    }
    foreach ($name in $runtimeLicenseFiles) {
        $sourcePath = Join-Path $repoRoot (Join-Path 'licenses' $name)
        Assert-NoReparsePoint -LiteralPath $sourcePath
        Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $runtimeLicensesStage $name)
    }

    $gitMetadata = Get-GitMetadata
    $runtimePayload = @(
        Get-ChildItem -LiteralPath $runtimeStage -File -Recurse |
            Sort-Object FullName |
            ForEach-Object {
                $relativePath = $_.FullName.Substring($runtimeStage.Length).TrimStart([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar).Replace('\', '/')
                [ordered]@{
                    Path = $relativePath
                    Size = $_.Length
                    Sha256 = Get-Sha256 -LiteralPath $_.FullName
                }
            }
    )

    $helperManifest = if ($hasElevatedHelper) {
        [ordered]@{
            Name = $optionalElevatedHelperName
            Sha256 = Get-Sha256 -LiteralPath $publishedHelper
            EmbeddedBindingSha256 = $expectedHelperSha256
            AuthenticodeStatus = [string]$helperSignature.Status
        }
    } else {
        $null
    }

    $buildManifest = [ordered]@{
        ManifestSchemaVersion = 2
        Product = $productName
        Version = $version
        ReleaseStage = $releaseStageName
        Beta2FeaturesEnabled = $releaseStageName -ceq 'Beta2'
        WerLocalDumpCaptureEnabled = $false
        ReleaseChannel = $releaseChannel
        ReleaseLabel = $releaseLabel
        PublisherTrust = $publisherTrust
        TrustNotice = $trustNotice
        ChecksumAlgorithm = 'SHA-256'
        Configuration = $Configuration
        TargetFramework = $targetFramework
        RuntimeIdentifier = $RuntimeIdentifier
        SelfContained = $true
        SingleFile = $true
        ExecutableName = $mainExecutableName
        ExecutableSha256 = Get-Sha256 -LiteralPath $publishedExe
        OptionalElevatedHelper = $helperManifest
        BuiltUtc = $buildTime.ToString('o')
        DotNetSdk = $sdkVersion
        TestsExecuted = $true
        SourceCommit = $gitMetadata.Commit
        SourceTreeState = $gitMetadata.TreeState
        AuthenticodeStatus = [string]$signature.Status
        SignerSubject = if ($null -ne $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
        SignerThumbprint = if ($null -ne $signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint.ToUpperInvariant() } else { $null }
        TimestampSignerSubject = if ($null -ne $signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.Subject } else { $null }
        TimestampSignerThumbprint = if ($null -ne $signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.Thumbprint.ToUpperInvariant() } else { $null }
        Files = $runtimePayload
    }
    $buildManifestPath = Join-Path $runtimeStage 'BUILD-MANIFEST.json'
    Write-Utf8NoBom -LiteralPath $buildManifestPath -Content ($buildManifest | ConvertTo-Json -Depth 8)

    $safeVersion = $version -replace '[^A-Za-z0-9._-]', '-'
    $runtimeZipName = "$assetPrefix-$safeVersion-$RuntimeIdentifier.zip"
    $sourceZipName = "$assetPrefix-$safeVersion-source.zip"
    $runtimeZipPath = Join-Path $releaseStage $runtimeZipName
    $sourceZipPath = Join-Path $releaseStage $sourceZipName

    $runtimeFiles = @(
        Get-ChildItem -LiteralPath $runtimeStage -File -Recurse |
            ForEach-Object {
                $relativePath = $_.FullName.Substring($runtimeStage.Length).TrimStart([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar).Replace('\', '/')
                [pscustomobject]@{
                    FullName = $_.FullName
                    EntryName = $relativePath
                }
            }
    )
    New-DeterministicZip -Files $runtimeFiles -DestinationPath $runtimeZipPath -EntryTimestamp $buildTime

    foreach ($sourceFile in $sourceFiles) {
        Assert-NoReparsePoint -LiteralPath ([string]$sourceFile.FullName)
    }
    New-DeterministicZip -Files $sourceFiles -DestinationPath $sourceZipPath -EntryTimestamp $buildTime

    $runtimePackageFiles = @(
        Get-ChildItem -LiteralPath $runtimeStage -File -Recurse |
            Sort-Object FullName |
            ForEach-Object {
                $relativePath = $_.FullName.Substring($runtimeStage.Length).TrimStart([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar).Replace('\', '/')
                [ordered]@{
                    Path = $relativePath
                    Size = $_.Length
                    Sha256 = Get-Sha256 -LiteralPath $_.FullName
                }
            }
    )

    $releaseManifest = [ordered]@{
        ManifestSchemaVersion = 2
        Product = $productName
        Version = $version
        ReleaseStage = $releaseStageName
        Beta2FeaturesEnabled = $releaseStageName -ceq 'Beta2'
        WerLocalDumpCaptureEnabled = $false
        ReleaseChannel = $releaseChannel
        ReleaseLabel = $releaseLabel
        PublisherTrust = $publisherTrust
        TrustNotice = $trustNotice
        ChecksumAlgorithm = 'SHA-256'
        Configuration = $Configuration
        BuiltUtc = $buildTime.ToString('o')
        TargetFramework = $targetFramework
        RuntimeIdentifier = $RuntimeIdentifier
        ExecutableName = $mainExecutableName
        ExecutableSha256 = Get-Sha256 -LiteralPath $publishedExe
        OptionalElevatedHelper = $helperManifest
        AuthenticodeStatus = [string]$signature.Status
        SignerSubject = if ($null -ne $signature.SignerCertificate) { $signature.SignerCertificate.Subject } else { $null }
        SignerThumbprint = if ($null -ne $signature.SignerCertificate) { $signature.SignerCertificate.Thumbprint.ToUpperInvariant() } else { $null }
        TimestampSignerSubject = if ($null -ne $signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.Subject } else { $null }
        TimestampSignerThumbprint = if ($null -ne $signature.TimeStamperCertificate) { $signature.TimeStamperCertificate.Thumbprint.ToUpperInvariant() } else { $null }
        TestsExecuted = $true
        SourceCommit = $gitMetadata.Commit
        SourceTreeState = $gitMetadata.TreeState
        RuntimePackageFiles = $runtimePackageFiles
        Assets = @(
            [ordered]@{
                Role = 'runtime'
                Name = $runtimeZipName
                Size = (Get-Item -LiteralPath $runtimeZipPath).Length
                Sha256 = Get-Sha256 -LiteralPath $runtimeZipPath
            },
            [ordered]@{
                Role = 'source'
                Name = $sourceZipName
                Size = (Get-Item -LiteralPath $sourceZipPath).Length
                Sha256 = Get-Sha256 -LiteralPath $sourceZipPath
            }
        )
    }

    $releaseManifestPath = Join-Path $releaseStage 'ReleaseManifest.json'
    Write-Utf8NoBom -LiteralPath $releaseManifestPath -Content ($releaseManifest | ConvertTo-Json -Depth 10)

    $checksumEntries = @($releaseManifest.Assets) + @(
        [ordered]@{
            Name = 'ReleaseManifest.json'
            Sha256 = Get-Sha256 -LiteralPath $releaseManifestPath
        }
    )
    $checksumLines = @(
        $checksumEntries |
            Sort-Object Name |
            ForEach-Object { "$($_.Sha256) *$($_.Name)" }
    )
    Set-Content -LiteralPath (Join-Path $releaseStage 'SHA256SUMS.txt') -Value $checksumLines -Encoding ASCII

    $verifyParameters = @{
        ArtifactsRoot = $releaseStage
        ExpectedVersion = $version
        RunSmokeTest = $true
    }
    if ($RequireSignature) {
        $verifyParameters.RequireSignature = $true
        $verifyParameters.ExpectedSignerThumbprint = $normalizedExpectedSignerThumbprint
    }
    & $verifyScriptPath @verifyParameters
    if ($LASTEXITCODE -ne 0) { throw "Release verification exited with code $LASTEXITCODE." }

    # Directory.Move refuses an existing destination. Unlike Move-Item, it
    # cannot silently nest this release inside a same-version directory that a
    # concurrent builder created after the initial preflight.
    [IO.Directory]::Move($releaseStage, $releaseRoot)
    Write-Host "Release created and verified: $releaseRoot" -ForegroundColor Green
} finally {
    if (Test-Path -LiteralPath $workingRoot) {
        Remove-Item -LiteralPath $workingRoot -Recurse -Force
    }
}
