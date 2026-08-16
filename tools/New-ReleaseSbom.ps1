[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$RepoRoot,

    [Parameter(Mandatory)]
    [string]$PayloadRoot,

    [Parameter(Mandatory)]
    [string]$RestoreArtifactsRoot,

    [Parameter(Mandatory)]
    [string]$DotNetPath,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [ValidateSet('ShareReadOnly')]
    [string]$FeatureProfile = 'ShareReadOnly',

    [ValidatePattern('^3\.2\.0-beta\.1$')]
    [string]$Version = '3.2.0-beta.1',

    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$SourceCommit,

    [string]$SbomRuntimeHostPath,

    [DateTimeOffset]$GeneratedUtc = [DateTimeOffset]::UtcNow
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$requiredToolVersion = '4.1.5'
$requiredToolRuntime = '8.0.30'
$repoFull = [IO.Path]::GetFullPath($RepoRoot)
$payloadFull = [IO.Path]::GetFullPath($PayloadRoot)
$restoreArtifactsFull = [IO.Path]::GetFullPath($RestoreArtifactsRoot)
$outputFull = [IO.Path]::GetFullPath($OutputPath)
$dotnetFull = [IO.Path]::GetFullPath($DotNetPath)

foreach ($requiredDirectory in @($repoFull, $payloadFull, $restoreArtifactsFull)) {
    if (-not (Test-Path -LiteralPath $requiredDirectory -PathType Container)) {
        throw "Required SBOM input directory not found: $requiredDirectory"
    }
}
if (-not (Test-Path -LiteralPath $dotnetFull -PathType Leaf)) {
    throw "Pinned .NET SDK host not found: $dotnetFull"
}

$toolManifestPath = Join-Path $repoFull '.config\dotnet-tools.json'
if (-not (Test-Path -LiteralPath $toolManifestPath -PathType Leaf)) {
    throw 'The repository-local .NET tool manifest is missing.'
}
$toolManifest = Get-Content -LiteralPath $toolManifestPath -Raw | ConvertFrom-Json
$toolEntry = $toolManifest.tools.'microsoft.sbom.dotnettool'
if ($null -eq $toolEntry -or [string]$toolEntry.version -cne $requiredToolVersion -or
    @($toolEntry.commands).Count -ne 1 -or [string]$toolEntry.commands[0] -cne 'sbom-tool') {
    throw "The local tool manifest must pin Microsoft.Sbom.DotNetTool $requiredToolVersion exactly."
}

if ([string]::IsNullOrWhiteSpace($SbomRuntimeHostPath)) {
    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    $SbomRuntimeHostPath = Join-Path $programFiles 'dotnet\dotnet.exe'
}
$sbomHostFull = [IO.Path]::GetFullPath($SbomRuntimeHostPath)
if (-not (Test-Path -LiteralPath $sbomHostFull -PathType Leaf)) {
    throw "Microsoft SBOM Tool requires a separate .NET 8 build-time host; not found: $sbomHostFull"
}
$runtimeList = @(& $sbomHostFull --list-runtimes)
if ($LASTEXITCODE -ne 0 -or @($runtimeList | Where-Object { $_ -match "^Microsoft\.NETCore\.App\s+$([regex]::Escape($requiredToolRuntime))\s+\[" }).Count -ne 1) {
    throw "Microsoft SBOM Tool $requiredToolVersion must run on Microsoft.NETCore.App $requiredToolRuntime exactly. This build-only runtime is separate from the packaged .NET 10.0.11 runtime."
}

$nugetPackagesRoot = if (-not [string]::IsNullOrWhiteSpace($env:NUGET_PACKAGES)) {
    [IO.Path]::GetFullPath($env:NUGET_PACKAGES)
} else {
    Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)) '.nuget\packages'
}
$toolAssemblyPath = Join-Path $nugetPackagesRoot "microsoft.sbom.dotnettool\$requiredToolVersion\tools\net8.0\any\Microsoft.Sbom.DotNetTool.dll"
if (-not (Test-Path -LiteralPath $toolAssemblyPath -PathType Leaf)) {
    throw "Microsoft SBOM Tool $requiredToolVersion is not restored. Run 'dotnet tool restore --tool-manifest .config/dotnet-tools.json' with the pinned SDK first."
}
$reportedToolVersion = ((& $sbomHostFull $toolAssemblyPath --version) -join '').Trim()
if ($LASTEXITCODE -ne 0 -or $reportedToolVersion -cne $requiredToolVersion) {
    throw "Microsoft SBOM Tool version mismatch: expected $requiredToolVersion, found '$reportedToolVersion'."
}

function Get-Sha256 {
    param([Parameter(Mandatory)][string]$LiteralPath)
    return (Get-FileHash -LiteralPath $LiteralPath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-StableSha256 {
    param([Parameter(Mandatory)][string]$Value)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value)))).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Assert-NoAbsoluteLocalPath {
    param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][string]$Description)
    if ($Text -match '(?i)[A-Z]:\\|\\Users\\|/home/') {
        throw "$Description contains an absolute build-machine path."
    }
}

$runtimeProjects = @(
    'PCCrashDiagnostic.Contracts',
    'PCCrashDiagnostic.Core',
    'PCCrashDiagnostic.LocalTools',
    'PCCrashDiagnostic.App'
)
$expectedPackages = @{}
foreach ($projectName in $runtimeProjects) {
    $lockPath = Join-Path $repoFull "src\$projectName\packages.lock.json"
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        throw "ShareReadOnly runtime lock file is missing: src/$projectName/packages.lock.json"
    }
    $lock = Get-Content -LiteralPath $lockPath -Raw | ConvertFrom-Json
    foreach ($framework in $lock.dependencies.PSObject.Properties) {
        foreach ($dependencyProperty in $framework.Value.PSObject.Properties) {
            $dependency = $dependencyProperty.Value
            if ([string]$dependency.type -ceq 'Project' -or [string]::IsNullOrWhiteSpace([string]$dependency.resolved)) {
                continue
            }
            $key = "$($dependencyProperty.Name)|$($dependency.resolved)".ToLowerInvariant()
            $expectedPackages[$key] = [pscustomobject]@{ Name = $dependencyProperty.Name; Version = [string]$dependency.resolved }
        }
    }
}
if ($expectedPackages.Count -eq 0) {
    throw 'The ShareReadOnly lock files contain no non-project dependencies; refusing to produce an incomplete SBOM.'
}

$payloadFiles = @(Get-ChildItem -LiteralPath $payloadFull -File -Recurse | Sort-Object FullName | ForEach-Object {
        $relative = $_.FullName.Substring($payloadFull.Length).TrimStart(
            [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar).Replace('\', '/')
        [pscustomobject]@{ RelativePath = $relative; FullName = $_.FullName; Sha256 = Get-Sha256 -LiteralPath $_.FullName }
    })
if ($payloadFiles.Count -eq 0) { throw 'The SBOM payload is empty.' }
$namespaceSeed = "$Version|$FeatureProfile|$($SourceCommit.ToLowerInvariant())|" +
    (@($payloadFiles | ForEach-Object { "$($_.RelativePath)=$($_.Sha256)" }) -join '|')
$namespaceIdentity = Get-StableSha256 -Value $namespaceSeed
$namespaceUniquePart = "PCCrashDiagnostic-$Version-$FeatureProfile-$namespaceIdentity"
$generationTimestamp = $GeneratedUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

$outputParent = Split-Path -Parent $outputFull
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    New-Item -ItemType Directory -Path $outputParent -Force | Out-Null
}
$workName = '.sbom-work-' + [Guid]::NewGuid().ToString('N')
$workParent = Split-Path -Parent $outputParent
if ([string]::IsNullOrWhiteSpace($workParent)) {
    $workParent = [IO.Path]::GetTempPath()
}
$workRoot = Join-Path $workParent $workName
$payloadPrefix = $payloadFull.TrimEnd(
    [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if ($workRoot.StartsWith($payloadPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    # Component Detection must not see the SBOM tool's own staging files as
    # payload. Use a random external workspace when the requested output is
    # nested more deeply inside the payload.
    $workParent = [IO.Path]::GetTempPath()
    $workRoot = Join-Path $workParent $workName
}
$workCleanupParent = [IO.Path]::GetFullPath($workParent).TrimEnd(
    [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
$componentRoot = Join-Path $workRoot 'components'
$manifestRoot = Join-Path $workRoot 'manifest'
$validationPath = Join-Path $workRoot 'validation.json'
New-Item -ItemType Directory -Path $componentRoot, $manifestRoot -Force | Out-Null

try {
    foreach ($projectName in $runtimeProjects) {
        $sourceProjectRoot = Join-Path $repoFull "src\$projectName"
        $stagedProjectRoot = Join-Path $componentRoot "src\$projectName"
        $stagedObjRoot = Join-Path $stagedProjectRoot 'obj'
        New-Item -ItemType Directory -Path $stagedObjRoot -Force | Out-Null
        foreach ($name in @("$projectName.csproj", 'packages.lock.json')) {
            $source = Join-Path $sourceProjectRoot $name
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "SBOM component input is missing: $source" }
            Copy-Item -LiteralPath $source -Destination (Join-Path $stagedProjectRoot $name)
        }
        $assetsPath = Join-Path $restoreArtifactsFull "obj\$projectName\project.assets.json"
        if (-not (Test-Path -LiteralPath $assetsPath -PathType Leaf)) {
            throw "RID-aware locked restore assets are missing for ${projectName}: $assetsPath"
        }
        Copy-Item -LiteralPath $assetsPath -Destination (Join-Path $stagedObjRoot 'project.assets.json')
    }

    $generateArguments = @(
        $toolAssemblyPath, 'generate',
        '-b', $payloadFull,
        '-bc', $componentRoot,
        '-m', $manifestRoot,
        '-pn', 'PC Crash Diagnostic',
        '-pv', $Version,
        '-ps', 'PC Crash Diagnostic contributors',
        '-nsb', 'https://github.com/brads93/PCCrashDiagnostic/sbom',
        '-nsu', $namespaceUniquePart,
        '-gt', $generationTimestamp,
        '-li', 'false',
        '-pm', 'false',
        '-F', 'false',
        '-mi', 'SPDX:2.2',
        '-V', 'Warning'
    )
    & $sbomHostFull @generateArguments
    if ($LASTEXITCODE -ne 0) { throw "Microsoft SBOM Tool generation exited with code $LASTEXITCODE." }

    $rawSbomPath = Join-Path $manifestRoot '_manifest\spdx_2.2\manifest.spdx.json'
    if (-not (Test-Path -LiteralPath $rawSbomPath -PathType Leaf)) {
        throw 'Microsoft SBOM Tool did not create the expected SPDX 2.2 manifest.'
    }
    $sbom = Get-Content -LiteralPath $rawSbomPath -Raw | ConvertFrom-Json
    if ([string]$sbom.spdxVersion -cne 'SPDX-2.2' -or [string]$sbom.SPDXID -cne 'SPDXRef-DOCUMENT') {
        throw 'Microsoft SBOM Tool output is not an SPDX 2.2 document.'
    }
    $expectedNamespaceSuffix = "/$Version/$namespaceUniquePart"
    if (-not ([string]$sbom.documentNamespace).EndsWith($expectedNamespaceSuffix, [StringComparison]::Ordinal)) {
        throw "Microsoft SBOM Tool returned an unexpected document namespace: $($sbom.documentNamespace)"
    }
    $actualCreated = ([DateTimeOffset]$sbom.creationInfo.created).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $pinnedCreatorCount = @($sbom.creationInfo.creators | Where-Object { [string]$_ -ceq 'Tool: Microsoft.SBOMTool-4.1.5' }).Count
    if ($actualCreated -cne $generationTimestamp -or $pinnedCreatorCount -ne 1) {
        throw "Microsoft SBOM Tool output does not record the pinned tool and deterministic generation timestamp: created='$($sbom.creationInfo.created)', creators='$(@($sbom.creationInfo.creators) -join '; ')'."
    }
    $sbom.creationInfo.created = $generationTimestamp

    $rootPackages = @($sbom.packages | Where-Object { [string]$_.SPDXID -ceq 'SPDXRef-RootPackage' })
    if ($rootPackages.Count -ne 1 -or [string]$rootPackages[0].name -cne 'PC Crash Diagnostic' -or
        [string]$rootPackages[0].versionInfo -cne $Version) {
        throw 'Microsoft SBOM Tool output does not contain the expected root package.'
    }
    foreach ($reference in @($rootPackages[0].externalRefs | Where-Object { [string]$_.referenceType -ceq 'purl' })) {
        # Braced capture syntax prevents a digest beginning with digits from
        # being parsed as a larger numeric capture-group reference.
        $reference.referenceLocator = ([string]$reference.referenceLocator) -replace '([?&]tag_id=)[^&]+', ('${1}' + $namespaceIdentity)
    }

    $detectedPackageMap = @{}
    foreach ($package in @($sbom.packages | Where-Object { [string]$_.SPDXID -cne 'SPDXRef-RootPackage' })) {
        $key = "$([string]$package.name)|$([string]$package.versionInfo)".ToLowerInvariant()
        $detectedPackageMap[$key] = $package
    }
    foreach ($expected in $expectedPackages.GetEnumerator()) {
        if (-not $detectedPackageMap.ContainsKey($expected.Key)) {
            throw "Microsoft SBOM Tool omitted a ShareReadOnly locked dependency: $($expected.Value.Name) $($expected.Value.Version)"
        }
    }
    $allowedInferredPackages = @(
        'Microsoft.NETCore.App.Runtime.win-x64|10.0.11',
        'Microsoft.WindowsDesktop.App.Runtime.win-x64|10.0.11',
        'Microsoft.AspNetCore.App.Runtime.win-x64|10.0.11',
        'Microsoft.Windows.SDK.NET.Ref|10.0.19041.57'
    ) | ForEach-Object { $_.ToLowerInvariant() }
    foreach ($detected in $detectedPackageMap.Keys) {
        if (-not $expectedPackages.ContainsKey($detected) -and $detected -notin $allowedInferredPackages) {
            throw "Microsoft SBOM Tool detected a package outside the ShareReadOnly runtime allowlist: $detected"
        }
    }

    $detectedFiles = @{}
    foreach ($file in @($sbom.files)) {
        $relative = ([string]$file.fileName).TrimStart('.', '/').Replace('\', '/')
        if ($detectedFiles.ContainsKey($relative)) { throw "Microsoft SBOM Tool emitted a duplicate file entry: $relative" }
        $sha256 = @($file.checksums | Where-Object { [string]$_.algorithm -ceq 'SHA256' })
        if ($sha256.Count -ne 1) { throw "Microsoft SBOM Tool omitted the SHA-256 for payload file: $relative" }
        $detectedFiles[$relative] = ([string]$sha256[0].checksumValue).ToLowerInvariant()
    }
    if ($detectedFiles.Count -ne $payloadFiles.Count) { throw 'Microsoft SBOM Tool payload file count does not match the staged runtime.' }
    foreach ($payloadFile in $payloadFiles) {
        if (-not $detectedFiles.ContainsKey($payloadFile.RelativePath) -or
            $detectedFiles[$payloadFile.RelativePath] -cne $payloadFile.Sha256) {
            throw "Microsoft SBOM Tool payload hash mismatch: $($payloadFile.RelativePath)"
        }
    }

    foreach ($file in @($sbom.files)) {
        $file.checksums = @($file.checksums | Sort-Object algorithm, checksumValue)
        if ($null -ne $file.PSObject.Properties['licenseInfoInFiles']) {
            $file.licenseInfoInFiles = @($file.licenseInfoInFiles | Sort-Object)
        }
    }
    foreach ($package in @($sbom.packages)) {
        foreach ($propertyName in @('hasFiles', 'dependsOn', 'licenseInfoFromFiles')) {
            if ($null -ne $package.PSObject.Properties[$propertyName]) {
                $package.$propertyName = @($package.$propertyName | Sort-Object)
            }
        }
        if ($null -ne $package.PSObject.Properties['externalRefs']) {
            $package.externalRefs = @($package.externalRefs | Sort-Object referenceCategory, referenceType, referenceLocator)
        }
    }
    $sbom.files = @($sbom.files | Sort-Object fileName)
    $sbom.packages = @($sbom.packages | Sort-Object @{ Expression = { if ([string]$_.SPDXID -ceq 'SPDXRef-RootPackage') { 0 } else { 1 } } }, name, versionInfo, SPDXID)
    $sbom.relationships = @($sbom.relationships | Sort-Object spdxElementId, relationshipType, relatedSpdxElement)
    $normalizedJson = ($sbom | ConvertTo-Json -Depth 20).Replace("`r`n", "`n").TrimEnd() + "`n"
    Assert-NoAbsoluteLocalPath -Text $normalizedJson -Description 'Packaged SBOM'
    [IO.File]::WriteAllText($rawSbomPath, $normalizedJson, [Text.UTF8Encoding]::new($false))

    & $sbomHostFull $toolAssemblyPath validate -b $payloadFull -m (Join-Path $manifestRoot '_manifest') `
        -o $validationPath -mi 'SPDX:2.2' -F false -V Warning
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $validationPath -PathType Leaf)) {
        throw 'Microsoft SBOM Tool validation failed for the normalized SPDX document.'
    }
    $validationText = Get-Content -LiteralPath $validationPath -Raw
    if ($validationText -match '(?i)"isValid"\s*:\s*false|"result"\s*:\s*"failed"') {
        throw 'Microsoft SBOM Tool validation reported a failed result.'
    }

    Copy-Item -LiteralPath $rawSbomPath -Destination $outputFull
    Write-Host "Microsoft SBOM Tool $requiredToolVersion SPDX 2.2 SBOM written and validated: $outputFull"
} finally {
    $workFull = [IO.Path]::GetFullPath($workRoot)
    if (Test-Path -LiteralPath $workFull) {
        $actualWorkParent = [IO.Path]::GetFullPath((Split-Path -Parent $workFull)).TrimEnd(
            [IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
        if (-not [string]::Equals($actualWorkParent, $workCleanupParent, [StringComparison]::OrdinalIgnoreCase) -or
            [IO.Path]::GetFileName($workFull) -notmatch '^\.sbom-work-[0-9a-f]{32}$') {
            throw "Refusing to clean an unexpected SBOM work path: $workFull"
        }
        Remove-Item -LiteralPath $workFull -Recurse -Force
    }
}
