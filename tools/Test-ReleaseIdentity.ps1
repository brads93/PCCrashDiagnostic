[CmdletBinding()]
param(
    [string]$RepoRoot,

    [switch]$RequireRepositoryIdentity
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Join-Path $PSScriptRoot '..'
}
$repoRootFull = [IO.Path]::GetFullPath($RepoRoot)
$buildScriptPath = Join-Path $repoRootFull 'tools\Build-Release.ps1'
$verifyScriptPath = Join-Path $repoRootFull 'tools\Verify-Release.ps1'

function Assert-ScriptSyntax {
    param([Parameter(Mandatory)][string]$LiteralPath)

    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile(
        $LiteralPath,
        [ref]$tokens,
        [ref]$errors)
    if (@($errors).Count -ne 0) {
        throw "PowerShell syntax error in '$LiteralPath': $($errors[0].Message)"
    }
}

function Assert-ContainsLiteral {
    param(
        [Parameter(Mandatory)][string]$Content,
        [Parameter(Mandatory)][string]$Literal,
        [Parameter(Mandatory)][string]$Description
    )

    if ($Content.IndexOf($Literal, [StringComparison]::Ordinal) -lt 0) {
        throw "$Description is missing required literal '$Literal'."
    }
}

function Assert-DoesNotContainLiteral {
    param(
        [Parameter(Mandatory)][string]$Content,
        [Parameter(Mandatory)][string]$Literal,
        [Parameter(Mandatory)][string]$Description
    )

    if ($Content.IndexOf($Literal, [StringComparison]::Ordinal) -ge 0) {
        throw "$Description retains legacy active-release literal '$Literal'."
    }
}

function Assert-LegacyChecksums {
    param([Parameter(Mandatory)][string]$ReleaseDirectory)

    if (-not (Test-Path -LiteralPath $ReleaseDirectory -PathType Container)) {
        return
    }

    $checksumPath = Join-Path $ReleaseDirectory 'SHA256SUMS.txt'
    if (-not (Test-Path -LiteralPath $checksumPath -PathType Leaf)) {
        throw "Preserved v2 release is missing SHA256SUMS.txt: '$ReleaseDirectory'."
    }

    foreach ($line in (Get-Content -LiteralPath $checksumPath)) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        if ($line -notmatch '^([0-9a-fA-F]{64}) \*([^\\/]+)$') {
            throw "Invalid preserved v2 checksum line: '$line'."
        }

        $filePath = Join-Path $ReleaseDirectory $Matches[2]
        if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
            throw "Preserved v2 checksum references a missing file: '$filePath'."
        }
        $actual = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash
        if ($actual -cne $Matches[1].ToUpperInvariant()) {
            throw "Preserved v2 checksum mismatch: '$filePath'."
        }
    }
}

foreach ($scriptPath in @($buildScriptPath, $verifyScriptPath)) {
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        throw "Required release script is missing: '$scriptPath'."
    }
    Assert-ScriptSyntax -LiteralPath $scriptPath
}

$buildScript = Get-Content -LiteralPath $buildScriptPath -Raw
$verifyScript = Get-Content -LiteralPath $verifyScriptPath -Raw
$combinedScripts = $buildScript + "`n" + $verifyScript

foreach ($literal in @(
        '3.1.0-beta.1',
        '3.1.0-beta.2',
        'PCCrashDiagnosticStage',
        '--artifacts-path',
        'ReleaseStage',
        'Beta2FeaturesEnabled',
        'PCCrashDiagnosticWerLocalDumpCapture',
        'WerLocalDumpCaptureEnabled',
        'Assert-ExecutableVersion',
        '$deterministicPathMap = "$repoRoot=/_/src%2C$workingRoot=/_/build"',
        'PC Crash Diagnostic',
        'PCCrashDiagnostic.exe',
        '"$assetPrefix-$safeVersion-$RuntimeIdentifier.zip"',
        '"$assetPrefix-$safeVersion-source.zip"',
        'PCCrashDiagnostic-source',
        'PCCrashDiagnostic.sln',
        'UNSIGNED BETA',
        'Unsigned beta. Verify SHA-256 through a trusted independent channel before running.',
        "ChecksumAlgorithm = 'SHA-256'",
        'PCCrashDiagnostic.ElevatedHelper.exe',
        'OptionalElevatedHelper',
        'EmbeddedBindingSha256',
        '--verify-helper-binding',
        "requiredSdkVersion = '10.0.302'")) {
    Assert-ContainsLiteral -Content $combinedScripts -Literal $literal -Description 'Release identity scripts'
}

foreach ($literal in @(
        'Unofficial BF6 Crash Diagnostic',
        'BF6CrashDiagnostic.exe',
        'BF6CrashDiagnostic.sln',
        'BF6CrashDiagnostic-source',
        'BF6CrashDiagnostic-$safeVersion',
        'friend-beta')) {
    Assert-DoesNotContainLiteral -Content $combinedScripts -Literal $literal -Description 'Release identity scripts'
}

$stageSpecificTestPattern = '(?s)''test'',\s*\$solutionPath,.*?-p:PCCrashDiagnosticVersion=\$version.*?-p:PCCrashDiagnosticStage=\$releaseStageName.*?-p:PCCrashDiagnosticWerLocalDumpCapture=\$werLocalDumpCapture'
if ($buildScript -notmatch $stageSpecificTestPattern) {
    throw 'Build-Release.ps1 must compile and run tests with the selected version and release-stage properties.'
}
$stageSpecificRestorePattern = '(?s)''restore'',\s*\$solutionPath,.*?-p:PCCrashDiagnosticVersion=\$version.*?-p:PCCrashDiagnosticStage=\$releaseStageName.*?-p:PCCrashDiagnosticWerLocalDumpCapture=\$werLocalDumpCapture'
if ($buildScript -notmatch $stageSpecificRestorePattern) {
    throw 'Build-Release.ps1 must restore with the selected version and release-stage properties.'
}
if ($buildScript.IndexOf('[IO.Directory]::Move($releaseStage, $releaseRoot)', [StringComparison]::Ordinal) -lt 0) {
    throw 'Build-Release.ps1 must publish the final release with a no-overwrite directory move.'
}

Assert-LegacyChecksums -ReleaseDirectory (Join-Path $repoRootFull 'artifacts-qa\2.0.0-beta.1')
Assert-LegacyChecksums -ReleaseDirectory (Join-Path $repoRootFull 'artifacts-repro\2.0.0-beta.1')

if ($RequireRepositoryIdentity) {
    $solutionPath = Join-Path $repoRootFull 'PCCrashDiagnostic.sln'
    $buildPropsPath = Join-Path $repoRootFull 'Directory.Build.props'
    $appProjectPath = Join-Path $repoRootFull 'src\BF6CrashDiagnostic.App\BF6CrashDiagnostic.App.csproj'
    $coreProjectPath = Join-Path $repoRootFull 'src\BF6CrashDiagnostic.Core\BF6CrashDiagnostic.Core.csproj'
    if (-not (Test-Path -LiteralPath $solutionPath -PathType Leaf)) {
        throw "Active solution is missing: '$solutionPath'."
    }

    [xml]$buildProps = Get-Content -LiteralPath $buildPropsPath -Raw
    $buildPropsContent = Get-Content -LiteralPath $buildPropsPath -Raw
    $defaultVersionElement = @($buildProps.Project.PropertyGroup.PCCrashDiagnosticVersion | Select-Object -First 1)[0]
    $defaultStageElement = @($buildProps.Project.PropertyGroup.PCCrashDiagnosticStage | Select-Object -First 1)[0]
    $defaultWerCaptureElement = @($buildProps.Project.PropertyGroup.PCCrashDiagnosticWerLocalDumpCapture | Select-Object -First 1)[0]
    $defaultVersion = [string]$defaultVersionElement.InnerText
    $defaultStage = [string]$defaultStageElement.InnerText
    $defaultWerCapture = [string]$defaultWerCaptureElement.InnerText
    if ($defaultVersion -cne '3.1.0-beta.2' -or $defaultStage -cne 'Beta2') {
        throw "Default build identity must be 3.1.0-beta.2/Beta2; found '$defaultVersion/$defaultStage'."
    }
    if ($defaultWerCapture -cne 'Disabled') {
        throw "Default WER LocalDumps capture gate must be Disabled; found '$defaultWerCapture'."
    }
    foreach ($literal in @(
            '<DefineConstants Condition="''$(PCCrashDiagnosticStage)'' == ''Beta1''">$(DefineConstants);PCD_BETA1</DefineConstants>',
            '<DefineConstants Condition="''$(PCCrashDiagnosticWerLocalDumpCapture)'' == ''Enabled''">$(DefineConstants);PCD_WER_LOCAL_DUMPS</DefineConstants>',
            'Beta1 builds must use PCCrashDiagnosticVersion=3.1.0-beta.1.',
            'Beta2 builds must use PCCrashDiagnosticVersion=3.1.0-beta.2.',
            'PCCrashDiagnosticWerLocalDumpCapture must be Disabled or Enabled.',
            'Per-application WER LocalDumps capture cannot be enabled in Beta1.')) {
        Assert-ContainsLiteral -Content $buildPropsContent -Literal $literal -Description 'Compile-time release-stage contract'
    }
    Assert-ContainsLiteral -Content $buildScript -Literal "`$werLocalDumpCapture = 'Disabled'" -Description 'Distributable WER LocalDumps gate'
    if (([regex]::Matches($buildScript, 'WerLocalDumpCaptureEnabled\s*=\s*\$false')).Count -ne 2) {
        throw 'Both distributable manifests must record WerLocalDumpCaptureEnabled=false.'
    }

    [xml]$project = Get-Content -LiteralPath $appProjectPath -Raw
    $assemblyName = [string](($project.Project.PropertyGroup | Where-Object AssemblyName | Select-Object -First 1).AssemblyName)
    $product = [string](($project.Project.PropertyGroup | Where-Object Product | Select-Object -First 1).Product)
    if ($assemblyName -cne 'PCCrashDiagnostic') {
        throw "Application AssemblyName must be 'PCCrashDiagnostic'; found '$assemblyName'."
    }
    if ($product -cne 'PC Crash Diagnostic') {
        throw "Application Product must be 'PC Crash Diagnostic'; found '$product'."
    }

    [xml]$coreProject = Get-Content -LiteralPath $coreProjectPath -Raw
    if ([string]$coreProject.Project.PropertyGroup.TargetFramework -cne 'net10.0-windows10.0.19041.0') {
        throw 'Core target framework identity changed unexpectedly.'
    }

    $repositoryIdentityFiles = [ordered]@{
        'App identity' = Join-Path $repoRootFull 'src\BF6CrashDiagnostic.App\App.xaml.cs'
        'Command-line identity' = Join-Path $repoRootFull 'src\BF6CrashDiagnostic.App\CommandLineOptions.cs'
        'Application manifest identity' = Join-Path $repoRootFull 'src\BF6CrashDiagnostic.App\app.manifest'
        'Report identity' = Join-Path $repoRootFull 'src\BF6CrashDiagnostic.Core\Reporting\ReportWriter.cs'
        'Dump-package identity' = Join-Path $repoRootFull 'src\BF6CrashDiagnostic.Core\Reporting\DumpPackager.cs'
        'Summary identity' = Join-Path $repoRootFull 'src\BF6CrashDiagnostic.Core\Reporting\SummaryBuilderV3.cs'
        'Recipient guide identity' = Join-Path $repoRootFull '00-START-HERE.txt'
    }
    foreach ($description in $repositoryIdentityFiles.Keys) {
        if (-not (Test-Path -LiteralPath $repositoryIdentityFiles[$description] -PathType Leaf)) {
            throw "$description file is missing: '$($repositoryIdentityFiles[$description])'."
        }
    }

    Assert-ContainsLiteral -Content (Get-Content -LiteralPath $repositoryIdentityFiles['App identity'] -Raw) -Literal 'Local\\PCCrashDiagnostic.Singleton.v3' -Description 'App identity'
    $commandLineContent = Get-Content -LiteralPath $repositoryIdentityFiles['Command-line identity'] -Raw
    Assert-ContainsLiteral -Content $commandLineContent -Literal 'Path.Combine(localAppData, "PCCrashDiagnostic")' -Description 'Command-line default data root'
    Assert-ContainsLiteral -Content $commandLineContent -Literal 'Usage: PCCrashDiagnostic.exe' -Description 'Command-line usage'
    $manifestContent = Get-Content -LiteralPath $repositoryIdentityFiles['Application manifest identity'] -Raw
    Assert-ContainsLiteral -Content $manifestContent -Literal 'version="3.1.0.0" name="PCCrashDiagnostic"' -Description 'Application manifest identity'
    Assert-ContainsLiteral -Content $manifestContent -Literal 'requestedExecutionLevel level="asInvoker"' -Description 'Application manifest execution level'
    $helperManifestPath = Join-Path $repoRootFull 'src\PCCrashDiagnostic.ElevatedHelper\app.manifest'
    if (-not (Test-Path -LiteralPath $helperManifestPath -PathType Leaf)) {
        throw "Elevated-helper manifest is missing: '$helperManifestPath'."
    }
    $helperManifestContent = Get-Content -LiteralPath $helperManifestPath -Raw
    Assert-ContainsLiteral -Content $helperManifestContent -Literal 'version="3.1.0.0" name="PCCrashDiagnostic.ElevatedHelper"' -Description 'Elevated-helper manifest identity'
    Assert-ContainsLiteral -Content $helperManifestContent -Literal 'requestedExecutionLevel level="requireAdministrator"' -Description 'Elevated-helper manifest execution level'
    $reportWriterContent = Get-Content -LiteralPath $repositoryIdentityFiles['Report identity'] -Raw
    Assert-ContainsLiteral -Content $reportWriterContent -Literal 'PCCrashDiagnostic-Report-' -Description 'Version 3 report prefix'
    Assert-ContainsLiteral -Content $reportWriterContent -Literal 'BF6-Diagnostic-Report-' -Description 'Preserved version 2 report prefix'
    Assert-ContainsLiteral -Content (Get-Content -LiteralPath $repositoryIdentityFiles['Dump-package identity'] -Raw) -Literal 'PCCrashDiagnostic-Dump-Package-' -Description 'Dump-package prefix'
    Assert-ContainsLiteral -Content (Get-Content -LiteralPath $repositoryIdentityFiles['Summary identity'] -Raw) -Literal 'PC Crash Diagnostic' -Description 'Version 3 report product text'
    Assert-ContainsLiteral -Content (Get-Content -LiteralPath $repositoryIdentityFiles['Recipient guide identity'] -Raw) -Literal 'This controlled beta is not digitally signed.' -Description 'Unsigned recipient warning'
}

Write-Host 'Release identity checks passed for staged PC Crash Diagnostic 3.1 betas.' -ForegroundColor Green
Write-Host 'Preserved v2 artifacts remain checksum-consistent when present.'
