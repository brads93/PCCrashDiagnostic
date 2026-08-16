[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$DotNetPath = 'dotnet'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$testProject = Join-Path $repoRoot 'tests\BF6CrashDiagnostic.Tests\BF6CrashDiagnostic.Tests.csproj'

if (Test-Path -LiteralPath $DotNetPath -PathType Leaf) {
    $resolvedDotNet = [IO.Path]::GetFullPath($DotNetPath)
} else {
    $dotNetCommand = Get-Command -Name $DotNetPath -CommandType Application -ErrorAction Stop
    $resolvedDotNet = $dotNetCommand.Source
}

if (-not (Test-Path -LiteralPath $testProject -PathType Leaf)) {
    throw "Test project was not found: $testProject"
}

Write-Host 'Running offline synthetic diagnostic scenarios.'
Write-Host 'This does not launch BF6, write Windows events, trigger a GPU reset, create a dump, or crash Windows.'
Write-Host 'Inputs are fixed fixtures; report files are created only under the test runner temporary directory.'

Push-Location $repoRoot
try {
    & $resolvedDotNet test $testProject `
        -c $Configuration `
        --no-restore `
        --filter 'Category=SyntheticScenario' `
        --nologo `
        --verbosity normal
    if ($LASTEXITCODE -ne 0) {
        throw "Synthetic scenario tests failed with exit code $LASTEXITCODE. Restore the locked solution first if packages are unavailable."
    }
} finally {
    Pop-Location
}

Write-Host 'Synthetic scenario tests passed.'
