[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$RestoreArtifactsRoot,
    [Parameter(Mandatory)][string]$PublishRoot,
    [Parameter(Mandatory)][string]$OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Reflection.Metadata

$artifactsFull = [IO.Path]::GetFullPath($RestoreArtifactsRoot)
$publishFull = [IO.Path]::GetFullPath($PublishRoot)
$outputFull = [IO.Path]::GetFullPath($OutputPath)
$appBin = Join-Path $artifactsFull 'bin\PCCrashDiagnostic.App\release_win-x64'
if (-not (Test-Path -LiteralPath $appBin -PathType Container)) { throw "Public App IL output not found: $appBin" }

$expectedAssemblies = @(
    'PCCrashDiagnostic.Contracts.dll',
    'PCCrashDiagnostic.Core.dll',
    'PCCrashDiagnostic.LocalTools.dll',
    'PCCrashDiagnostic.dll'
)
$assemblies = @(Get-ChildItem -LiteralPath $appBin -Filter 'PCCrashDiagnostic*.dll' -File | Sort-Object Name)
if (@(Compare-Object $expectedAssemblies @($assemblies.Name)).Count -ne 0) {
    throw 'Public App IL output does not contain exactly the four ShareReadOnly assemblies.'
}
$executables = @(Get-ChildItem -LiteralPath $publishFull -Filter '*.exe' -File)
if ($executables.Count -ne 1 -or $executables[0].Name -cne 'PCCrashDiagnostic.exe') {
    throw 'Published payload must contain exactly one PCCrashDiagnostic.exe.'
}

$forbidden = @('PCCrashDiagnostic.Privileged', 'PCCrashDiagnostic.ElevatedHelper', 'BF6CrashDiagnostic.App')
$referenceCount = 0
$resourceCount = 0
$typeReferenceCount = 0
foreach ($assembly in $assemblies) {
    $stream = [IO.File]::OpenRead($assembly.FullName)
    try {
        $pe = [Reflection.PortableExecutable.PEReader]::new($stream)
        try {
            if (-not $pe.HasMetadata) { throw "Managed metadata is missing from $($assembly.Name)." }
            $reader = [Reflection.Metadata.PEReaderExtensions]::GetMetadataReader($pe)
            foreach ($handle in $reader.AssemblyReferences) {
                $name = $reader.GetString($reader.GetAssemblyReference($handle).Name)
                $referenceCount++
                if ($name -in $forbidden) { throw "Public IL references forbidden assembly: $name" }
            }
            foreach ($handle in $reader.TypeReferences) {
                $typeReference = $reader.GetTypeReference($handle)
                $namespace = $reader.GetString($typeReference.Namespace)
                $typeReferenceCount++
                if (@($forbidden | Where-Object { $namespace.StartsWith($_, [StringComparison]::Ordinal) }).Count -ne 0) {
                    throw "Public IL references forbidden namespace: $namespace"
                }
            }
            foreach ($handle in $reader.ManifestResources) {
                $resourceName = $reader.GetString($reader.GetManifestResource($handle).Name)
                $resourceCount++
                if ($resourceName -match '(?i)(?:\.pfx|\.p12|\.key|secret|credential)' -or
                    @($forbidden | Where-Object { $resourceName.Contains($_, [StringComparison]::Ordinal) }).Count -ne 0) {
                    throw "Public assembly contains a forbidden resource name: $resourceName"
                }
            }
        } finally { $pe.Dispose() }
    } finally { $stream.Dispose() }

    $bytes = [IO.File]::ReadAllBytes($assembly.FullName)
    $ascii = [Text.Encoding]::UTF8.GetString($bytes)
    $unicode = [Text.Encoding]::Unicode.GetString($bytes)
    foreach ($text in $forbidden) {
        if ($ascii.Contains($text, [StringComparison]::Ordinal) -or $unicode.Contains($text, [StringComparison]::Ordinal)) {
            throw "Public assembly bytes contain forbidden profile identity '$text': $($assembly.Name)"
        }
    }
}

$result = [ordered]@{
    SchemaVersion = 1
    PublicIlAndResourceAuditPassed = $true
    AssemblyCount = $assemblies.Count
    AssemblyReferenceCount = $referenceCount
    TypeReferenceCount = $typeReferenceCount
    ManifestResourceCount = $resourceCount
    PublishedExecutableCount = $executables.Count
    ForbiddenFindingCount = 0
    Privacy = 'Aggregate counts only; no local paths, symbols, type names, or resource names are recorded.'
}
$parent = Split-Path -Parent $outputFull
if (-not (Test-Path -LiteralPath $parent -PathType Container)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
[IO.File]::WriteAllText($outputFull, (($result | ConvertTo-Json -Depth 5).Replace("`r`n", "`n").TrimEnd() + "`n"), [Text.UTF8Encoding]::new($false))
Write-Host "Public IL/resource audit passed for $($assemblies.Count) assemblies."
