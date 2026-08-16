[CmdletBinding()]
param(
    [string]$RepoRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = Join-Path $PSScriptRoot '..'
}
$repoRootFull = [IO.Path]::GetFullPath($RepoRoot)
$sourceRoot = Join-Path $repoRootFull 'src'
$manifestPath = Join-Path $sourceRoot 'BF6CrashDiagnostic.App\app.manifest'
$appProjectPath = Join-Path $sourceRoot 'BF6CrashDiagnostic.App\BF6CrashDiagnostic.App.csproj'
$configurationStorePath = Join-Path $sourceRoot 'BF6CrashDiagnostic.Core\Collectors\CrashCaptureConfigurationStore.cs'
$protectedHelperPath = Join-Path $sourceRoot 'BF6CrashDiagnostic.Core\Collectors\ProtectedEvidenceHelper.cs'
$advancedModelsPath = Join-Path $sourceRoot 'BF6CrashDiagnostic.Core\Models\AdvancedDiagnosticModels.cs'
$boundedRunnerPath = Join-Path $sourceRoot 'BF6CrashDiagnostic.Core\Collectors\BoundedCommandRunner.cs'
$dumpQualityCollectorPath = Join-Path $sourceRoot 'BF6CrashDiagnostic.Core\Collectors\DumpQualityCollector.cs'
$driverVerifierCollectorPath = Join-Path $sourceRoot 'BF6CrashDiagnostic.Core\Collectors\DriverVerifierCollector.cs'
$winDbgRunnerPath = Join-Path $sourceRoot 'BF6CrashDiagnostic.Core\Analysis\WinDbgRunner.cs'
$elevatedHelperClientPath = Join-Path $sourceRoot 'BF6CrashDiagnostic.Core\Collectors\ElevatedHelperClient.cs'
$desktopInteractionPath = Join-Path $sourceRoot 'BF6CrashDiagnostic.App\Services\DesktopInteractionService.cs'
$buildPropsPath = Join-Path $repoRootFull 'Directory.Build.props'
$releaseBuildPath = Join-Path $repoRootFull 'tools\Build-Release.ps1'
$releaseVerifyPath = Join-Path $repoRootFull 'tools\Verify-Release.ps1'

foreach ($requiredPath in @(
        $sourceRoot,
        $manifestPath,
        $appProjectPath,
        $configurationStorePath,
        $protectedHelperPath,
        $advancedModelsPath,
        $boundedRunnerPath,
        $dumpQualityCollectorPath,
        $driverVerifierCollectorPath,
        $winDbgRunnerPath,
        $elevatedHelperClientPath,
        $desktopInteractionPath,
        $buildPropsPath,
        $releaseBuildPath,
        $releaseVerifyPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath)) {
        throw "Safety scan input is missing: $requiredPath"
    }
}

$sourceFiles = @(
    Get-ChildItem -LiteralPath $sourceRoot -File -Recurse |
        Where-Object {
            $_.Extension -in @('.cs', '.xaml', '.csproj', '.manifest') -and
            $_.FullName -notmatch '[\\/](?:bin|obj)[\\/]'
        }
)
if ($sourceFiles.Count -eq 0) { throw 'No source files were found for the safety scan.' }

$forbiddenPatterns = [ordered]@{
    'network API' = '\b(?:System\.Net|HttpClient|HttpRequestMessage|WebRequest|WebClient|TcpClient|UdpClient|Socket|Dns)\b'
    'native network API' = '\b(?:WinHttp|InternetOpen|InternetConnect|HttpOpenRequest|URLDownloadToFile|BITSManager|ClientWebSocket)\w*\s*\('
    'process memory or injection API' = '\b(?:ReadProcessMemory|WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|QueueUserAPC|NtMapViewOfSection)\s*\('
    'hook, debugger, or input-capture API' = '\b(?:SetWindowsHookEx|GetAsyncKeyState|RegisterRawInputDevices|DebugActiveProcess|Debugger\.Launch|MiniDumpWriteDump)\b'
    'process module or command-line inspection' = '\b(?:Process\s*\.\s*Modules|process(?:es)?\s*\.\s*Modules|MainModule|Win32_Process[^\r\n]*CommandLine|NtQueryInformationProcess)\b'
    'unapproved persistence API' = '\b(?:ServiceController|TaskScheduler|StartupTask|RunOnce)\b'
    'native registry mutation API' = '\bReg(?:SetValue|CreateKey|DeleteKey|DeleteValue|LoadKey|RestoreKey|ReplaceKey)(?:Ex|Transacted)?[AW]?\s*\('
    'security-control weakening command' = '\b(?:Set-MpPreference|DisableAntiSpyware|nointegritychecks|testsigning|DisableRealtimeMonitoring)\b'
    'command interpreter launch' = '(?i)\b(?:cmd|powershell|pwsh|wscript|cscript|mshta|rundll32)(?:\.exe)?\b'
    'shell command argument' = '(?i)["''](?:/c|/k|-command|-encodedcommand|-enc)["'']'
    'repair or mutating disk command' = '(?i)\b(?:sfc|dism|chkdsk|Repair-WindowsImage)(?:\.exe)?\b'
    'reboot or shutdown API' = '(?i)\b(?:shutdown\.exe|Restart-Computer|Stop-Computer|ExitWindowsEx|InitiateSystemShutdown(?:Ex)?|Win32Shutdown)\b'
    'forced-crash mechanism' = '(?i)\b(?:NtRaiseHardError|RtlAdjustPrivilege|RaiseFailFastException|Environment\.FailFast|NotMyFault|CrashOnCtrlScroll|NMICrashDump|KeBugCheck(?:Ex)?)\b'
    'stress-test launcher' = '(?i)\b(?:prime95|furmark|occt|memtest86|memtest64|y-cruncher)(?:\.exe)?\b'
    'Driver Verifier mutation argument' = '(?i)["'']/(?:reset|standard|all|driver|bootmode|volatile|flags)\b'
}

$violations = New-Object System.Collections.Generic.List[string]
foreach ($category in $forbiddenPatterns.Keys) {
    foreach ($match in (Select-String -LiteralPath $sourceFiles.FullName -Pattern $forbiddenPatterns[$category] -AllMatches)) {
        $relative = $match.Path.Substring($repoRootFull.Length).TrimStart('\', '/')
        $violations.Add("$category at $relative`:$($match.LineNumber): $($match.Line.Trim())")
    }
}

# Public/friend beta packages must compile the per-executable WER LocalDumps
# mutation surface out. Enabling it remains an explicit developer-only build
# choice and is never accepted by Build-Release.ps1.
$buildProps = Get-Content -LiteralPath $buildPropsPath -Raw
$releaseBuild = Get-Content -LiteralPath $releaseBuildPath -Raw
$releaseVerify = Get-Content -LiteralPath $releaseVerifyPath -Raw
foreach ($contract in @(
        [pscustomobject]@{ Text = $buildProps; Fragment = '<PCCrashDiagnosticWerLocalDumpCapture Condition="''$(PCCrashDiagnosticWerLocalDumpCapture)'' == ''''">Disabled</PCCrashDiagnosticWerLocalDumpCapture>'; Description = 'safe default WER LocalDumps gate' },
        [pscustomobject]@{ Text = $buildProps; Fragment = '<DefineConstants Condition="''$(PCCrashDiagnosticWerLocalDumpCapture)'' == ''Enabled''">$(DefineConstants);PCD_WER_LOCAL_DUMPS</DefineConstants>'; Description = 'explicit WER LocalDumps compile constant' },
        [pscustomobject]@{ Text = $releaseBuild; Fragment = "`$werLocalDumpCapture = 'Disabled'"; Description = 'distributable WER LocalDumps setting' },
        [pscustomobject]@{ Text = $releaseVerify; Fragment = '$expectedWerLocalDumpCapture = $false'; Description = 'verifier WER LocalDumps expectation' })) {
    if (-not $contract.Text.Contains($contract.Fragment, [StringComparison]::Ordinal)) {
        $violations.Add("$($contract.Description) is missing")
    }
}
if (([regex]::Matches($releaseBuild, '-p:PCCrashDiagnosticWerLocalDumpCapture=\$werLocalDumpCapture')).Count -ne 4) {
    $violations.Add('release restore, test, helper publish, and app publish must all force the WER LocalDumps gate')
}
if (([regex]::Matches($releaseBuild, 'WerLocalDumpCaptureEnabled\s*=\s*\$false')).Count -ne 2) {
    $violations.Add('both distributable manifests must record WerLocalDumpCaptureEnabled=false')
}

function Get-RepoRelativePath([string]$Path) {
    return [IO.Path]::GetRelativePath($repoRootFull, [IO.Path]::GetFullPath($Path))
}

function Add-MissingInvariantViolation([string]$Category, [string]$Text, [string]$RequiredPattern) {
    if ($Text -notmatch $RequiredPattern) {
        $violations.Add($Category)
    }
}

# v3.1 intentionally writes only fixed CrashControl values, the PagingFiles
# value needed for exact page-file rollback, and one executable-basename child
# under WER LocalDumps. Keep all mutation primitives in this one reviewed store;
# additions fail closed until this scan is updated.
$registryMutationPattern = '\.\s*(?:SetValue|CreateSubKey|DeleteSubKeyTree|DeleteSubKey|DeleteValue)\s*\('
$managementMutationPattern = '\.\s*Put\s*\('
foreach ($pattern in @($registryMutationPattern, $managementMutationPattern)) {
    foreach ($match in (Select-String -LiteralPath $sourceFiles.FullName -Pattern $pattern -AllMatches)) {
        if (-not [IO.Path]::GetFullPath($match.Path).Equals(
                [IO.Path]::GetFullPath($configurationStorePath),
                [StringComparison]::OrdinalIgnoreCase)) {
            $relative = Get-RepoRelativePath $match.Path
            $violations.Add("registry or WMI mutation outside the fixed configuration store at $relative`:$($match.LineNumber): $($match.Line.Trim())")
        }
    }
}

$configurationStore = Get-Content -LiteralPath $configurationStorePath -Raw
Add-MissingInvariantViolation 'configuration store must pin the HKLM CrashControl path' $configurationStore 'private\s+const\s+string\s+CrashControlPath\s*=\s*@"SYSTEM\\CurrentControlSet\\Control\\CrashControl"\s*;'
Add-MissingInvariantViolation 'configuration store must pin the per-executable HKLM WER LocalDumps path' $configurationStore 'private\s+const\s+string\s+WerLocalDumpsPath\s*=\s*@"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps"\s*;'

if ($configurationStore -match 'Registry\.(?:CurrentUser|ClassesRoot|Users|CurrentConfig)') {
    $violations.Add('the crash-capture configuration store may write only through Registry.LocalMachine')
}

$expectedMutationCounts = [ordered]@{
    '\.\s*Put\s*\(' = 1
    '\.\s*CreateSubKey\s*\(' = 4
    '\.\s*DeleteSubKey\s*\(' = 1
    '\.\s*DeleteSubKeyTree\s*\(' = 0
    '\.\s*DeleteValue\s*\(' = 5
    '\.\s*SetValue\s*\(' = 4
}
foreach ($pattern in $expectedMutationCounts.Keys) {
    $actual = ([regex]::Matches($configurationStore, $pattern)).Count
    $expected = $expectedMutationCounts[$pattern]
    if ($actual -ne $expected) {
        $violations.Add("fixed configuration-store mutation count changed for '$pattern'; expected $expected, found $actual")
    }
}

# The three newly counted primitives above must remain together in the fixed
# PagingFiles restoration method. Removing that method leaves exactly the
# previously reviewed CrashControl and per-executable WER mutation surface.
$pagingWriterMatch = [regex]::Match(
    $configurationStore,
    '(?ms)^\s{4}private static void WritePagingFilesValue\(PageFileConfigurationSnapshot snapshot\)\s*\{.*?^\s{4}\}')
if (-not $pagingWriterMatch.Success) {
    $violations.Add('fixed PagingFiles restoration method could not be verified')
}
else {
    $pagingWriter = $pagingWriterMatch.Value
    foreach ($fragment in @(
            '@"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"',
            'memoryManagement.SetValue("PagingFiles", snapshot.PagingFiles.ToArray(), RegistryValueKind.MultiString)',
            'memoryManagement.DeleteValue("PagingFiles", throwOnMissingValue: false)')) {
        if (-not $pagingWriter.Contains($fragment, [StringComparison]::Ordinal)) {
            $violations.Add("fixed PagingFiles restoration guard is missing: $fragment")
        }
    }

    $pagingMutationCounts = [ordered]@{
        '\.\s*CreateSubKey\s*\(' = 1
        '\.\s*DeleteValue\s*\(' = 1
        '\.\s*SetValue\s*\(' = 1
    }
    foreach ($pattern in $pagingMutationCounts.Keys) {
        $actual = ([regex]::Matches($pagingWriter, $pattern)).Count
        if ($actual -ne $pagingMutationCounts[$pattern]) {
            $violations.Add("PagingFiles restoration mutation count changed for '$pattern'; expected $($pagingMutationCounts[$pattern]), found $actual")
        }
    }

    $configurationWithoutPagingWriter = $configurationStore.Remove(
        $pagingWriterMatch.Index,
        $pagingWriterMatch.Length)
    $priorMutationCounts = [ordered]@{
        '\.\s*CreateSubKey\s*\(' = 3
        '\.\s*DeleteValue\s*\(' = 4
        '\.\s*SetValue\s*\(' = 3
    }
    foreach ($pattern in $priorMutationCounts.Keys) {
        $actual = ([regex]::Matches($configurationWithoutPagingWriter, $pattern)).Count
        if ($actual -ne $priorMutationCounts[$pattern]) {
            $violations.Add("non-PagingFiles configuration-store mutation count changed for '$pattern'; expected $($priorMutationCounts[$pattern]), found $actual")
        }
    }
}

$requiredConfigurationFragments = @(
    'Registry.LocalMachine.CreateSubKey(CrashControlPath, writable: true)',
    'Registry.LocalMachine.CreateSubKey(WerLocalDumpsPath, writable: true)',
    'parentKey.CreateSubKey(safeName, writable: true)',
    'parent.DeleteSubKey(safeName, throwOnMissingSubKey: false)',
    'existing.DeleteValue("DumpType", throwOnMissingValue: false)',
    'existing.DeleteValue("DumpCount", throwOnMissingValue: false)',
    'existing.DeleteValue("DumpFolder", throwOnMissingValue: false)',
    'CrashCaptureSetting.CrashDumpEnabled => ("CrashDumpEnabled", RegistryValueKind.DWord)',
    'CrashCaptureSetting.FilterPages => ("FilterPages", RegistryValueKind.DWord)',
    'CrashCaptureSetting.DumpFile => ("DumpFile", RegistryValueKind.ExpandString)',
    'CrashCaptureSetting.MinidumpDirectory => ("MinidumpDir", RegistryValueKind.ExpandString)',
    'CrashCaptureSetting.EventLogging => ("LogEvent", RegistryValueKind.DWord)',
    'CrashCaptureSetting.OverwriteExistingDump => ("Overwrite", RegistryValueKind.DWord)',
    'NormalizeExecutableName(executableName)'
)
foreach ($fragment in $requiredConfigurationFragments) {
    if (-not $configurationStore.Contains($fragment, [StringComparison]::Ordinal)) {
        $violations.Add("fixed configuration-store guard is missing: $fragment")
    }
}

# The mutating store interface may be called only by the one-shot helper. Main
# app/coordinator/readiness code can instantiate the store for read-only facts.
$writeCallPattern = '\.\s*Write(?:CrashSetting|WerSettings)\s*\('
foreach ($match in (Select-String -LiteralPath $sourceFiles.FullName -Pattern $writeCallPattern -AllMatches)) {
    $fullPath = [IO.Path]::GetFullPath($match.Path)
    if (-not $fullPath.Equals([IO.Path]::GetFullPath($configurationStorePath), [StringComparison]::OrdinalIgnoreCase) -and
        -not $fullPath.Equals([IO.Path]::GetFullPath($protectedHelperPath), [StringComparison]::OrdinalIgnoreCase)) {
        $relative = Get-RepoRelativePath $match.Path
        $violations.Add("crash-capture write invoked outside the fixed helper at $relative`:$($match.LineNumber): $($match.Line.Trim())")
    }
}

$advancedModels = Get-Content -LiteralPath $advancedModelsPath -Raw
$operationMatch = [regex]::Match(
    $advancedModels,
    'public\s+enum\s+ProtectedEvidenceOperation\s*\{(?<body>[^}]*)\}',
    [Text.RegularExpressions.RegexOptions]::Singleline)
if (-not $operationMatch.Success) {
    $violations.Add('ProtectedEvidenceOperation enum could not be verified')
}
else {
    $actualOperations = @(
        $operationMatch.Groups['body'].Value.Split(',') |
            ForEach-Object { ($_ -replace '//.*$', '').Trim() } |
            Where-Object { $_ }
    )
    $allowedOperations = @(
        'RetryNamedSource',
        'CopySelectedDump',
        'ApplyCrashCapturePlan',
        'RestoreCrashCapturePlan',
        'ApplyWerLocalDumpPlan',
        'RestoreWerLocalDumpPlan'
    )
    foreach ($operation in $actualOperations) {
        if ($allowedOperations -notcontains $operation) {
            $violations.Add("unreviewed elevated-helper operation '$operation'")
        }
    }
    foreach ($operation in $allowedOperations) {
        if ($actualOperations -notcontains $operation) {
            $violations.Add("required fixed elevated-helper operation '$operation' is missing")
        }
    }
}

$protectedHelper = Get-Content -LiteralPath $protectedHelperPath -Raw
foreach ($operation in @(
        'ApplyCrashCapturePlan',
        'RestoreCrashCapturePlan',
        'ApplyWerLocalDumpPlan',
        'RestoreWerLocalDumpPlan')) {
    $dispatchPattern = [regex]::Escape("ProtectedEvidenceOperation.$operation") +
        '\s*=>\s*' + [regex]::Escape($operation) + '\s*\('
    if ($protectedHelper -notmatch $dispatchPattern) {
        $violations.Add("fixed elevated-helper dispatch is missing for $operation")
    }
}

# Process starts remain reviewed and shell-free except for the fixed UAC helper
# and Explorer's folder-opening UI action. The generic bounded runner has only
# the two fixed, validated callers below.
$allowedProcessLaunchPaths = @(
    $desktopInteractionPath,
    $winDbgRunnerPath,
    $elevatedHelperClientPath,
    $boundedRunnerPath
) | ForEach-Object { [IO.Path]::GetFullPath($_) }
foreach ($match in (Select-String -LiteralPath $sourceFiles.FullName -Pattern 'new\s+ProcessStartInfo\b|\bProcess\.Start\s*\(' -AllMatches)) {
    if ($allowedProcessLaunchPaths -notcontains [IO.Path]::GetFullPath($match.Path)) {
        $relative = Get-RepoRelativePath $match.Path
        $violations.Add("unreviewed process-launch site at $relative`:$($match.LineNumber): $($match.Line.Trim())")
    }
}

$allowedBoundedCallers = @($dumpQualityCollectorPath, $driverVerifierCollectorPath) |
    ForEach-Object { [IO.Path]::GetFullPath($_) }
foreach ($match in (Select-String -LiteralPath $sourceFiles.FullName -Pattern 'new\s+BoundedCommandRequest\s*\(' -AllMatches)) {
    if ($allowedBoundedCallers -notcontains [IO.Path]::GetFullPath($match.Path)) {
        $relative = Get-RepoRelativePath $match.Path
        $violations.Add("unreviewed bounded-command caller at $relative`:$($match.LineNumber): $($match.Line.Trim())")
    }
}

$boundedRunner = Get-Content -LiteralPath $boundedRunnerPath -Raw
foreach ($fragment in @(
        'UseShellExecute = false',
        'RedirectStandardInput = true',
        'process.StandardInput.Close()',
        'process.Kill(entireProcessTree: true)')) {
    if (-not $boundedRunner.Contains($fragment, [StringComparison]::Ordinal)) {
        $violations.Add("bounded-command safety guard is missing: $fragment")
    }
}

$driverVerifierCollector = Get-Content -LiteralPath $driverVerifierCollectorPath -Raw
if ($driverVerifierCollector -notmatch 'new\s+BoundedCommandRequest\s*\(\s*_executablePath\s*,\s*\["/querysettings"\]') {
    $violations.Add('Driver Verifier must be invoked only with the read-only /querysettings argument')
}
foreach ($fragment in @(
        'Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "verifier.exe")',
        'if (!_validator.IsAllowed(_executablePath))')) {
    if (-not $driverVerifierCollector.Contains($fragment, [StringComparison]::Ordinal)) {
        $violations.Add("Driver Verifier read-only guard is missing: $fragment")
    }
}

foreach ($match in (Select-String -LiteralPath $sourceFiles.FullName -Pattern '(?i)["'']verifier(?:\.exe)?["'']' -AllMatches)) {
    if (-not [IO.Path]::GetFullPath($match.Path).Equals(
            [IO.Path]::GetFullPath($driverVerifierCollectorPath),
            [StringComparison]::OrdinalIgnoreCase)) {
        $relative = Get-RepoRelativePath $match.Path
        $violations.Add("Driver Verifier referenced outside the read-only collector at $relative`:$($match.LineNumber): $($match.Line.Trim())")
    }
}

$dumpQualityCollector = Get-Content -LiteralPath $dumpQualityCollectorPath -Raw
foreach ($fragment in @(
        'if (!_validator.IsAllowed(request.DumpChk))',
        'request.DumpChk.Path',
        '[Path.GetFullPath(request.Dump.OriginalPath)]')) {
    if (-not $dumpQualityCollector.Contains($fragment, [StringComparison]::Ordinal)) {
        $violations.Add("DumpChk fixed-command guard is missing: $fragment")
    }
}

$winDbgRunner = Get-Content -LiteralPath $winDbgRunnerPath -Raw
foreach ($fragment in @(
        'if (!_validator.IsAllowedDebugger(request.Debugger))',
        'if (_userTokenInspector.IsElevated())',
        'UseShellExecute = false',
        'RedirectStandardInput = true',
        'startInfo.ArgumentList.Add("-sins")',
        'startInfo.ArgumentList.Add("-z")',
        'startInfo.ArgumentList.Add("-c")',
        'process.StandardInput.Close()')) {
    if (-not $winDbgRunner.Contains($fragment, [StringComparison]::Ordinal)) {
        $violations.Add("WinDbg fixed-command guard is missing: $fragment")
    }
}

$desktopInteraction = Get-Content -LiteralPath $desktopInteractionPath -Raw
foreach ($fragment in @(
        'FileName = "explorer.exe"',
        'ArgumentList = { folderPath }',
        'UseShellExecute = true')) {
    if (-not $desktopInteraction.Contains($fragment, [StringComparison]::Ordinal)) {
        $violations.Add("Explorer folder-launch guard is missing: $fragment")
    }
}

$elevatedHelperClient = Get-Content -LiteralPath $elevatedHelperClientPath -Raw
foreach ($fragment in @(
        'private const string HelperFileName = "PCCrashDiagnostic.ElevatedHelper.exe"',
        'FileName = _helperPath',
        'Verb = "runas"',
        'startInfo.ArgumentList.Add(ticket.RequestId)')) {
    if (-not $elevatedHelperClient.Contains($fragment, [StringComparison]::Ordinal)) {
        $violations.Add("fixed UAC-helper launch guard is missing: $fragment")
    }
}
if (([regex]::Matches(
            ($sourceFiles | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n",
            'Verb\s*=\s*"runas"')).Count -ne 1) {
    $violations.Add('there must be exactly one reviewed runas launch site for the fixed elevated helper')
}

$manifest = Get-Content -LiteralPath $manifestPath -Raw
if ($manifest -notmatch 'requestedExecutionLevel\s+level="asInvoker"\s+uiAccess="false"') {
    $violations.Add('application manifest must request asInvoker with uiAccess=false')
}
if ($manifest -match 'requireAdministrator|highestAvailable|autoElevate') {
    $violations.Add('application manifest contains an elevation request')
}

[xml]$appProject = Get-Content -LiteralPath $appProjectPath -Raw
$properties = $appProject.Project.PropertyGroup
$expectedProperties = [ordered]@{
    TargetFramework = 'net10.0-windows10.0.19041.0'
    UseWPF = 'true'
    RuntimeIdentifier = 'win-x64'
    SelfContained = 'true'
    PublishSingleFile = 'true'
    PublishTrimmed = 'false'
}
foreach ($propertyName in $expectedProperties.Keys) {
    $value = [string](($properties | Where-Object { $_.$propertyName } | Select-Object -First 1).$propertyName)
    if ($value -cne $expectedProperties[$propertyName]) {
        $violations.Add("application project property $propertyName must be '$($expectedProperties[$propertyName])'; found '$value'")
    }
}

$allowedPackages = @(
    'Microsoft.NET.Test.Sdk',
    'System.Diagnostics.PerformanceCounter',
    'System.Management',
    'xunit',
    'xunit.runner.visualstudio'
)
foreach ($projectPath in (Get-ChildItem -LiteralPath $repoRootFull -Filter '*.csproj' -File -Recurse |
        Where-Object { $_.FullName -notmatch '[\\/](?:bin|obj)[\\/]' } |
        Select-Object -ExpandProperty FullName)) {
    [xml]$project = Get-Content -LiteralPath $projectPath -Raw
    foreach ($reference in @($project.SelectNodes("//*[local-name()='PackageReference']"))) {
        $name = [string]$reference.GetAttribute('Include')
        if ($allowedPackages -notcontains $name) {
            $relative = $projectPath.Substring($repoRootFull.Length).TrimStart('\', '/')
            $violations.Add("unapproved package reference '$name' in $relative")
        }
    }
}

if ($violations.Count -gt 0) {
    throw "Safety boundary scan failed:`n- $($violations -join "`n- ")"
}

Write-Host "Safety boundary scan passed: $($sourceFiles.Count) source file(s), fixed crash-capture writes, reviewed command launches, approved dependencies, asInvoker manifest." -ForegroundColor Green
