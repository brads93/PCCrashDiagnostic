# Development and release

## Toolchain

The repository pins .NET SDK `10.0.302` in `global.json`. Install that SDK (or a compatible patch permitted by the file) from Microsoft. The release targets `net10.0-windows10.0.19041.0` and `win-x64`.

No Visual Studio installation is required for command-line builds. WPF compilation and integration testing require Windows.

## Restore, test, and run

```powershell
dotnet restore .\PCCrashDiagnostic.sln --locked-mode
dotnet test .\PCCrashDiagnostic.sln -c Release --no-restore
dotnet run --project .\src\BF6CrashDiagnostic.App\BF6CrashDiagnostic.App.csproj -c Debug
```

The lock files are authoritative. Use an unlocked restore only when intentionally updating a dependency, review the resulting lock-file diff, and update third-party notices if necessary.

## Release build

```powershell
.\tools\Build-Release.ps1 -Version 3.1.0-beta.1 -Configuration Release -RuntimeIdentifier win-x64
.\tools\Build-Release.ps1 -Version 3.1.0-beta.2 -Configuration Release -RuntimeIdentifier win-x64
```

Useful parameters:

- `-OutputRoot <path>` changes the artifact destination.
- `-Version 3.1.0-beta.1|3.1.0-beta.2` selects the compile-time feature stage and package identity. Beta.1 disables the beta.2 diagnostic additions. Both distributable stages compile new per-app WER apply off.
- `-DotNetPath <path>` selects a specific `dotnet.exe`.
- `-BuildTimestampUtc <ISO-8601 timestamp>` fixes archive timestamps for reproducibility checks.
- `-RequireSignature -ExpectedSignerThumbprint <40-hex thumbprint>` requires a valid Authenticode signature from that certificate plus a timestamp certificate. Do not use this for the unsigned beta.

The script performs a static safety-boundary/dependency scan, locked restore, stage-specific test, single-file publish, staging, deterministic ZIP creation, manifest generation, checksum generation, helper-integrity verification, and packaged stage/version smoke check. Both packages must include the root `00-START-HERE.txt` recipient guide. The script refuses to overwrite an existing release directory. Run the scan alone with `tools\Test-SafetyBoundary.ps1`.

## Verify artifacts

```powershell
.\tools\Verify-Release.ps1 -ArtifactsRoot .\artifacts\3.1.0-beta.1 -ExpectedVersion 3.1.0-beta.1
.\tools\Verify-Release.ps1 -ArtifactsRoot .\artifacts\3.1.0-beta.2 -ExpectedVersion 3.1.0-beta.2
```

Pass `-RequireSignature -ExpectedSignerThumbprint <40-hex thumbprint>` for a signed-release check. Verification checks every listed asset hash, runtime ZIP shape, EXE architecture and signature status, manifest identity, and source ZIP exclusions.

The verifier performs static checks by default and does not launch the packaged EXE. Add `-RunSmokeTest` only after establishing trust in the package; it launches the EXE with `--smoke-test` against a temporary data root and verifies the compiled tool version and feature stage.

Do not exercise live registry writes, crash generation, or rollback on a development workstation during ordinary automated testing. Helper mutation and race tests use in-memory stores; the required live security matrix belongs in disposable Windows VMs.

The machine-wide, basename-keyed WER LocalDumps implementation is retained only for security research. An explicit source test build can compile it with `-p:PCCrashDiagnosticWerLocalDumpCapture=Enabled`; never distribute that build or run its apply workflow outside a disposable VM. Normal builds and `Build-Release.ps1` force this property to `Disabled`, while receipt restore remains available.

## Signing a public release

Obtain an organization-validated or extended-validation code-signing certificate from a CA trusted by Windows. Protect the private key in a hardware token or managed signing service; do not store it in the repository or a general CI secret. Sign the final EXE with SHA-256, include an RFC 3161 timestamp from the CA, verify the signature on a clean Windows machine, then package and hash the signed bytes.

Signing authenticates the publisher and protects integrity after signing. It does not guarantee SmartScreen reputation immediately, and it does not replace reproducible source, checksums, malware scanning, or security review.
