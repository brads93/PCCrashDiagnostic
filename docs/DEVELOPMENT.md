# Development

## Toolchain

The repository pins .NET SDK `10.0.400` with roll-forward disabled in
`global.json`. The ShareReadOnly release targets
`net10.0-windows10.0.19041.0`, `win-x64`, and the serviced .NET runtime
`10.0.11`.

Release packaging also requires build-only Microsoft.NETCore.App runtime
`8.0.30` to run Microsoft SBOM Tool 4.1.5. The builder verifies that exact
runtime before generating SPDX 2.2 output; it is not included in the app.

Command-line WPF builds require Windows. No Visual Studio installation is
required.

## Profiles

The normal distributable graph is `PCCrashDiagnostic.Share.slnf` with:

```text
PCCrashDiagnosticVersion=3.2.0-beta.1
PCCrashDiagnosticFeatureProfile=ShareReadOnly
PCCrashDiagnosticWerLocalDumpCapture=Disabled
PCCrashDiagnosticRuntimeVersion=10.0.11
```

Do not substitute the full solution when making a friend-facing artifact. The
full solution contains non-distributable privileged and WER research projects.
See [BUILD_PROFILES.md](BUILD_PROFILES.md).

## Restore, test, and run

```powershell
$properties = @(
  '-p:PCCrashDiagnosticVersion=3.2.0-beta.1',
  '-p:PCCrashDiagnosticFeatureProfile=ShareReadOnly',
  '-p:PCCrashDiagnosticWerLocalDumpCapture=Disabled',
  '-p:PCCrashDiagnosticRuntimeVersion=10.0.11'
)

dotnet restore .\PCCrashDiagnostic.Share.slnf --locked-mode @properties
dotnet restore .\src\PCCrashDiagnostic.App\PCCrashDiagnostic.App.csproj -r win-x64 --locked-mode @properties
dotnet test .\PCCrashDiagnostic.Share.slnf -c Release --no-restore @properties
dotnet run --project .\src\PCCrashDiagnostic.App\PCCrashDiagnostic.App.csproj -c Debug @properties
```

The lock files are authoritative. Use an unlocked restore only when
intentionally updating dependencies. Review every lock-file diff, third-party
notice impact, and the resulting SBOM before acceptance.

Internal development uses `PCCrashDiagnostic.Full.slnf` with
`PCCrashDiagnosticFeatureProfile=FullDiagnostic`. The compile-time project
guards are intentional: the Share filter must fail under an internal profile,
and the Full filter must fail under `ShareReadOnly`. Test both wrong-profile
failures whenever profile/project guards change; a successful wrong-profile
build is a release blocker.

## Static release checks

```powershell
.\tools\Test-SafetyBoundary.ps1 -ExpectedFeatureProfile ShareReadOnly
.\tools\Test-ReleaseIdentity.ps1 -RequireRepositoryIdentity
```

The safety check validates compile/release gates and workflow pinning. It is not
dynamic malware analysis or exact-package VM evidence.

## Build a candidate

Use a clean checkout. Place output outside the repository for release work:

```powershell
.\tools\Build-Release.ps1 `
  -OutputRoot C:\release-candidates `
  -BuilderId 'local:developer'
```

Use `-RequireExactTag` for a signing input. `-AllowDirtyControlledBuild` exists
only for an unsigned local engineering candidate with modified tracked files;
it rejects untracked files because they cannot be safely and completely bound
to the source ZIP. It cannot be combined with a prebuilt signed executable.

The builder:

1. resolves the Git commit, tree, and clean/dirty state;
2. checks SDK/profile/runtime and static boundaries;
3. restores locked ShareReadOnly dependencies, including the exact `win-x64` App graph;
4. runs tests, a fail-closed NuGet vulnerability audit, and a public
   IL/resource/profile-boundary audit, then creates sanitized `TestEvidence.json`;
5. publishes and smoke-tests one self-contained Windows x64 executable;
6. generates and validates an SPDX 2.2 SBOM with Microsoft SBOM Tool 4.1.5 and writes unattested provenance;
7. produces deterministic runtime/source ZIPs and schema-3 manifests; and
8. statically verifies the candidate and runs the packaged smoke check.

The builder refuses to overwrite an existing candidate directory. It never
sets `ShareApproved=true`.

## Verify a candidate

```powershell
.\tools\Verify-Release.ps1 `
  -ArtifactsRoot C:\release-candidates\3.2.0-beta.1-share-read-only-unsignedcandidate
```

Verification checks manifest identity, package shape, every listed hash,
source exclusions, PE architecture/version, Authenticode state, and packaged
evidence. It extracts to a random temporary directory and does not launch the
EXE unless `-RunSmokeTest` is supplied.

`-RequireShareApproved` is the final verifier mode. It must fail for ordinary
builder/SignPath candidates because exact-package VM approval is still external.

## Reproducibility

Set `SOURCE_DATE_EPOCH` or pass `-BuildTimestampUtc` and build the same clean
commit twice into different output roots. Compare manifests and archive hashes.
If they differ, do not label the build reproducible; inspect file ordering,
timestamps, compiler inputs, and embedded data.

Authenticode changes executable bytes. Preserve the unsigned input hash and
signing-request identity, then bind all signed-candidate and VM evidence to the
signed runtime ZIP hash.

## CI and signing

`.github/workflows/ci.yml` runs the locked ShareReadOnly graph on Windows and
retains raw TRX evidence for seven days. Raw TRX can contain test/machine detail
and is not packaged; `New-TestEvidence.ps1` emits only aggregate counts and the
raw-file hash.

The SignPath workflow is intentionally manual and disabled through repository
configuration. Follow [CODE_SIGNING_POLICY.md](../CODE_SIGNING_POLICY.md) and
[RELEASE_PROCESS.md](RELEASE_PROCESS.md). It produces a signed candidate only;
no workflow publishes a release.

## Testing boundaries

Do not exercise live registry writes, deliberate crashes, Driver Verifier
mutation, stress tests, repair commands, or privileged helper flows on a
development workstation. The ShareReadOnly graph has no such APIs. Any future
privileged security matrix belongs in fresh disposable Windows VMs.
