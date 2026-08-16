# PC Crash Diagnostic

PC Crash Diagnostic is a portable, open-source Windows app that collects local
evidence around blue screens, unexpected restarts, application crashes or
hangs, and display-driver resets. Battlefield 6 is included as a monitoring
preset, but the app is for general Windows crash triage.

The app reports what Windows recorded, possible relevance, limitations, and a
next check. It does not claim that one event, driver name, or hardware category
proves a root cause.

This project is unofficial and is not affiliated with or endorsed by
Electronic Arts, Battlefield Studios, Microsoft, AMD, NVIDIA, or their
affiliates.

## 3.2.0-beta.1: ShareReadOnly

Version `3.2.0-beta.1` introduces a compile-time `ShareReadOnly` profile for the
friend-facing app. This is a separate application graph, not the earlier
settings-changing UI with buttons hidden.

The ShareReadOnly package:

- contains one executable, `PCCrashDiagnostic.exe`;
- runs as the signed-in standard user and never asks for UAC;
- cannot launch an elevated helper, change or restore Windows settings,
  configure WER LocalDumps, stage protected dumps, or package dump bytes;
- makes no telemetry, upload, updater, or automatic repair request;
- keeps reports local until the user exports them; and
- offers a reviewed safe summary before the advanced technical report.

The release infrastructure currently creates candidates. Do not send a build
to a friend until its manifest is explicitly approved after Authenticode,
RFC 3161 timestamp, and exact-package disposable-VM gates. An unsigned or
**signed awaiting VM** artifact is not a shareable release.

See [Build profiles](docs/BUILD_PROFILES.md),
[Code signing policy](CODE_SIGNING_POLICY.md), and
[Release process](docs/RELEASE_PROCESS.md).

Free code signing provided by SignPath.io, certificate by SignPath Foundation
([SignPath.io](https://signpath.io/), [SignPath Foundation](https://signpath.org/)).

## Main workflows

- **Windows restarted or showed a blue screen** — search 24 hours, seven days,
  14 days, or a custom period; choose an incident; then collect related Windows
  evidence.
- **An app or game closed or froze** — choose a target and inspect matching
  application evidence.
- **Monitor an app for the next problem** — observe all matching process
  instances without reading their memory, modules, command lines, or input.
- **Open a previous report** — validate and review a local report.
- **Local report history** — reopen reports or move selected history to the
  Windows Recycle Bin.

A monitored process disappearing is recorded as **app closed**, not
automatically as a crash. The monitor waits for two missed samples and then
polls Windows evidence for up to 60 seconds.

## Diagnostic coverage

Depending on what Windows exposes to the standard user, collection can include:

- normalized bugcheck codes and parameters;
- WER 1001, Kernel-Power 41, EventLog 6008, boot changes, and dump-write
  evidence;
- WHEA processor, memory, PCIe, and generic hardware categories without
  declaring a component defective;
- narrowly filtered storage, filesystem, Windows Memory Diagnostic, GPU reset,
  application-error, and application-hang records;
- dump inventory and bounded header recognition for accessible dump files;
- privacy-filtered driver/device context;
- recent Windows Update and bounded driver-install timing context;
- Windows-reported storage health when available;
- a read-only query of existing Driver Verifier settings; and
- crash-capture readiness, including dump mode, page-file facts, destination
  accessibility, and free-space estimates.

The readiness card is read-only. This build cannot prepare the PC, improve an
existing dump, or change how the next dump is captured.

If a source is denied, unavailable, or times out, the report says so. The UI
uses: **No cause was identified in the Windows records this app could read.**

## Results and sharing

Results distinguish the observation, evidence label, possible relevance,
limitation, and next check. Source coverage stays visible so missing records are
not mistaken for proof that nothing occurred.

Use **Review safe summary** first. Copy and Save use the exact previewed bytes.
The advanced technical report contains structured Windows evidence and more
machine detail, so it requires a separate confirmation. Neither export contains
crash-dump bytes or raw debugger logs.

Read [Sharing results with a helper](docs/SUPPORT_SUMMARY.md) and
[Privacy](PRIVACY.md) before sending a report.

## Battlefield 6 boundary

The app does not inject into, hook, automate, or send input to Battlefield 6.
It does not inspect process memory, modules, command lines, game files, or
anti-cheat data. Monitoring uses ordinary aggregate process counters exposed by
Windows.

## Local data

Version 3 uses `%LocalAppData%\PCCrashDiagnostic` for reports, history, and
session data. Version 2 data under `%LocalAppData%\UnofficialBF6Diagnostic` is
left unchanged. The app has no cloud account or server-side copy.

Moving a report to the Recycle Bin is recoverable and is not secure erasure.
Restored files may reappear in history.

## Build and test

Requirements:

- Windows x64;
- .NET SDK `10.0.400`, pinned by `global.json`;
- Microsoft.NETCore.App runtime `8.0.30` for the pinned SBOM tool during
  release packaging only (it is not part of the app package); and
- Windows PowerShell 5.1 or PowerShell 7+.

Restore and test only the distributable graph:

```powershell
dotnet restore .\PCCrashDiagnostic.Share.slnf --locked-mode `
  -p:PCCrashDiagnosticFeatureProfile=ShareReadOnly `
  -p:PCCrashDiagnosticRuntimeVersion=10.0.11

dotnet test .\PCCrashDiagnostic.Share.slnf -c Release --no-restore `
  -p:PCCrashDiagnosticFeatureProfile=ShareReadOnly `
  -p:PCCrashDiagnosticRuntimeVersion=10.0.11
```

Create an unsigned local candidate from a clean checkout:

```powershell
.\tools\Build-Release.ps1 -OutputRoot C:\release-candidates
```

The builder pins version `3.2.0-beta.1`, profile `ShareReadOnly`, SDK
`10.0.400`, runtime `10.0.11`, and `win-x64`. It uses locked dependencies, runs
the ShareReadOnly test graph and static checks, performs a packaged smoke test,
and emits deterministic archives with:

- schema-3 build/release manifests;
- sanitized test evidence;
- an SPDX 2.2 SBOM generated with the pinned Microsoft SBOM Tool 4.1.5;
- an unattested in-toto/SLSA provenance statement; and
- SHA-256 file identities.

These artifacts improve traceability; they are not a substitute for publisher
signing or final-package testing.

## Release package

A candidate directory contains exactly:

- `PCCrashDiagnostic-3.2.0-beta.1-share-read-only-win-x64.zip`;
- `PCCrashDiagnostic-3.2.0-beta.1-source.zip`;
- `ReleaseManifest.json`; and
- `SHA256SUMS.txt`.

The runtime ZIP contains only one `.exe`. A friend should not be asked to
perform a manual hash ritual; publisher identity comes from the verified
Authenticode signature and trusted release channel. Checksums remain useful to
bind build, signing, and VM evidence to exact bytes.

## Explicit exclusions

PC Crash Diagnostic does not generate forced crashes, enable Driver Verifier,
run stress tests or SMART self-tests, export raw EVTX logs, run automatic
SFC/DISM repairs or `chkdsk /f`, change BIOS or drivers, tune hardware, weaken
security controls, or declare hardware faulty from one record.

Licensed under the [MIT License](LICENSE). See [Development](docs/DEVELOPMENT.md),
[Report format](docs/REPORT_FORMAT.md), [Security](SECURITY.md), and
[Third-party notices](THIRD_PARTY_NOTICES.md).
