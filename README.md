# PC Crash Diagnostic

PC Crash Diagnostic is a portable, open-source Windows app for collecting evidence around blue screens, unexpected restarts, application crashes and hangs, and display-driver resets. Battlefield 6 is included as a monitoring preset, but the app is designed for general Windows crash diagnosis.

Everything is processed locally. There is no telemetry, upload, updater, automatic repair, stress test, or automatic driver or BIOS change. A report explains what Windows recorded, what could be relevant, what the evidence does not prove, and what to check next.

This project is unofficial and is not affiliated with or endorsed by Electronic Arts, Battlefield Studios, AMD, Microsoft, or their affiliates.

## Version 3.1 staged betas

The v3.1 work is released in two stages from the same source tree:

| Release | Included |
| --- | --- |
| `3.1.0-beta.1` | Corrected crash-readiness checks, the **Prepare this PC for the next crash** workflow, one UAC prompt, verification, restart status, and rollback. |
| `3.1.0-beta.2` | Everything in beta.1, plus dump-quality checks, recent update/driver timing, storage health, Driver Verifier detection, and WinDbg boot/service black-box summaries. The per-app WER implementation remains source-only behind an explicit developer gate. |

Both are controlled unsigned builds. Because the elevated helper can change the specific crash-capture settings shown in a preview, these builds are for developer and controlled VM testing until both executables are Authenticode-signed and the final bytes pass the disposable-VM security plan. They are not cleared for broad public or friend-to-friend distribution.

## Main workflows

- **Windows restarted or showed a blue screen** — choose an incident, then collect bugcheck, WHEA, dump, driver, storage, and nearby Windows evidence.
- **An app or game closed or froze** — choose an executable or running process and review matching Windows records.
- **Monitor an app for the next problem** — monitor all matching instances without reading process memory, modules, command lines, input, or anti-cheat data.
- **Open a previous report** — review a saved v3 report or import validated v2 reports into local history.
- **Prepare this PC for the next crash** — preview a fixed Automatic Memory Dump configuration, approve one UAC prompt, verify the result, and retain a rollback receipt.

A monitored process disappearing is recorded as **app closed**. The app waits for two missed samples and checks Windows evidence for up to 60 seconds before describing any crash or hang evidence.

## Crash-capture preparation

The recommended preset can set only these values:

- Automatic Memory Dump;
- `%SystemRoot%\MEMORY.DMP`;
- crash-event logging enabled;
- overwrite enabled; and
- Windows-managed page-file sizing when the existing dump backing cannot be shown to be sufficient.

It also clears `FilterPages` so Automatic Memory Dump is not accidentally treated as Active Memory Dump. It does not change automatic restart, `AlwaysKeepMemoryDump`, the minidump directory, or unrelated recovery settings, and it never restarts Windows automatically.

Before UAC, the app shows every current and proposed value, expected disk/privacy effects, and whether a restart is needed. The one-shot helper compares the current values with that preview before writing, verifies every write, and saves the exact previous values in an ACL-restricted receipt. Restore uses another explicit UAC prompt and refuses to overwrite values changed later by another program or policy. A Start-screen restore notice remains available after relaunch or restart.

This cannot improve a dump that already exists. It prepares Windows to capture better evidence from a future crash.

## Per-application dumps: developer testing only

Distributable beta.2 packages compile the WER LocalDumps apply path off. Windows stores this setting in `HKLM` by executable basename, so a later elevated or system process with the same basename could write private memory into the configured location. Signing does not remove that design risk. The normal UI can still restore a validated receipt created by an earlier developer build.

The implementation remains available to explicit source builds for disposable-VM security research; it is not cleared for a daily-use PC or friend distribution.

The Advanced per-app option creates a WER `LocalDumps` entry only for the selected ordinary executable. It never enables global LocalDumps. The fixed configuration uses full user-mode dumps, keeps at most two, and writes to a helper-derived ACL-restricted folder.

The selected ordinary app must be running in the signed-in user session when setup is committed. Critical Windows processes, Battlefield 6, anti-cheat targets, and protected profiles are rejected by the helper. The app asks the user to confirm that a generic executable is not a protected game. Per-app capture can later be disabled and the exact earlier values restored.

Full user-mode dumps can be large and may contain private process memory. Some programs with their own crash reporter may not honor WER LocalDumps. Because Windows keys this setting by executable name, disable capture before later running an executable with that same name as administrator.

## Diagnostic coverage

Standard collection includes:

- normalized bugcheck codes and all four parameters from compatible Windows records;
- WER 1001, Kernel-Power 41, EventLog 6008, dump timestamps, boot changes, and dump-write failures;
- WHEA processor, memory, PCIe, and generic hardware categories from documented records, without declaring a component defective;
- narrowly filtered storage, filesystem, Windows Memory Diagnostic, GPU reset, application error, and application hang evidence;
- crash-readiness, configured and active page-file state, actual dump-volume capacity, and destination accessibility;
- privacy-filtered driver/device context and read-only storage health when Windows exposes it;
- a seven-day Windows Update and bounded SetupAPI driver-install timeline, shown as timing context rather than causation;
- the current result of a timed `verifier /querysettings` query—the app never enables or resets Driver Verifier; and
- bounded dump validation. User-mode `MDMP` structure is checked with documented APIs; kernel dumps receive signature/metadata checks unless a trusted Microsoft tool is available.

When a Microsoft-signed x64 WinDbg or DumpChk installation is found, the app can run it locally, non-elevated, with fixed arguments and a timeout. WinDbg starts with local symbols. A Microsoft public-symbol retry happens only after explicit consent; the dump remains local. Exported debugger fields are labeled **WinDbg reported**, and a named module is never described as a confirmed faulty driver.

The ordinary report never includes dump bytes or raw debugger output.

## Microsoft references

- [Windows memory-dump options](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/memory-dump-file-options)
- [Page-file requirements for crash dumps](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/how-to-determine-the-appropriate-page-file-size-for-64-bit-versions-of-windows)
- [WER per-application LocalDumps](https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps)
- [DumpChk](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/dumpchk)
- [WinDbg `!blackboxbsd`](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-blackboxbsd)
- [Driver Verifier](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier)

## Battlefield 6 boundary

The app does not inject into, hook, automate, or send input to Battlefield 6. It does not inspect process memory, modules, command lines, game files, or anti-cheat data.

While the BF6 preset detects BF6 running, the app blocks dump inspection, dump packaging, helper launch, and debugger launch. Long-running dump tools and copies are cancelled if BF6 starts, and partial private staging data is removed.

## Local files and privacy

Version 3 uses `%LocalAppData%\PCCrashDiagnostic` for reports, history, symbols, sessions, and the one-use helper request/response channel. Administrator-owned receipts, WER dumps, and protected staging use `%ProgramData%\PCCrashDiagnostic\<originating user SID>` so a normal user cannot replace their security-sensitive parent folder. All of it remains on the PC. A custom `--data-root` changes only ordinary report/history/session storage; it cannot redirect elevated requests, receipts, WER dumps, or protected staging.

Version 2 data under `%LocalAppData%\UnofficialBF6Diagnostic` is left unchanged. Validated v2 reports can be imported for history without rewriting the originals.

Crash dumps can contain usernames, paths, chat, documents, credentials, encryption material, or other memory contents. Dump packaging is a separate explicit operation with a privacy warning. Read [PRIVACY.md](PRIVACY.md) before sharing anything.

## Runtime files

Extract the entire runtime ZIP before launching it. The main executable is `PCCrashDiagnostic.exe`; the separate `PCCrashDiagnostic.ElevatedHelper.exe` appears in UAC only after an explicit action that needs administrator access. The main app stays `asInvoker`; the helper handles one allowlisted request and exits. It is not installed as a service and creates no scheduled task, startup entry, driver, or updater.

Each release directory contains:

- `PCCrashDiagnostic-<version>-win-x64.zip`
- `PCCrashDiagnostic-<version>-source.zip`
- `ReleaseManifest.json`
- `SHA256SUMS.txt`

The main app automatically verifies the helper hash before requesting UAC. There is no manual hash step in the UI. Release checksums remain available for developers who want to verify that a package matches an independently obtained release value; a checksum by itself does not identify the publisher.

## Build and test

Requirements:

- Windows x64; the desktop target is Windows 11 x64;
- .NET SDK `10.0.302`, pinned by `global.json`; and
- Windows PowerShell 5.1 or PowerShell 7+.

```powershell
dotnet restore .\PCCrashDiagnostic.sln --locked-mode
dotnet test .\PCCrashDiagnostic.sln -c Release --no-restore
```

Build either staged release:

```powershell
.\tools\Build-Release.ps1 -Version 3.1.0-beta.1
.\tools\Build-Release.ps1 -Version 3.1.0-beta.2
```

The builder uses locked dependencies, runs the full unit/synthetic suite and static safety checks, publishes self-contained Windows x64 executables, produces source/runtime archives, records checksums and signature state, and smoke-checks the packaged version and feature stage. It refuses to overwrite an existing release directory.

Public distribution requires Authenticode signatures and RFC 3161 timestamps for both executables plus security validation of the exact finished package in a fresh disposable Windows VM. Signing does not replace that test.

## Explicit exclusions

PC Crash Diagnostic does not generate forced crashes, enable Driver Verifier, run stress tests or SMART self-tests, export raw EVTX logs, run SFC/DISM repairs, run `chkdsk /f`, change BIOS or drivers, tune hardware, or declare hardware guilty from one record.

Licensed under the [MIT License](LICENSE). See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [docs/REPORT_FORMAT.md](docs/REPORT_FORMAT.md), and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
