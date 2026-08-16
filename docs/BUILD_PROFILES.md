# Build profiles

PC Crash Diagnostic uses compile-time profiles so a friend-facing binary cannot
reach privileged features merely because a button is hidden.

| Capability | `ShareReadOnly` | `FullDiagnostic` | `WerResearch` |
| --- | --- | --- | --- |
| Standard Windows crash evidence | Yes | Yes | Yes |
| Target monitoring | Yes | Yes | Yes |
| Read-only crash-readiness check | Yes | Yes | Yes |
| Local report history and safe summary | Yes | Yes | Yes |
| Technical report export | Yes | Yes | Yes |
| Elevated helper | No | Yes | Yes |
| Windows setting changes or rollback | No | Yes | Yes |
| Protected dump staging or dump packaging | No | Yes | Yes |
| Per-app WER LocalDumps | No | No | Research only |

## ShareReadOnly

`ShareReadOnly` is the only distributable profile for `3.2.0-beta.1`. Its
solution filter is `PCCrashDiagnostic.Share.slnf`. The runtime package contains
only `PCCrashDiagnostic.exe`, starts as the signed-in standard user, does not ask
for UAC, and cannot apply or restore Windows crash settings.

The profile can read diagnostic records available to the current user, inspect
crash-readiness configuration without changing it, monitor matching process
counters, create local reports, export a reviewed safe summary, export an
advanced technical report after confirmation, and move its own reports to the
Recycle Bin.

## FullDiagnostic

`FullDiagnostic` retains the earlier privileged diagnostic architecture for
continued engineering and migration work. It is not packaged by
`tools/Build-Release.ps1` and is not approved for friend or public distribution.
Its solution filter is `PCCrashDiagnostic.Full.slnf`.
Its helper and settings-changing paths require separate signing, security, and
VM evidence before any future release decision.

## WerResearch

`WerResearch` is a disposable-VM research profile. It is the only profile that
may compile `PCCrashDiagnosticWerLocalDumpCapture=Enabled`. It must never be
shared as a user build or tested on a daily-use PC. WER LocalDumps is keyed by
executable basename and can capture private process memory.

## Build-time enforcement

`Directory.Build.props` rejects unknown profiles, rejects WER capture outside
`WerResearch`, and maps each profile to a distinct compile symbol. The contracts
assembly rejects a ShareReadOnly capability set if any privileged capability is
enabled. Release tooling independently pins `ShareReadOnly` and rejects a
runtime payload containing an elevated helper or more than one executable.

The project guards must also reject crossed graphs: building
`PCCrashDiagnostic.Share.slnf` with `FullDiagnostic`, or
`PCCrashDiagnostic.Full.slnf` with `ShareReadOnly`, is an expected failure.
Either crossed graph succeeding is a release blocker.
