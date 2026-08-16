# Security policy

## Supported versions

`3.1.0-beta.1` and `3.1.0-beta.2` are controlled unsigned test releases. Older v2 and v3 reports remain useful for comparison, but superseded executables do not receive security fixes.

## Reporting a vulnerability

Do not attach a crash dump, diagnostic report, Windows event export, username, machine name, or other personal data to a public issue. Use the repository's private security-advisory feature when available. Otherwise contact the maintainer privately with the affected version, a minimal synthetic reproduction, expected and observed behavior, and the possible confidentiality or integrity impact.

## Release trust model

- A release contains a runtime ZIP, source ZIP, `ReleaseManifest.json`, and `SHA256SUMS.txt`.
- The builder uses locked dependencies, stage-specific tests, static safety checks, deterministic archives, and packaged version/stage smoke checks.
- The source package is selected by explicit path and extension allowlists. Dumps, reports, logs, secrets, keys, certificates, private package configuration, binaries, and nested archives are rejected.
- The main executable contains the expected elevated-helper SHA-256 and verifies the helper immediately before launch. This is an internal component binding, not a manual UI step or publisher identity check.
- Same-package checksums establish consistency. Publisher trust requires independently pinned Authenticode signatures and timestamps on the final executable bytes.

Both v3.1 betas are unsigned. SmartScreen and UAC may show **Unknown publisher**. Never disable Defender, SmartScreen, UAC, anti-cheat, or another security control for this app.

## One-shot elevated helper

`PCCrashDiagnostic.exe` remains `asInvoker`. `PCCrashDiagnostic.ElevatedHelper.exe` requests administrator rights only after an explicit protected-evidence, prepare, or restore action. The helper processes one expiring random request ID and exits; it is not a service and creates no persistence.

The allowlisted operations are:

- retry one named protected Windows evidence source;
- copy one selected dump from an approved Windows dump root into private staging;
- apply or restore the fixed Automatic Memory Dump plan; and
- apply or restore the fixed per-executable WER LocalDumps plan in beta.2.

The helper never accepts a command, debugger, registry path, destination, dump source, or LocalDumps folder from its elevated command line. Every request is treated as untrusted and must pass independent shape, expiry, report binding, expected-current-value, target, path, file-identity, and feature-stage checks.

For alternate-credential UAC, the helper resolves the one-use request by its random ID through validated Windows profile metadata, rejects zero or multiple matches, validates origin SID and ACL/reparse state, and does not switch data ownership to the administrator account. Durable elevated data is rooted beneath an administrator-owned `%ProgramData%\PCCrashDiagnostic\<origin SID>` ancestor. Receipts and protected staging do not live beneath a user-replaceable parent. Per-app dump folders grant the originating user only the bounded rights needed by the documented WER workflow; they do not grant directory replacement, ACL changes, or arbitrary redirection.

Configuration writes are transactional:

- the preview contains every allowlisted current and proposed value;
- the helper compares each current value, including registry type, immediately before writing it;
- a successful write is recorded for recovery before readback verification;
- partial apply failure restores exact earlier values and types;
- partial restore failure puts the prepared values back;
- rollback is allowed to finish even if a protected target starts after the first setting write; and
- a later program or Group Policy change causes restore to stop instead of overwriting it.

The system preset cannot change automatic restart, `AlwaysKeepMemoryDump`, the minidump directory, arbitrary page-file sizes, or unrelated recovery settings. The app never reboots automatically.

## Per-application WER boundary

The WER apply path is compile-gated off in distributable beta.2 artifacts. WER LocalDumps is machine-wide and keyed by executable basename; the current design cannot guarantee that a future elevated or system process with the same basename will not use that entry. Restore remains enabled so a validated receipt from an earlier developer build can be rolled back. WER apply may be compiled only for disposable-VM research and must not be presented as friend/public-ready.

Beta.2 can configure only `DumpType=2`, `DumpCount=2`, and the helper-derived private folder beneath the per-origin ProgramData root. It never creates global LocalDumps defaults.

Before commit, the helper requires a matching medium-integrity, non-session-0 process owned by the validated originating user. It rejects Battlefield 6, anti-cheat/protected profiles, PC Crash Diagnostic's own executables, critical/system executables, elevated targets, invalid basenames, arbitrary folders, and feature-stage mismatches. Restore uses only a validated private receipt and preserves unknown values or subkeys added later while removing or restoring the three app-owned values.

Full dumps can contain private process memory. Microsoft LocalDumps may not be honored by an application that uses its own crash reporting.

## Dump and debugger boundary

Dump staging is limited to approved Windows roots, files no larger than 64 GiB, recognized dump signatures, validated non-reparse paths, stable file identity, and available private-staging capacity. Data is hashed while copied. Partial staging is removed after cancellation or failure.

DumpChk and WinDbg run only from approved Microsoft-signed x64 installations, non-elevated, with fixed arguments, bounded output, job-object timeout, and process-tree cancellation. WinDbg starts offline. Microsoft public symbols are enabled only after explicit consent, and the dump remains local. Raw debugger output and its path are excluded from standard reports.

## Battlefield 6 boundary

Helper launch, dump inspection, dump packaging, DumpChk, and WinDbg are unavailable while the BF6 preset detects BF6 running. The non-elevated app checks before launch and the helper/tool boundary checks again. Long-running copy or analysis operations stop if BF6 starts; partial results are discarded.

No code injection, graphics/input hooks, synthesized input, process-memory/module/command-line inspection, game-file access, anti-cheat access, or security-control change is permitted.

## Public-distribution gate

The controlled unsigned betas are not approved for broad public or friend-to-friend distribution. A public settings-changing build requires:

- pinned Authenticode signatures and RFC 3161 timestamps on both executables;
- a passing signed-package verification against the final bytes; and
- security testing of that exact package in fresh disposable Windows VMs, including standard-user alternate-credential UAC.

The VM matrix must cover UAC cancellation, malformed/expired/colliding requests, ACL and reparse substitution, parent swaps, target-integrity/ownership checks, compare-and-set races, partial apply and restore, post-write readback failure, stale receipts, repeated rollback, capacity checks, cleanup, BF6 start races, unexpected network traffic, and persistence checks. Signing does not replace this validation.

## Explicitly forbidden behavior

The project must not generate forced crashes, enable Driver Verifier, run stress tests or SMART self-tests, export raw EVTX logs, run automatic SFC/DISM repairs or `chkdsk /f`, change BIOS or drivers, install services/drivers/tasks/startup entries, weaken platform security, upload data, or declare hardware faulty from one event.
