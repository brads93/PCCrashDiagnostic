# Security policy

## Supported build

Security work targets `3.2.0-beta.1` with the `ShareReadOnly` profile. The
repository currently produces release candidates; a candidate is not approved
for friend or public distribution until signing, RFC 3161 timestamp, and
exact-package disposable-VM gates are complete.

Earlier `3.1` binaries contain a different privileged architecture and are not
the friend-facing release. They should not be redistributed as substitutes.

## Reporting a vulnerability

Do not attach a crash dump, technical report, Windows event export, username,
machine name, signing secret, or other private data to a public issue. Use the
repository's private security-advisory feature when available. Otherwise contact
the maintainer privately with the affected version/profile, a minimal synthetic
reproduction, expected and observed behavior, and the possible confidentiality
or integrity impact.

## ShareReadOnly boundary

The distributable graph is `PCCrashDiagnostic.Share.slnf`. Its application:

- uses `requestedExecutionLevel=asInvoker`;
- has no reference to the privileged project;
- exposes no settings-apply, settings-restore, protected-evidence, protected
  staging, or dump-packaging API;
- compiles WER LocalDumps capture off;
- contains no elevated helper in the runtime ZIP; and
- rejects the ShareReadOnly capability set if a privileged capability is
  enabled.

The release builder pins this profile and rejects an unexpected executable or
`PCCrashDiagnostic.ElevatedHelper.exe`. The verifier independently requires one
`.exe` named `PCCrashDiagnostic.exe`.

If a purported ShareReadOnly app prompts for UAC, cancel it. No normal workflow
requires administrator access.

## Diagnostic boundary

The app reads diagnostic evidence available to the current user. It must not:

- inject code, install a hook, synthesize input, or read target-process memory,
  modules, or command lines;
- access game files or anti-cheat data;
- change Windows crash settings, WER settings, page files, services, drivers,
  tasks, startup entries, BIOS, or drivers;
- generate a forced crash, enable or reset Driver Verifier, run a stress test,
  run a SMART self-test, or invoke automatic repairs;
- weaken Defender, SmartScreen, UAC, code integrity, or another security
  control; or
- upload reports or diagnostic data.

Moving the app's own validated reports to the Recycle Bin is an explicit,
recoverable user action, not secure erasure.

## Export boundary

Safe-summary Copy and Save must use the exact previewed bytes. Technical report
export requires a separate confirmation and validates the selected local report
before copying it. Standard exports never contain dump bytes or raw debugger
output.

Redaction reduces accidental disclosure but cannot guarantee that free-form
Windows messages are anonymous. Users must review exports before sharing.

## Release trust model

Release construction uses:

- a clean Git commit and optional exact release tag;
- locked NuGet dependencies;
- the pinned .NET SDK and runtime;
- profile-specific build/test and static boundary checks;
- a packaged smoke test;
- deterministic archive construction;
- sanitized test evidence, SPDX SBOM, and unattested provenance; and
- schema-3 manifests and checksums.

These controls establish traceability, not publisher identity. A shareable
release additionally requires the policy in [CODE_SIGNING_POLICY.md](CODE_SIGNING_POLICY.md):
valid Authenticode from the pinned publisher, a verified RFC 3161 timestamp, and
security evidence bound to the exact final runtime ZIP.

The SignPath workflow is disabled unless `SIGNPATH_ENABLED=true` in protected
repository configuration. It accepts only the exact release tag, uploads only
the main executable for signing, never publishes a release, and emits a signed
candidate that remains blocked on external gates. Signing credentials must not
be stored in source or artifacts.

## Exact-package VM gate

The final runtime ZIP must be tested in a fresh disposable Windows VM as a
standard user. Evidence must be bound to the package SHA-256 and cover at least:

- Defender and Authenticode/timestamp checks;
- launch and collection without UAC;
- safe-summary and confirmed technical export;
- malformed/unavailable Windows evidence;
- cancellation and local-history deletion behavior;
- absence of unexpected network traffic, persistence, settings changes, child
  helpers, or extra executables; and
- cleanup after exit.

Any repack, documentation edit inside the ZIP, or signature change invalidates
the evidence. Signing does not replace this validation.

## Dependency and build-system changes

Review changes to lock files, release scripts, GitHub workflows, SignPath
configuration, CODEOWNERS, and signing policy as security-sensitive. Workflow
actions must be pinned to full commit SHAs. Do not enable the signing workflow
until CODEOWNERS is confirmed and all SignPath values are real, reviewed
configuration.
