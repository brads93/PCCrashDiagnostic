# Contributing

Contributions that improve evidence quality, privacy, accessibility, reliability, or plain-language explanations are welcome.

## Ground rules

- Preserve the read-only, non-elevated, offline safety boundary.
- Do not add injection, hooks, overlays, input capture, process-memory/module/command-line inspection, kernel drivers, services, scheduled tasks, startup persistence, telemetry, automatic upload, or code that weakens a security control.
- Do not label correlation as causation. Unknown providers and unavailable sources must remain unknown/unavailable.
- Do not commit real reports, event exports, dumps, machine identifiers, or other user data. Use synthetic fixtures.
- Runtime dependencies require a clear need, compatible license, and an update to `THIRD_PARTY_NOTICES.md` and the locked restore files.

## Development workflow

1. Install the SDK pinned in `global.json`.
2. Run `dotnet restore PCCrashDiagnostic.sln --locked-mode`.
3. Make a focused change with tests.
4. Run `dotnet test PCCrashDiagnostic.sln -c Release --no-restore`.
5. Run `tools\Build-Release.ps1` for a release-candidate change.
6. Run `tools\Verify-Release.ps1` against the resulting artifacts.

Code must build with warnings treated as errors. Tests should use deterministic clocks, synthetic event XML, and temporary directories. Platform-dependent tests must report an intentional skip rather than silently pass.

## Pull-request checklist

- Behavior and threat-model impact are described.
- Tests cover success, denied/unavailable sources, and redaction/failure paths.
- User-facing wording distinguishes evidence from inference.
- Report-schema changes update the schema version and `docs/REPORT_FORMAT.md`.
- Documentation, notices, and changelog are updated when applicable.
- No generated `bin`, `obj`, `artifacts`, reports, or personal data is committed.
