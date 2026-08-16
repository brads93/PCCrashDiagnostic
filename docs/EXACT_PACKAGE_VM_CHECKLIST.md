# Exact-package disposable-VM checklist

This checklist is an external release gate. Passing source tests or an unsigned
candidate does not satisfy it.

## Evidence identity

Record before testing:

- release version and feature profile;
- exact Git tag and commit;
- runtime ZIP filename, size, and SHA-256;
- `ReleaseManifest.json` SHA-256;
- executable SHA-256 after extracting the ZIP;
- Authenticode publisher, certificate thumbprint, chain result, and RFC 3161
  timestamp result;
- VM image/build, architecture, locale, snapshot ID, and UTC test time; and
- tester/reviewer identity.

Do not modify or repack the ZIP after recording these values. Any byte change
invalidates the result.

## Clean environment

- Start from a fresh disposable Windows 11 x64 snapshot.
- Use a standard-user account.
- Apply normal Windows security controls; do not disable Defender, SmartScreen,
  UAC, code integrity, or firewall logging.
- Capture a before snapshot of processes, services, scheduled tasks, startup
  entries, relevant registry areas, network connections, and filesystem roots.
- Scan the exact extracted folder with Microsoft Defender and retain the result.

## Trust and launch

- Confirm the ZIP contains exactly one `.exe`, `PCCrashDiagnostic.exe`.
- Verify Authenticode and RFC 3161 against the expected publisher.
- Launch normally as the standard user.
- Fail the gate if UAC appears, an elevated/helper process starts, or the app
  requests credentials.
- Confirm the UI reports ShareReadOnly and no administrator access.

## Functional checks

- Search each supported time range and handle a period with no incident.
- Select and analyze a synthetic/fixture-backed blue-screen or restart incident.
- Select an ordinary application incident.
- Start monitoring, cancel while waiting, and verify cancellation cleanup.
- Monitor a harmless test process through normal exit; confirm the result says
  app closed unless Windows evidence establishes more.
- Open a valid prior schema-3 report.
- Reject a malformed, truncated, substituted, or unsupported report.
- Review crash-readiness and source-coverage behavior when a source is
  available, missing, denied, and timed out.
- Preview, copy, and save a safe summary; confirm Copy and Save match the exact
  preview bytes.
- Confirm the advanced technical export requires its warning/confirmation and
  contains no dump bytes or raw debugger output.
- Move one report and all history to the Recycle Bin; confirm no unrelated file
  is selected and restored reports can reappear.

## Security observations

- Confirm no unexpected network request during launch, collection, monitoring,
  history, safe-summary, technical-export, or deletion workflows.
- Confirm no service, driver, task, startup entry, installer registration,
  firewall exception, or machine setting is created or changed.
- Confirm writes are limited to expected local app/report/export/Recycle Bin
  activity.
- Confirm no registry/page-file/crash-control/WER setting changes.
- Confirm no process-memory/module/command-line/input or anti-cheat interaction.
- Confirm cancellation and exit leave no child process or partial export.
- Compare the after snapshot with the before snapshot and explain every
  persistent difference.

## Evidence handling and decision

Keep raw VM logs restricted because they may contain machine detail. Produce a
sanitized summary with each check marked pass/fail/not-run and attach the exact
package/hash identity. Require an independent reviewer to confirm the binding.
The promotion JSON must match
`.config/release/ExactPackageVmEvidence.schema.json` exactly. It records the
runtime filename/size/hash, pre-promotion release-manifest hash, executable and
source identity, signer and timestamp identity, sanitized VM/build/snapshot
identity, distinct tester and reviewer IDs, test/review times, and aggregate
pass states. Do not put raw logs, local paths, usernames, or machine names in
that JSON.

The gate passes only when every required check passes and unexplained changes
are absent. Record failures without editing the package. Fix the source, assign
a new candidate, rebuild/re-sign, and repeat the entire exact-package test.
