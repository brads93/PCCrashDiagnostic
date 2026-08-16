# Privacy

## Local processing

The `3.2.0-beta.1` ShareReadOnly app has no telemetry, analytics, upload,
updater, cloud account, or automatic network request. It writes reports,
history, and temporary session data under `%LocalAppData%\PCCrashDiagnostic`
unless a supported local test configuration supplies another data root.

The ShareReadOnly app does not ask for administrator access. It cannot configure
crash capture, create WER LocalDumps settings, stage protected dump files, or
package dump bytes. Earlier FullDiagnostic and research code is not part of the
friend-facing application graph.

Version 2 data under `%LocalAppData%\UnofficialBF6Diagnostic` is not moved,
rewritten, or deleted automatically.

## What collection may contain

A schema-3 technical report can contain:

- CPU, GPU, motherboard, firmware, memory, Windows, and driver model/version
  facts;
- privacy-filtered driver/device labels, provider, version, date, INF name,
  signing state, device class, and problem state;
- timestamped system and selected-target performance counters;
- filtered Windows Event Log fields and Reliability Monitor records;
- crash-readiness facts such as dump mode, page-file capacity, redacted dump
  locations, destination capacity, and restart state;
- dump metadata and a bounded header read used to recognize an accessible dump;
- privacy-filtered Windows Update, driver-install timing, storage health, and
  existing Driver Verifier state;
- incident selection, correlation, source coverage, collection status, and
  report-manifest data; and
- ranked observations, limitations, and next checks.

The technical report does not intentionally contain crash-dump contents, raw
Event Log XML, raw debugger output, arbitrary logs, target-process memory,
modules, command lines, user input, game files, credentials, hardware IDs,
serial numbers, device locations, or arbitrary personal files.

Original dump paths may be used briefly for local correlation. Exported paths
are redacted and original paths are excluded from report JSON.

## Safe summary and technical report

**Review safe summary** shows the exact text that Copy or Save will export. It
is the recommended first item to send to a helper. It includes bounded system,
bugcheck, signal-count, readiness, dump-metadata, storage/recent-change, and
source-coverage fields. It excludes event/reliability messages, usernames,
paths, session and device IDs, hashes, dump bytes, raw debugger output, finding
prose, collector error details, process IDs, command lines, modules, inputs, and
anti-cheat data.

The advanced technical ZIP includes more structured machine detail and requires
separate confirmation. Windows event messages are free-form, so redaction can
never be guaranteed. Device names, hardware models, timestamps, software
versions, executable names, and event descriptions may identify a person or PC
when combined. Extract the ZIP and inspect every JSON, CSV, and text member
before sharing it.

Neither export proves a diagnosis. A named driver or hardware category can be
relevant without being the root cause.

## Local history and deletion

History is built from local validated reports. The app can move a selected
report or all recognized history to the Windows Recycle Bin. This is recoverable
deletion, not secure erasure; restored reports may reappear in history.

Close the app and delete unwanted files from the local data root for ordinary
filesystem cleanup. The portable app has no server-side copy to remove. Version
2 and version 3 roots must be handled separately.

## Release evidence

`BUILD-MANIFEST.json`, `ReleaseManifest.json`, `TestEvidence.json`, the SPDX
SBOM, provenance statement, and checksum file contain build identity, package
names, dependency names/versions, test counts, source commit, sizes, and hashes.
The packaged test evidence intentionally excludes test names, machine names,
usernames, and absolute paths. Raw TRX files stay in restricted CI artifacts and
are not included in the runtime ZIP.

A checksum identifies bytes; it does not identify the publisher. Friend-facing
trust depends on a verified Authenticode publisher, a trusted release channel,
and the external release gates described in `CODE_SIGNING_POLICY.md`.
