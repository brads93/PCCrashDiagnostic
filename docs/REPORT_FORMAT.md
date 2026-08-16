# Report format

PC Crash Diagnostic version 3 writes local ZIP archives and matching `.sha256` files in its own report folder. The normal **Export** action copies only the report ZIP, so recipients are not given a manual checksum step. A missing, denied, timed-out, or unavailable source is recorded explicitly and is never treated as proof that no relevant event occurred.

Version 3 report archives use this prefix:

```text
PCCrashDiagnostic-Report-<UTC timestamp>-<short session id>.zip
```

## Version 3 members

| File | Purpose |
| --- | --- |
| `SUMMARY.txt` | Plain-language evidence, limitations, and next checks. |
| `Report.json` | Complete structured report with `ReportSchemaVersion` set to `3`. |
| `Performance-Samples.csv` | Timestamped system and selected-target counters when monitoring was used. |
| `Windows-Events.json` | Filtered and redacted individual Windows-event fields. |
| `Windows-Event-Groups.json` | Normalized duplicate groups with counts and time ranges. |
| `Reliability.json` | Filtered Reliability Monitor records when available. |
| `Artifacts.json` | Metadata only for relevant Windows-generated artifacts. |
| `Collection-Status.json` | Per-source available, unavailable, denied, timed-out, or error state. |
| `Source-Coverage.json` | Which evidence sources contributed records to the selected window. |
| `Incident.json` | Selected incident, target profile, fingerprint, evidence window, and crash/dump correlation. |
| `Bugchecks.json` | Normalized Windows Error Reporting and Kernel-Power bugcheck records. |
| `Crash-Readiness.json` | Windows dump mode, active filtering, configured/runtime page-file facts, actual destination-volume capacity, and activation state as observed when the report was collected. |
| `Dump-Inventory.json` | Bounded dump metadata and header-recognition state; never dump contents. |
| `Driver-Inventory.json` | Privacy-filtered driver/device facts without IDs, serials, or locations. |
| `Debugger-Analysis.json` | Optional bounded structured debugger result, including allowlisted boot/service black-box facts when reported. Raw debugger output, the local log, and its path are not exported. |
| `Dump-Quality.json` | Optional bounded structural validation for the selected dump and, when available, a Microsoft-signed DumpChk result. |
| `Recent-Changes.json` | Optional privacy-filtered Windows Update and driver-install timing context. |
| `Storage-Health.json` | Optional Windows-reported storage health and reliability counters without persistent device identifiers. |
| `Driver-Verifier.json` | Optional read-only snapshot of existing Driver Verifier settings. The app never enables Driver Verifier. |
| `Manifest.json` | Schema version, session ID, creation time, size, and SHA-256 for every payload member. |

The five optional analysis members are present only when the corresponding analysis exists. Consumers must ignore unknown additive properties and members, and must inspect collection status and source coverage before interpreting absent evidence.

### WinDbg capture limit

The local debugger workflow retains at most 8,388,608 characters (8 Mi characters) from WinDbg standard output and independently retains the same amount from standard error. It continues draining both streams after those limits to avoid blocking the debugger process, but discards excess characters. The local `.log` is therefore a bounded capture and is not guaranteed to be a complete debugger transcript.

When either stream exceeds its limit, the local log contains a truncation notice and the `Limitation` field in `Debugger-Analysis.json` states that structured fields may be incomplete. The raw streams, bounded local log, and local path are never report members.

## Evidence and correlation

Incident fingerprints are deterministic SHA-256 identifiers derived from bounded incident identity fields. They are not machine or user identifiers.

Bugcheck codes and parameters are normalized from allowlisted event fields. Dump correlation can be based on an exact recorded path, exact filename, or timestamp proximity. Correlation does not establish cause.

WHEA severity comes from the shared event-ID catalog. Unknown IDs remain unknown; message wording is not used to invent a severity classification in the version 3 incident foundation.

## Privacy properties

The dump inventory reads at most 32 fixed header bytes to recognize `MDMP`, 32-bit page-dump, or 64-bit page-dump signatures. A separately selected user-mode `MDMP` can be inspected through documented `MiniDumpReadDumpStream` metadata streams, and optional Microsoft tools can perform bounded local analysis. Kernel page-dump contents are not parsed by the built-in reader. Original dump paths used for local correlation are excluded from JSON; exported paths are redacted.

The driver inventory includes only allowlisted descriptive fields. Device IDs, instance paths, hardware IDs, serials, locations, and user names are neither queried nor retained by that collector.

Free-form Windows event messages can still contain identifying information. Extract and inspect every member before sharing a report.

## Elevated-helper boundary

The runtime application includes a separate one-shot UAC helper, but the helper executable and its request files are never report members. A protected-evidence retry returns a bounded, privacy-filtered set of event fields or dump-file metadata for one allowlisted source and the selected report window. The normal process validates, deduplicates, and adds accepted evidence to a newly checksummed report. Raw Event Log XML and dump contents never enter the standard report.

When the user explicitly approves protected dump staging, the helper can copy one validated `.dmp` from `MEMORY.DMP`, Windows Minidump, or LiveKernelReports into the app's private staging root and compute its SHA-256. That staged dump remains outside the standard report. Dump contents enter only a separately requested dump package or an explicitly selected local debugger workflow.

Helper denial, cancellation, timeout, BF6-running block, or unavailable source must be represented as unavailable/denied status and must not be converted into a finding that the evidence does not exist.

Crash-capture plans and rollback receipts are local control data, not report members. Preparing or restoring settings does not rewrite the historical report that led to the action. A later report records the settings actually active when that later incident was collected.

## Transactional export

Reports are assembled in randomly named hidden staging files under the selected data root. The app writes and hashes every member, publishes the checksum first, and publishes the final-looking archive last as the commit point. Cancellation removes packaging partials. A completed report ZIP therefore has a matching checksum file.

The checksum file uses the standard form:

```text
<lowercase SHA-256> *<archive filename>
```

## Legacy version 2 compatibility

Version 2 reports retain `ReportSchemaVersion` `2`, their original member set, and the `BF6-Diagnostic-Report-...zip` prefix. Version 3 does not rename or rewrite existing version 2 archives. Consumers should select behavior from `ReportSchemaVersion`, not filename alone.

## Dump packages

Dump contents never appear in a standard report. An explicitly requested dump package is a separate `PCCrashDiagnostic-Dump-Package-...zip` archive with its own privacy warning, manifest, and checksum. Treat it as sensitive memory data. Protected dump staging and packaging are blocked while `BF6.exe` is running.
