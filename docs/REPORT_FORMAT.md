# Report format

PC Crash Diagnostic writes local schema-3 ZIP archives and matching internal
checksum files under its data root. The ShareReadOnly app offers two exports:

- a reviewed plain-text **safe summary**; and
- a separately confirmed **technical report ZIP**.

The ordinary export copies the selected file; it does not ask the recipient to
perform a manual checksum step. A missing, denied, timed-out, or unavailable
source is recorded explicitly and is never treated as proof that no relevant
record exists.

Version 3 report archives use:

```text
PCCrashDiagnostic-Report-<UTC timestamp>-<short session id>.zip
```

## Safe summary

The safe-summary preview is authoritative: Copy and Save use exactly those
bytes. It is a plain-text support handoff containing bounded incident identity,
observations, limitations, crash-readiness state, source coverage, and next
checks.

It includes bounded system specifications, bugchecks, signal counts,
crash-readiness, dump metadata, privacy-filtered storage/recent-change facts,
and source coverage. It excludes event/reliability messages, usernames, paths,
session and device IDs, hashes, dump bytes, raw debugger output, finding prose,
collector error details, process IDs, command lines, modules, inputs,
anti-cheat data, and report internals.

## Technical report members

| File | Purpose |
| --- | --- |
| `SUMMARY.txt` | Plain-language observations, limitations, and next checks. |
| `Report.json` | Complete structured report with `ReportSchemaVersion` `3`. |
| `Performance-Samples.csv` | System and selected-target counters when monitoring was used. |
| `Windows-Events.json` | Filtered and redacted Windows-event fields. |
| `Windows-Event-Groups.json` | Normalized duplicate groups with counts and time ranges. |
| `Reliability.json` | Filtered Reliability Monitor records when available. |
| `Artifacts.json` | Metadata only for relevant Windows-generated artifacts. |
| `Collection-Status.json` | Available, unavailable, denied, timed-out, or error state by source. |
| `Source-Coverage.json` | Which sources contributed records to the selected incident window. |
| `Incident.json` | Selected incident, target profile, fingerprint, evidence window, and correlation. |
| `Bugchecks.json` | Normalized compatible WER and Kernel-Power bugcheck records. |
| `Crash-Readiness.json` | Read-only dump mode, page-file facts, destination capacity, and activation state. |
| `Dump-Inventory.json` | Bounded dump metadata and header-recognition state; never dump contents. |
| `Driver-Inventory.json` | Privacy-filtered driver/device facts without IDs, serials, or locations. |
| `Recent-Changes.json` | Privacy-filtered Windows Update and bounded driver-install timing. |
| `Storage-Health.json` | Windows-reported storage health without persistent device identifiers. |
| `Driver-Verifier.json` | Read-only snapshot of existing Driver Verifier settings. |
| `Debugger-Analysis.json` | Optional allowlisted structured debugger fields from compatible reports; never raw output. |
| `Dump-Quality.json` | Optional bounded structural validation from compatible reports. |
| `Manifest.json` | Session identity, creation time, size, and SHA-256 for payload members. |

Optional members appear only when that analysis exists. Consumers must ignore
unknown additive members/properties and must inspect collection status and
source coverage before interpreting absent evidence.

The `3.2.0-beta.1` ShareReadOnly UI does not launch an elevated helper, stage
protected dumps, package dump bytes, or offer a debugger workflow. It can still
open a valid schema-3 report that contains compatible optional structured
members from earlier tooling.

## Evidence and correlation

Incident fingerprints are deterministic SHA-256 identifiers derived from
bounded incident fields. They are not machine or user identifiers.

Bugcheck codes and parameters are normalized from allowlisted event fields.
Dump correlation can be based on an exact recorded filename or timestamp
proximity. Correlation does not establish cause.

WHEA severity comes from a shared event-ID catalog. Unknown IDs remain unknown;
message wording is not used to invent a severity classification.

## Dump handling

The accessible dump inventory reads at most 32 fixed header bytes to recognize
`MDMP`, 32-bit page-dump, or 64-bit page-dump signatures. Original local paths
used for correlation are excluded from JSON and exported paths are redacted.
The technical report contains metadata only.

ShareReadOnly exposes no dump-packaging API and produces no dump ZIP. A Windows
crash dump can contain credentials, documents, chats, keys, and other private
memory; never treat a technical report as permission to request or share the
underlying dump.

## Driver and event privacy

The driver inventory includes only allowlisted descriptive fields. Device IDs,
instance paths, hardware IDs, serials, locations, and usernames are neither
retained nor exported by that collector.

Free-form Windows messages can still contain identifying information. Extract
and inspect every technical-report member before sharing it.

## Transactional local report creation

Reports are assembled in randomly named staging files under the selected data
root. The app writes and hashes each member, publishes the checksum first, and
publishes the final-looking archive last as the commit point. Cancellation
removes packaging partials. A completed local report ZIP therefore has a
matching internal checksum file.

The checksum uses:

```text
<lowercase SHA-256> *<archive filename>
```

The advanced export validator revalidates the selected local report before
copying it. The checksum is build/report evidence, not publisher identity.

## Legacy compatibility

Version 2 reports retain schema `2`, their original members, and the
`BF6-Diagnostic-Report-...zip` prefix. Version 3 does not rename or rewrite
existing version 2 archives. Consumers must select behavior from
`ReportSchemaVersion`, not filename alone.
