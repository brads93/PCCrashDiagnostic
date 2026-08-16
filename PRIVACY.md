# Privacy

## Local processing and optional symbol download

PC Crash Diagnostic has no telemetry, analytics, update checks, uploads, or automatic network requests. Version 3 writes diagnostic state and reports under `%LocalAppData%\PCCrashDiagnostic` unless `--data-root` supplies another absolute path. If the user explicitly approves **Download Microsoft symbols and retry**, the installed WinDbg tool may download symbol files only from Microsoft's public symbol server into the app's private local cache. The crash dump and report are not uploaded.

Version 2 data under `%LocalAppData%\UnofficialBF6Diagnostic` is not moved, overwritten, or deleted by the version 3 default. Choosing a legacy folder explicitly with `--data-root` is the user's responsibility.

`--data-root` changes the report, history, and normal session-data folder only. The one-use request/response channel uses the originating user's fixed `%LocalAppData%\PCCrashDiagnostic\HelperRequests` folder. Configuration receipts, temporary protected dump copies, and per-application WER dumps use administrator-owned, ACL-restricted folders under `%ProgramData%\PCCrashDiagnostic\<originating user SID>`. An arbitrary report folder cannot redirect the elevated helper. Request files expire, validated staging copies are deleted after the selected operation completes, fails, or is cancelled, and preparation receipts remain until restored or deleted by an administrator-approved restore/cleanup action.

## Standard report contents

A version 3 standard report can contain:

- CPU, GPU, motherboard, firmware, RAM, Windows, and graphics-driver model/version facts;
- a privacy-filtered driver/device inventory containing device class/name, manufacturer, provider, version, date, INF name, signing state, and signer;
- timestamped system-memory, commit, selected-target process-memory, CPU, and GPU counters;
- narrowly filtered Windows Event Log fields and Reliability Monitor records;
- crash-readiness facts such as active dump filtering, dump mode, configured and runtime page-file capacity, redacted dump locations, actual destination-volume capacity, and restart state;
- dump metadata and at most 32 header bytes used only to recognize a supported Windows dump signature;
- dump-quality classification and bounded results from an optional local Microsoft DumpChk run, without raw tool output;
- privacy-filtered storage health, existing Driver Verifier state, Windows Update history, and bounded SetupAPI driver-install timing;
- incident selection, evidence-window, correlation, source-coverage, collection-status, and report-manifest data; and
- ranked findings and a human-readable summary.

The standard report does not intentionally include dump contents, raw Event Log XML, arbitrary log contents, target-process memory, process modules, command lines, user input, game files, network configuration, credentials, device IDs, hardware IDs, serial numbers, device locations, or arbitrary personal files.

Original dump paths may be retained only in memory long enough to correlate a Windows record with a local file. Exported dump paths are redacted, and original paths are excluded from JSON serialization.

## Redaction and residual risk

Before export, the app redacts known usernames/profile paths, computer/domain names, SIDs, email addresses, IP/MAC addresses, and diagnostic correlation identifiers. ETW provider GUIDs are retained in the dedicated provider field because they identify logging providers; unrelated GUIDs are redacted.

Windows event messages are free-form, so automatic redaction cannot be guaranteed. Device names, hardware models, timestamps, Windows/driver versions, executable names, event descriptions, and performance history can also identify a person or machine in combination. The in-app summary is not a complete privacy review. Extract the report ZIP and inspect every JSON, CSV, and text file before sharing it.

## Crash preparation, app dumps, and debugger analysis

The **Prepare this PC for the next crash** workflow writes only the proposed crash-capture values after UAC approval. Its receipt contains setting names and exact previous/proposed values, report/session binding, activation timestamps, and a privacy-filtered target profile. It does not contain crash memory or arbitrary registry data. Receipts are protected so an unelevated process cannot silently rewrite the rollback record.

Distributable beta.2 packages do not allow new per-application WER LocalDumps settings. Windows applies that machine-wide setting by executable basename, so a future elevated or system process with the same basename could expose its private memory through the configured dump location. The implementation is retained only behind an explicit source-build gate for disposable-VM research. Restore remains available for validated receipts from earlier developer builds. Existing `.dmp` files remain local and are never added to a standard report automatically; restoring settings does not delete them.

The standard report never contains the dump file itself. The bounded dump inspector reads no more than 32 header bytes and does not parse memory pages, stacks, modules, or embedded strings.

Creating a dump ZIP is a separate, explicit action with a separate checksum. A dump can contain usernames, paths, chat, account material, encryption keys, documents, or fragments of any data resident in memory. Share dump packages only with a trusted recipient through a secure channel.

If optional debugger analysis is used, the exported report may contain bounded fields such as a stop code, failure bucket, named module, limited stack-module list, or allowlisted boot/service black-box facts. The debugger runs as the normal user. It first uses only locally available symbols; a Microsoft-symbol retry requires a separate confirmation. A bounded local debugger log and its path are not exported. A named module is not proof that the module caused the crash.

## Release verification data

`ReleaseManifest.json` and `SHA256SUMS.txt` contain release identity, filenames, sizes, and hashes, not diagnostic data. This controlled beta is unsigned; checksums establish byte integrity only when the expected values are obtained through a trusted independent channel.

## Deletion

Reports and sessions are ordinary local files. Close the app and delete unwanted files under the selected data root. Per-app dump files can be reviewed and deleted separately from the ProgramData application-dump folder; changing or removing protected receipts/staging roots requires administrator approval. The portable app has no cloud account or server-side copy to remove. Version 2 and version 3 use separate default roots and must be deleted separately.
