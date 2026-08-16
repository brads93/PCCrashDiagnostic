# Sharing results with a helper

For a Discord helper or support technician, start with the app's **safe
summary**, not the full technical ZIP and never a crash dump.

## Recommended steps

1. Collect the incident or monitor the affected app.
2. On Results, read **Evidence collected**, **Crash capture readiness**, and
   **Source coverage**. Missing evidence is reported as missing or unavailable;
   it is not treated as proof that nothing happened.
3. Select **Review safe summary**.
4. Read the exact text shown. Copy or save it only if you are comfortable
   sharing those bytes.
5. Send that text to the person helping you.

The safe summary is designed to include system specifications, normalized
bugcheck values, allowlisted Windows-signal counts, crash-readiness state,
bounded dump metadata, privacy-filtered storage/recent-change facts, and source
coverage. It excludes event and Reliability Monitor messages, usernames, paths,
session IDs, device IDs, hashes, dump bytes, raw debugger output, finding prose,
collector error detail, process IDs, command lines, modules, inputs, and
anti-cheat data.

## When a technical report is useful

Use **Export the full technical report (advanced)** only when the helper needs
structured evidence and you trust them with more machine detail. The app shows
a privacy warning and requires confirmation. Extract the ZIP and inspect every
file before sending it.

The technical report does not contain crash-dump bytes or raw debugger output,
but Windows event messages and hardware/driver labels can still identify a PC.
Do not post it publicly without review.

## What the result means

The app reports what Windows recorded, possible relevance, limitations, and a
next check. It does not guarantee a root cause. A named driver or hardware
category is not proof that a specific component is defective.

If the app says **No cause was identified in the Windows records this app could
read**, share the source-coverage section too. A denied, timed-out, missing, or
overwritten record can be as important as the records that were present.
