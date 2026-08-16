# Code signing policy

Free code signing provided by SignPath.io, certificate by SignPath Foundation
([SignPath.io](https://signpath.io/), [SignPath Foundation](https://signpath.org/)).

This policy applies to friend-facing or public PC Crash Diagnostic Windows
artifacts. It does not claim that the current candidate is approved for
sharing.

## Required result

A shareable `3.2.0-beta.1` package must meet all of these conditions:

1. The source is the clean, exact Git tag `v3.2.0-beta.1`.
2. CI passes for the `ShareReadOnly` solution filter with locked dependencies,
   .NET SDK `10.0.400`, and runtime `10.0.11`.
3. The package contains one executable: `PCCrashDiagnostic.exe`. It must not
   contain `PCCrashDiagnostic.ElevatedHelper.exe` or another executable.
4. Authenticode is valid for the expected publisher certificate and the
   certificate thumbprint matches the release configuration.
5. The Authenticode signature has a valid RFC 3161 timestamp.
6. The exact finished package passes the disposable-Windows-VM release matrix.
7. `ReleaseManifest.json`, `SHA256SUMS.txt`, the runtime ZIP, and the source ZIP
   describe the same bytes and `ShareApproved` is true only after every gate is
   independently verified.

A checksum is useful for byte identity, but it does not establish who signed or
published a file.

## Key custody

The private signing key must remain in a managed signing service or protected
hardware. Do not store a PFX, private key, certificate password, or signing API
token in Git, a build artifact, a workflow log, or a general repository
secret. SignPath credentials belong in the protected `code-signing` GitHub
environment with required reviewer approval.

The repository variable `SIGNPATH_ENABLED` must remain unset or `false` until:

- `.github/CODEOWNERS` has been confirmed against the repository's real
  maintainers;
- branch/tag protection and the `code-signing` environment are active;
- SignPath organization, project, policy, and artifact-configuration slugs are
  reviewed; and
- `SIGNPATH_SIGNER_THUMBPRINT`, `SIGNPATH_SIGNER_SUBJECT`, and
  `SIGNPATH_SIGNER_ISSUER` contain independently verified exact certificate
  values from the approved SignPath Foundation policy. Certificate values are
  not guessed in source because the service assigns them after onboarding.

## Two-phase pipeline

The workflow in `.github/workflows/signpath-share-read-only.yml` is deliberately
two-phase:

1. Build and test two isolated unsigned ShareReadOnly candidates from the exact
   tag with one fixed `SOURCE_DATE_EPOCH`, then require identical EXE SHA-256 values.
2. Extract and upload only the hash-matched `PCCrashDiagnostic.exe` as the SignPath input.
3. Sign that executable using the reviewed SignPath artifact configuration.
4. Run the release builder again with the signed executable as immutable input.
   The builder validates the filename, exact PE metadata (including the SDK
   apphost's `PCCrashDiagnostic.dll` InternalName and OriginalFilename),
   Authenticode trust, pinned signer thumbprint/subject/issuer, and the RFC 3161
   unsigned-attribute OID before
   reconstructing the package.

The workflow uploads a candidate named **signed awaiting VM**. It does not
create a GitHub release, push Git state, or mark the artifact shareable.

## Timestamp and VM gates

The release verifier distinguishes the RFC 3161 Authenticode attribute
(`1.3.6.1.4.1.311.3.3.1`) from the legacy countersignature attribute and also
requires the timestamp certificate's Time Stamping EKU. The final evidence
records the result, signer, timestamp authority, and checked file SHA-256.

The VM test must use the exact runtime ZIP that will be shared, identified by
SHA-256. Repacking, editing documentation inside the ZIP, re-signing, or
changing any byte invalidates that evidence and requires the VM test again.
Use `docs/EXACT_PACKAGE_VM_CHECKLIST.md` as the minimum execution record.
The evidence must record at least:

- package filename and SHA-256;
- source commit and exact tag;
- Windows image/build and VM snapshot identity;
- Microsoft Defender result;
- Authenticode publisher and timestamp verification;
- standard-user launch without UAC;
- expected read-only collection and safe-summary export;
- absence of unexpected network requests, persistence, settings writes, or
  extra processes; and
- tester, UTC time, and pass/fail outcome.

Raw VM logs may contain machine-specific data. Keep them restricted; publish a
sanitized release-evidence summary.

## Revocation and incident response

Stop distribution immediately if a signing credential, workflow, dependency,
or packaged byte is suspected of compromise. Disable the SignPath policy and
GitHub environment, preserve evidence, notify the signing provider when
appropriate, and publish a security advisory. A corrected build receives a new
version; never replace published bytes under an existing version.
