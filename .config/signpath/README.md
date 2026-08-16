# SignPath templates

These files document the intended ShareReadOnly signing shape. They are not an
active SignPath project configuration and do not authorize a release.

- `share-read-only-artifact-configuration.xml` signs only
  `PCCrashDiagnostic.exe` inside the uploaded ZIP and restricts its supported
  PE metadata to the reviewed release values. Its required `product-version`
  parameter is read from the two-build hash-matched signing input and must equal
  `3.2.0-beta.1+<exact-tag-commit>` before the signing request is submitted.
- `share-read-only-source-policy.template.yml` requires a GitHub-hosted runner
  and disallows workflow reruns.

After the SignPath organization, project, policy, and artifact-configuration
slugs are created, copy the source-policy template to SignPath's required
`.signpath/policies/<project-slug>/<policy-slug>.yml` location and have the real
maintainers review it. Do not guess slugs or activate the signing workflow with
placeholder ownership.

The signing workflow produces a signed candidate only. It cannot set
`ShareApproved` because RFC 3161 verification and exact-package disposable-VM
evidence remain separate release gates.

The .NET single-file apphost reports `PCCrashDiagnostic.dll` as both
`OriginalFilename` and `InternalName`; the artifact configuration therefore
uses the DLL value rather than claiming the packaged filename is embedded in
those fields. SignPath's artifact configuration does not expose every PE
version-resource field. `tools/Test-AuthenticodePolicy.ps1` is the fail-closed
post-sign authority for FileDescription, ProductName, CompanyName, Copyright,
FileVersion, ProductVersion, InternalName, and OriginalFilename as well as the
certificate and RFC 3161 policy.
