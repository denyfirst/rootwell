# Security invariants

An invariant is a behavior Rootwell must preserve, not an aspiration. Every
entry names tests that exist. A change that renames or removes a cited test must
update this file in the same commit, and CI verifies that the citations resolve.

This list guards the CLI and certificate-inspection boundaries. File-writing
and private-key invariants are added with the code that first creates those
risks.

## C1 — Diagnostics do not reflect command input

Unknown commands and invalid argument combinations are attacker-controlled and
may contain paths, credentials, terminal escapes, or private data. Diagnostics
state what was wrong without repeating the supplied token.

Guarded by `TestUnknownCommandDoesNotEchoInput` and `FuzzRun`.

## C2 — Exit codes and output channels are stable

Success is `0`, operational failure is `1`, and command-line usage failure is
`2`. Requested information goes to stdout; diagnostics and usage failures go to
stderr. Automation must not infer success from text.

Guarded by `TestRunContract`.

## C3 — Output failure cannot be reported as success

A closed pipe, full filesystem, or failed writer is an operation failure. Help
or version output that was not delivered must not return success.

Guarded by `TestRunReportsWriteFailure`.

## C4 — Build version output is a single safe line

Build metadata is part of the release boundary. It cannot inject additional
terminal lines or control characters into output; invalid injected metadata is
reported as `development` rather than reproduced.

Guarded by `TestVersionValue` and `FuzzVersionValue`.

## C5 — A single input read is bounded

Rootwell reads at most 16 MiB plus one detection byte. Empty and oversized
inputs fail before certificate parsing, and a file exactly at the limit remains
valid input to the boundary. Certificate-derived text and repeated metadata
also have explicit limits before terminal escaping can amplify them.

Guarded by `TestReadLimited`, `FuzzReadLimited`, and
`TestCertificateMetadataLimits`.

## C6 — Inspection accepts exactly one complete certificate

DER must be one complete ASN.1 sequence. PEM must be one header-free
`CERTIFICATE` block. Truncated, unrelated, multiple, or trailing objects fail
closed rather than being partially accepted.

Guarded by `TestInspectRejectsTrailingData`,
`TestInspectRejectsMalformedOrUnsupportedInput`, and
`FuzzInspectCertificate`.

## C7 — Requested certificate text cannot control the terminal

Subjects, issuers, SANs, and URIs are attacker-controlled even in a valid
certificate. Human output quotes them as ASCII and escapes control, Unicode,
and line-separator characters.

Guarded by `TestHumanCertificateOutputEscapesText` and
`FuzzHumanCertificateOutput`.

## C8 — Inspection errors do not disclose paths or input bytes

Open, read, parse, and format failures return fixed diagnostics. A sensitive
path or malformed file content is not reflected to either output channel.

Guarded by `TestReadDoesNotExposePath` and `TestInspectDoesNotEchoPath`.

## C9 — The local Workbench has no network or child-process capability

The executable and its production packages cannot directly import networking,
process execution, plugins, or unsafe code. Inspection never follows URLs
embedded in a certificate.

Guarded by `TestWorkbenchHasNoNetworkOrProcessImports`.

## C10 — Structured inspection output is versioned and terminal-safe

JSON output is derived from the same typed certificate result as human output.
Its schema version is explicit, repeated fields are arrays rather than `null`,
and decoded strings preserve their meaning while the emitted document contains
only printable ASCII and newlines. The schema has no raw certificate or
private-key field.

Guarded by `TestInspectJSONCommand`,
`TestJSONCertificateOutputIsASCIIAndSemantic`,
`TestJSONCertificateOutputRejectsInvalidUTF8`,
`TestJSONSchemaExcludesSecretBearingFields`, and
`FuzzJSONCertificateOutput`.
