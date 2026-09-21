# ADR 0002: CLI and error contract

**Status:** accepted

**Date:** 2026-09-21

## Decision

The `rootwell` executable has a small dispatcher around independently testable
commands. The initial exit-code contract is:

| Code | Meaning |
|---:|---|
| 0 | requested operation completed and its output was delivered |
| 1 | operational or output failure |
| 2 | command-line usage failure |

Requested data is written to stdout. Diagnostics and usage guidance are written
to stderr. Errors are lowercase, one line, and have no trailing punctuation.
Attacker-controlled command tokens and paths are not reflected by default.

`help`, `version`, `inspect <file>`, and the explicit-trust `verify` profile are
successful commands in the implemented increments. Inspection accepts one bounded PEM or DER X.509
certificate and reports metadata; it does not claim trust, chain verification,
hostname suitability, or current validity. Commands that will later process
private material are not exposed as placeholders: an unimplemented operation
must not look like a supported but failed operation.

TLS server verification uses this contract:

```text
rootwell verify <leaf> --trust-bundle <roots.pem> [--intermediates <chain.pem>] --hostname <name>
```

Flag order is not significant. Each flag is accepted at most once. Trust roots
and hostname are required, intermediates are optional, and unknown or incomplete
flags are usage failures. The operation reads only named local files, never
consults system roots, and never performs network access. A passed result always
states that revocation was not checked.

## Structured output

`inspect --json <file>` emits the typed `rootwell.inspect.x509.v1` schema. It
cannot contain private-key bytes, raw input, or the input path. Human-readable
and JSON modes are derived from the same result object. Repeated fields are
always arrays, including when empty, and incompatible changes require a new
schema identifier.

JSON string semantics are preserved, but non-ASCII runes are emitted as Unicode
escapes so formatting controls cannot directly affect a terminal.

The v1 schema permits additive fields; consumers must ignore unknown fields.
Removing, renaming, or changing an existing field's type or meaning requires a
new schema identifier. The additive `time_window` object is explicitly an
evaluation of encoded dates, not a trust verdict.

## Consequences

- Shell automation can rely on exit codes rather than parsing prose.
- Error text can remain intentionally low-detail without hiding the failure
  class.
- Output writer failures propagate as failure instead of producing false
  success.
- Future commands must document whether their inputs are public, sensitive, or
  secret before their flags are accepted.
- Automation can select a named JSON schema instead of parsing human output.
