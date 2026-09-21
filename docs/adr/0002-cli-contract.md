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

`help`, `version`, and `inspect <file>` are the successful commands in the first
implemented increment. Inspection accepts one bounded PEM or DER X.509
certificate and reports metadata; it does not claim trust, chain verification,
hostname suitability, or current validity. Commands that will later process
private material are not exposed as placeholders: an unimplemented operation
must not look like a supported but failed operation.

## Structured output

JSON is deferred until the first inspection result model exists. When added,
it will use a versioned, typed schema that cannot contain private-key bytes.
Human-readable and JSON modes will be derived from the same result object.

## Consequences

- Shell automation can rely on exit codes rather than parsing prose.
- Error text can remain intentionally low-detail without hiding the failure
  class.
- Output writer failures propagate as failure instead of producing false
  success.
- Future commands must document whether their inputs are public, sensitive, or
  secret before their flags are accepted.
