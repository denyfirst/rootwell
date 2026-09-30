# ADR 0032: Fingerprint-selected public certificate extraction from PFX

**Status:** accepted for the offline development CLI, not production custody

**Date:** 2026-09-30

## Decision

`rootwell pfx-extract-cert --input <file> --sha256 <fingerprint> --to pem|der
--output <new-file>` saves exactly one public X.509 certificate from the
authenticated, bounded modern PFX profile already admitted by `pfx-inspect`.
The operator copies the complete uppercase colon-hex SHA-256 fingerprint from
the inspection result. No index or implicit "first" selection is accepted.
The CLI reads the PFX once before prompting; a later path replacement cannot
change the selected bytes. A fingerprint not present in that authenticated
PFX fails without writing a file.

The operation uses the existing PFX preflight, local terminal password,
one-shot 10-second deadline, strict bag/key/certificate checks, single-public-
certificate converter, and no-overwrite public-file writer. Extraction occurs
only after full authentication and key/certificate-set validation. The output
is only one public certificate in the requested encoding. It is not a
fullchain, private key, trust anchor, key match report, TLS verification, or
live-server observation. The input PFX and password never enter the output or
normal diagnostics. Public certificates can still disclose internal names.

## Boundaries

There is no browser, server, inventory, network, or Porch integration. No
private-key extraction is authorized by this decision. The narrow profile and
encrypted-safe KDF limitation of [ADR 0031](0031-bounded-pfx-public-inspection.md)
remain unchanged; the 10-second deadline relies on one-shot process exit and
must not be reused in a daemon. The public writer does not promise crash
durability or secret-output protection. Broad vendor support and encrypted
private-key export need separate decisions and tests. Independent audit is
required before real-user release.
