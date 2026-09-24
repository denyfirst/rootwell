# ADR 0005: Browser export of one selected public certificate

**Status:** accepted

**Date:** 2026-09-24

## Context

Explore identifies public certificates in one file. A user may need one
certificate separately as PEM or DER. Export must not accidentally include
another bundle member or any private key, and a web page cannot promise the
same filesystem no-overwrite semantics as a native writer.

## Decision

Each card offers explicit PEM and DER actions. On action, the selected source
is read again. The shared strict `publicbundle` parser rejects mixed,
secret-bearing, duplicate, malformed, or excessive input. The full SHA-256
fingerprint from the card selects one entry; order and subject are not
selectors. The Go core emits either one canonical PEM `CERTIFICATE` block or
the certificate's exact DER bytes, re-parses the output, and compares its DER
and fingerprint with the selection. The bridge returns a versioned result with
the public bytes as a typed array. The browser checks that result and re-parses
the output again before creating a Blob download.

The generated filename has a fixed prefix, a fingerprint fragment, a
cryptographically random 128-bit suffix, and `.pem` or `.der`. No
certificate-derived subject, source filename, or path is used. Rootwell does
not call filesystem-write APIs. It requests a browser-managed download only;
the browser and OS decide the destination and any overwrite prompt. The
random suffix makes accidental name collisions negligible but does not prove
browser-wide no-overwrite behavior. Strict no-overwrite on an explicitly
chosen path remains a separate native/CLI boundary.

No private key, PFX, password, role inference, chain verification, or trust
decision is introduced. Rootwell-owned byte buffers are cleared best-effort;
Blob, runtime, download-manager, and browser copies may persist. This public
only operation retains the origin and asset assumptions in ADR 0003 and the
bundle parser assumptions in ADR 0004.

## Deferred

Multiple separate inputs, bulk export, secret-bearing conversion, and native
file writes each require separate design and tests.
