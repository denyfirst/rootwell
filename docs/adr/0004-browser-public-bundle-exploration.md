# ADR 0004: Browser exploration reuses the public bundle parser

**Status:** accepted

**Date:** 2026-09-24

## Context

Users often receive a `.crt` or `.cer` file and a PEM bundle without knowing
which certificates are inside. CLI `rootwell explore` already has a strict,
bounded, public-only parser. A browser workflow should expose that information
without uploading bytes or creating a second parser.

## Decision

The browser adds a separate Explore action for one explicitly selected file.
The existing Go/WebAssembly program calls `publicbundle.Parse` and returns a
versioned metadata-only response. The limits are 16 MiB input, 64 public PEM
certificates, 1 MiB aggregate subject/issuer text, and 4 MiB serialized
response. One DER certificate is also accepted. The browser preflights input
size; the bridge repeats the check before allocating a Go copy; the parser
still enforces its own limit. Malformed, mixed, duplicated, trailing, and
secret-bearing input fails with fixed diagnostics and no partial output.

The UI validates the response schema, renders certificate-derived values only
with DOM text nodes, and displays `not-performed` verification and
`not-selected` trust-anchor status. The CA flag is displayed as metadata, not
a trusted-root label. No filename extension changes parsing. No file bytes go
to an HTTP API, and the file-reading script retains no network capability.

The operator's selected file, copied JS byte array, Go entry buffer, and
parsed public DER copies exist only in browser memory. Buffers under Rootwell's
control are cleared best-effort; browser-wide secure erasure is not claimed.
The trusted self-hosted origin, runtime shim, CSP, and asset checks from ADR
0003 still apply.

## Deferred

Multiple separate files, role/chain inference, public certificate export,
browser Verify, PFX/private-key import, and all secret-bearing conversion are
separate increments. In particular, an included root certificate cannot
authorize itself as a trust anchor.
