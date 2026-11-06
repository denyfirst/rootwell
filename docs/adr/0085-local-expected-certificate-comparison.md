# ADR 0085: Compare an expected public certificate with a website

## Status

Development, 2026-11-06. Builds on ADR 0084; not an independent audit.

## Decision

The same Check a website page gains an optional Compare with my certificate
control. A single public PEM/CRT/CER/DER file or public PEM bundle is parsed
locally by the existing Go WASM public-only parser, up to 256 KiB / 10
certificates. Private keys, mixed secret-bearing files, PFX, duplicates and
malformed content refuse before the website request. One non-CA certificate
is selected automatically; several require an explicit selection. A CA-only
bundle cannot stand in for an expected site certificate.

Neither bytes nor fingerprints from the selected file enter the HTTP API.
The existing exact target/confirm request, authorization, SSRF, Linux-only TLS
connector and independent server-chain verification remain unchanged. After
the bounded response, the browser compares the full normalized SHA-256 DER
fingerprint of the selected expected leaf with the first server-presented
certificate. PEM versus DER packaging cannot cause a difference. A renewed
certificate, even with the same names/key, is a different certificate.

The comparison and server health are separate results: an exact match does
not prove trusted/current/correct deployment; a different certificate can be
valid for the same domain. Additional CA certificates in the supplied bundle
are only compared for presence in the server-sent list or locally verified
trust path. Absence is informational: servers normally omit roots and may
serve a valid alternative cross-signed chain. Uploaded certificates never
complete or repair the observed server chain and never become trust anchors.

The operator specifically requires the location of the difference, not a
generic mismatch message. Existing WASM issuer analysis cryptographically
links the supplied collection. A unique expected chain is displayed node by
node; ambiguity is not resolved by file order. The server report adds bounded
per-child verified/rejected candidate fingerprints (at most 10*9 checks),
computed from the actually presented certificates. The comparison identifies
the expected intermediate and the exact server-sent candidate position when
signature/CA eligibility fails, missing intermediates, legitimate alternative
signing candidates and normal root omission. Candidate names are labels, not
evidence. A failed candidate is not automatically an attack or the cause of
every independent validation failure. A valid server path is not blamed for
an unused rejected candidate. Neither collection is reordered into a trust
claim by the comparison.

Selection changes, cancellation, timeout, hidden/pageexit boundaries clear
results and discard late file-read/engine/network results. File bytes are
cleared after parsing where possible; browser/runtime copies cannot be
reliably wiped. No file/name/results are persisted or sent to the target, CA,
Rootwell backend or DenyFirst. Apart from fixed same-origin engine/assets,
only the existing approved target observation uses the network. A generated comparison example is explicitly synthetic and
does not use the operator's selected file or perform a live check.

## Limits

One observed IP/SNI/TLS profile at one instant. A matching leaf does not prove
every node was updated, that any particular uploaded bundle is a valid chain,
revocation status or universal MITM absence. Public HTTPS:443 and Linux live
connector restrictions from ADR 0084 remain. No new export/converter, saved
library/private-key selection, renewal or deployment operation is added.
