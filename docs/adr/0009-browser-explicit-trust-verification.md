# ADR 0009: Browser TLS verification with explicit trust

## Status

Accepted for local Workbench development; not an independent security audit.

## Decision

Browser Verify uses the existing `certverify.Verify` policy and returns a
versioned, bounded public result. It never consults system roots or a
network endpoint. The user must enter a hostname and independently select a
PEM trust-anchor file. The evaluation time defaults to the browser clock;
Advanced permits an explicit RFC 3339 value. Both modes pass the same typed
inputs to the same Go verifier.

Simple accepts 1–8 strict public CA-provided files under a combined 16 MiB
limit. It requires exactly one non-CA leaf candidate, collects non-self-signed
CA certificates as intermediate candidates, and ignores self-signed source
roots as trust sources. Duplicates, mixed/private-key blocks, malformed
input, and ambiguous leaves fail closed. Advanced requires a separately
chosen single PEM/DER leaf and optional strict PEM intermediate bundle. The
same separate trust file and hostname are required in both modes.

The browser checks the response schema, explicit trust marker, hostname,
bounded verified chain, and non-claims before showing Verified. Any failure
or changed selection hides the result and emits a fixed diagnostic without
reflecting certificate bytes or names. JS and Go copies are cleared on a
best-effort basis.

## Non-claims

This is offline TLS server certificate verification against user-supplied
trust, not proof of live deployment, private-key possession, revocation,
Certificate Transparency, or browser/OS trust. A wrong host clock or wrong
explicit trust file can change the result. It does not make a supplied root
trusted unless the user separately selects it as trust input.
