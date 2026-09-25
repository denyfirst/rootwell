# ADR 0008: Explicit public PEM bundle export

## Status

Accepted for local Workbench development; not an independent security audit.

## Decision

Explore offers an unchecked selection box on each public certificate card.
The user explicitly selects one or more certificates. Rootwell exports them
as adjacent PEM `CERTIFICATE` blocks in the displayed order; it does not
reorder them, infer a verified chain, include private keys, or call the file
a trusted fullchain.

At download time the Go WebAssembly bridge re-reads the 1–8 selected public
source files under the 16 MiB/64-certificate limits. It rejects mixed,
secret-bearing, malformed, duplicate, or changed files. The full ordered
fingerprint list must exactly match the Explore snapshot, and the requested
subset must preserve that order. Output is re-parsed, checked against the
selected fingerprints and original DER bytes, limited to 16 MiB, and named
using a fixed prefix plus a random suffix. The browser checks the response
and output again before requesting a browser-managed download. Input and
output buffers are cleared best-effort; browser/OS memory and overwrite
behavior cannot be guaranteed.

## Non-claims

Selection is not TLS verification. The output may not be a complete or
correctly ordered deployable chain if the user selected the wrong items.
Browser Verify and a separately reviewed chain-ordering workflow remain
distinct increments. No private-key or PFX input is accepted here.
