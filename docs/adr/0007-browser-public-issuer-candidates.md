# ADR 0007: Public issuer candidates before verification

## Status

Accepted for local Workbench development; not an independent security audit.

## Context

Explore previously showed independent certificate cards. Users need to see
whether their selected files appear related, but matching issuer and subject
text alone can falsely join unrelated certificates. A chain view can also be
mistaken for a trust verdict.

## Decision

After a successful public-only Explore, the browser sends the same 1–8
selected files to a separate Go WebAssembly analysis operation. It re-parses
the strict public collection and requires the fingerprint list to match the
Explore result in order. Failure or changed files hide all cards. The bridge
limits combined input to 16 MiB, output to 64 KiB, certificates to 64, and
possible issuer signature checks to 256. All returned relationships are index
references; no untrusted certificate text is added to the response.

A possible issuer requires a matching raw issuer/subject name, a CA flag with
valid basic constraints, and a successful `CheckSignatureFrom` result. A
self-signed CA candidate is labeled separately. Multiple candidates remain
multiple; Rootwell does not pick a path or anchor. Filenames are display-only.

## Non-claims

This is not full chain verification. Time, hostname, EKU, path length,
algorithm policy, explicit trust, revocation, deployment, and private-key
possession are not evaluated here. Browser Verify will use the separate
`certverify` core and require an independently supplied trust source.
