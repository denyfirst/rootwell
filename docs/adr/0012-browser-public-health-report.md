# ADR 0012: Explicit browser-only public certificate health report

Status: accepted for the public-only Workbench.

## Decision

Expose one opt-in JSON download from a completed Explore result. The report is
versioned as `rootwell.public-health-report.v1` and records the Explore-time
browser clock, each public certificate's metadata and full SHA-256
fingerprint, source file number rather than filename, possible signer card
numbers, and an expiry window. It records `not-performed`, `not-selected`,
`not-checked`, and `not-contacted` for verification, trust anchor, revocation,
and live server respectively. It is not a compliance or deployment report.

Before download, all source files are re-read under the existing combined
16 MiB bound, parsed by the Go public certificate core, and compared against
the displayed ordered full fingerprints. Stale selection or changed/malformed
input is refused. JSON output is capped at 2 MiB. The filename contains a
fresh 128-bit random suffix and no certificate- or file-derived text. The
browser's Blob download path is used; no Rootwell server API or persistent
browser store receives the content.

## Security and usability consequences

Certificate subjects and issuers are public X.509 metadata but can disclose
internal hostnames when a report is shared. Rootwell warns beside the button
and does not include local source filenames. The browser clock can be wrong;
expiry windows are advisory. A matching certificate fingerprint does not
authenticate a root or prove revocation or live deployment. The app cannot
guarantee the browser/OS final save location or no-overwrite behavior.

Private keys, PFX, trusted-root selection, scheduled reporting, storage and
network discovery are out of scope. A future inventory requires a separate
data-retention and access-control decision.
