# ADR 0086: Open a saved certificate in Check a website

## Status

Development, 2026-11-06. Builds on ADR 0085. Not an independent audit.

## Decision

Certificates gains one Check on website action under Details and manage. A
same-tab native POST to `/website-check/saved` carries only the selected public
fingerprint, exact inventory generation and fixed `website-check` destination.
It never carries a target, certificate upload, private key, password or notes.
GET/query navigation cannot select a record. Existing Workbench/renewal form
parsing keeps its own allowed destinations; the shared bounded parser does
not grant those routes the new destination.

The navigation requires a ready enrolled Linux session, exact Origin and
same-origin/document/navigate metadata. The encrypted inventory is read under
the existing derivation busy gate, generation and presence are checked, and
session/revision/cancellation are rechecked before publication. Invalid,
missing, stale, CA-only or fingerprint-inconsistent records do not produce a
selection. No inventory write, private-material accessor or connector call is
involved. The server includes exactly one public DER certificate in bounded,
HTML-escaped inert JSON on the existing website page; no inline script or URL
payload is introduced. The page retains no owner/location or related key.

The browser consumes and clears the inert node, validates the exact schema,
canonical base64, generation and full fingerprint, then reparses the one DER
certificate through the existing public-only Go WASM engine before a check.
The selected expected leaf must equal the declared full fingerprint. It shows
that a saved public snapshot is selected, leaves the target empty and consent
unchecked. No target is guessed from SANs or service notes. Choosing a file
clears this selection and consent; hidden/pagehide clears its bytes, labels,
results and late work. A malformed selection cannot silently become an
uncompared successful website check.

Only the separately approved website check can connect, through the unchanged
`{target,confirm}` API and ADR 0084 public-HTTPS/SSRF/session/time bounds. The
saved certificate cannot supply intermediates/trust to the server verifier.
An exact identity match and independent server health remain separate.

## Limits and evidence

This is the public snapshot at navigation time, not a continuously current
library link. Later library edits do not replace it. Hidden/back navigation
requires a new selection; no browser storage, URL identity or server handoff
record is used. HTTP responses are no-store, but browser/runtime memory copies
and history handling cannot be guaranteed erased. Private-key custody and
download rules are unchanged. Only the chosen leaf is transferred, not every
CA in its original imported bundle; the site still diagnoses its served chain.

Native form/parser/refusal and inert-object tests, the existing actual Linux
encrypted-inventory navigation test extended with this route, actual Go WASM
website UI identity/refusal, old generation/hidden UI guards and read-only demo
navigation cover the boundaries. Full CI/race and separately recorded
maintainer self-review remain required before merge. The preview is generated
data with live observation disabled; no live production target or independent
audit is claimed. Automatic renewal stays deferred; Porch is untouched.
