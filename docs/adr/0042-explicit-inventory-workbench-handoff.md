# ADR 0042 — Exact saved public certificate → offline Workbench

Status: accepted for development, not independently audited.

## Decision

Saved certificates has two plain **Inspect** / **Verify** buttons per card.
They navigate in the same tab using a native POST form to `/workbench`.
Only the canonical full fingerprint, displayed image generation and an
allowlisted destination are submitted. There is no certificate upload,
download UI, URL parameter, application browser storage, popup, message
channel, session handoff queue, new dependency or storage-schema change.

The Linux gateway requires a ready revision-bound session, an enrolled
installation, exact Origin and mandatory `Sec-Fetch-Site: same-origin`,
`Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`. This is a narrow
exception to the JSON API's custom-header requirement: native forms cannot
set that header. Unsupported browsers fail visibly, with no relaxed fallback.
Host, query, method and session checks still run. The form is bounded to
1 KiB, accepts exactly one of each of three fields and rejects unknown fields,
noncanonical fingerprints/generations and unsafe integers.

The entire encrypted inventory is authenticated under existing private-file
locks before exact generation and fingerprint lookup. A stale or absent
selection returns no certificate. A read neither writes ciphertext nor changes
generation/session expiry. It is a snapshot, not an anti-rollback anchor.

Only the selected <=64 KiB public DER and identity/destination are inserted
into a single inert text marker in a bounded Workbench template using
HTML-escaped JSON. Owner/location notes, private keys, credentials and trust
fields are excluded. Responses remain `no-store`, `nosniff`, unframeable.
Only the Inventory document permits same-origin form navigation and uses
`Referrer-Policy: same-origin` (including its meta policy); other documents
remain no-referrer. Inventory has a fixed query-free URL and still sends no
referrer to other origins. `no-referrer` would force native POST Origin to
`null` under the [Fetch Standard](https://fetch.spec.whatwg.org/#append-a-request-origin-header),
breaking the exact Origin guard. `null` remains refused; the guard is not
relaxed. Both header and meta policy are regression-tested.
Workbench's CSP and file/network capability separation are unchanged.

The file-reading UI consumes and immediately removes the inert container,
validates its exact schema/limits, creates a memory-only public File, and
reparses it through the same Go WASM core. Full fingerprint and single-object
identity must match before any certificate cards or guided Verify source are
shown. New manual selection or page exit cancels pending handoff. Page exit
clears retained saved-source cards, guided inputs and verdicts. No automatic
processing overrides an earlier manual selection.

Verify only inherits a source when exactly one certificate lacks the CA flag.
The hostname and a separate trusted root are still required. Optional issuer
files can be added explicitly to guided sources without re-uploading the
leaf; the replacement picker stays hidden behind an explicit "Choose different
certificate files" action while a source is already loaded. Existing total
file/byte limits and verifier rules still apply. Added
files never become trust, new choice invalidates the verdict, and verified
export re-verifies the captured complete sources. A saved root cannot choose
itself as trusted. Missing issuers, duplicate/unsafe files and wrong trust
fail normally. Conversion/export stay in their existing Workbench locations.

## Residual risks and nonclaims

This is not private-key custody, live TLS monitoring, renewal, revocation or
proof that manual server notes describe deployment. Browsers, extensions and
the OS can retain copies, including document memory/history; no browser-wide
erasure claim is made. A local snapshot already opened in Workbench is not
automatically revoked by later server-session expiry/deletion. It is cleared
at page exit, and subsequent server reads reauthenticate. An operator-owned
asset directory and uncompromised same-origin code remain required. Existing
in-request access-file races and complete-image filesystem rollback boundaries
are unchanged. The synthetic demo has no authentication/durable user storage;
only its repository-generated public test leaf supports this navigation.

## Evidence

`TestWorkbenchSelectionIsExactBoundedAndNonUploading`,
`TestInventoryWorkbenchHTMLContainsOnlySelectedPublicObject`,
`TestLinuxInventoryWorkbenchRequiresAuthorityAndExactSnapshot`,
`scripts/test-inventory-workbench.mjs` (real Go WASM),
`scripts/test-rootwelld-inventory.mjs`, `scripts/test-inventory-demo.mjs`,
existing capability/trust tests and browser click proof. Both-direction
sabotage must fail the real-WASM handoff regressions before merge.
