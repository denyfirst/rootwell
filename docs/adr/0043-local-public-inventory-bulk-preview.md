# ADR 0043 — Local public bulk preview before atomic inventory Save

Status: accepted for development, not independently audited.

## Decision

Inventory offers one path: select 1–8 public files, Preview locally, then
Save all. PEM certificate bundles and single DER certificates can be mixed;
extensions do not decide encoding. Combined inputs are at most 16 MiB,
64 certificates, 512 KiB displayed subject/issuer metadata, and 64 KiB DER
per inventory object. Existing Go parsing/export boundaries are reused.
No new dependency, format, network destination or storage schema is added.

Preview uses the real Go WASM parser in the browser. The Inventory-only
loader fetches only the fixed /rootwell.wasm asset with same-origin
credentials and redirects refused, since the gateway protects assets with
ready access. The standalone Workbench's cookie-omitting loader and no-upload
processing remain unchanged. The helper itself has no network, DOM, storage
or download capability. This is bounded main-thread public processing, not a
preemptible parser worker; a blocked browser process cannot enforce a timer.

Preview retains File references and detached public metadata only, not input
buffers. No file bytes go to the server before explicit Save. Filenames are
bounded, controls/bidi formatting replaced, and all text uses textContent.
PFX, private-key blocks, mixed content, malformed/oversized files and duplicate
certificates within/across selected files reject the entire preview. Within
a bundle, the file is identified; cross-file duplicate errors name both files.
Saved-record duplicates are marked in the successful preview and block all
Save. No entry is silently skipped, merged, overwritten or trusted.

Save rereads the exact selected File identities, reparses them via the Go
bundle exporter against the ordered preview fingerprints, includes every
certificate, reparses the resulting canonical public PEM and checks its
fingerprints. Input/output byte arrays are best-effort cleared; this does not
promise browser/OS memory erasure. One existing /api/inventory POST sends only
that public bundle and the operator's shared optional owner/location notes.
Those notes apply to every certificate, as the UI states. Raw selected files,
filenames and parsing errors are not uploaded.

The server remains final authority: ready Linux revision-bound session, exact
Origin plus custom header, bounded JSON, strict public reparse, complete-image
authentication, duplicate/capacity refusal and existing locked atomic append.
The browser snapshot is advisory, not a new server generation precondition;
another session may add a duplicate after preview, causing refusal of the
whole batch. Unrelated concurrent changes need not block an otherwise valid
append. This is inventory import, not a trust, deployment or renewal verdict.

Selection changes, explicit inventory refresh, visibility loss and page exit
invalidate preview and pending rereads. Late completion cannot render or
start POST. Stale/unavailable inventory cannot save. The one-minute monitoring
refresh pauses while a selected/previewed batch is being prepared; the
two-minute staleness guard still disables Save. Explicit refresh clears the
preview, requiring another Preview. Local readiness/read deadlines bound
asynchronous waiting but do not interrupt synchronous WASM execution.

Save responses are bounded to 4 MiB, have a 20-second deadline and must return
the exact ordered fingerprint set. A network failure, timeout, navigation
after POST or inconsistent success response is an uncertain outcome: refresh
before another import. Aborting a request cannot undo a server commit.
The read-only Windows demo allows only local synthetic-file preview; both the
client read-only guard and write-refusing fixture server prevent persistence.
It is not real authenticated Linux storage or a production deployment.

## Evidence and remaining risks

`scripts/test-inventory-bulk.mjs` runs actual public preparation and Inventory
UI against real Go WASM. Success, mixed PEM/DER, bundles, same-/cross-file and
already-saved duplicates, private/mixed/malformed input, size/count limits,
same-size content replacement, hidden/changed/late source, inconsistent engine
output, conflict/unconfirmed save and read-only fixture paths are exercised.
`TestInventoryBulkAssetsRemainBehindReadyAccess` covers the new asset routes.
`TestLinuxInventoryAPIRequiresReadySessionAndExplicitSave` exercises one
successful two-certificate transaction and byte-identical images after
duplicate/mixed-secret batch refusal. Existing catalog/storage fault, race,
restore, capacity and parser fuzz tests remain mandatory. Separate maintainer
self-review and CI gates are development evidence, not independent audit.

Compromised browser/assets/extensions/host, already-copied metadata, intact
filesystem rollback and the inherited access-file in-request race remain
outside the claim. Public metadata can disclose topology. No new trust,
private-key custody, outbound monitoring, background alert or Porch change.
Independent review remains required before first release/real-user use.
