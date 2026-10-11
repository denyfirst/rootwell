# ADR 0056 — Explicit staging DNS validation and read-only reconciliation

Date: 2026-10-11. First increment of the approved validation → issuance/pair
storage → renewal → DNS automation wave. Linux single-operator development.
Porch, offline Workbench, production CA and DNS provider credentials unchanged.

## Authority

After local DNS acknowledgement, a fresh-password, exact-generation/revision,
explicit-consent action saves encrypted validation intent before network under
the private writer lock. It reserves a result slot. Read the exact saved order
and every authorization before accepting any challenge. Recompute each pending
DNS digest with the stored account signer and compare it to the acknowledged
TXT; changed names/tokens, duplicate identities/challenge URLs and partial sets
refuse before acceptance. Only exact pending dns-01 challenge URLs from that
complete snapshot may receive the maintained client's Accept, with payload {}.
No arbitrary signer/URL/payload, new order, finalize, certificate fetch or DNS write.

One bounded snapshot, not WaitAuthorization/WaitOrder polling. At most 35
requests: directory + nine nonce/read pairs + eight nonce/Accept pairs. The
existing 20-second CA / 25-second API / scoped 30-second response/UI deadlines,
pinned public DNS/IP/system TLS, no redirects/proxy/retry/Link, strict UTF-8,
unique bounded JSON and shared budgets apply. Error bodies never reach the UI.

Unknown completion retains validation intent. Subsequent explicit fresh-password
refresh reads only the same saved order/authorizations: never repeats Accept or
creates a new order. This deliberately conservative first increment can leave
an unsent pending challenge after a partial multi-domain failure; reviewed
per-challenge reconciliation/retry authority is needed before production.

## Evidence and custody

Accept success is not domain verification. Persist a typed, name-bound CA
snapshot: pending/valid/invalid authorizations and pending/ready/invalid order.
Only a ready order AND every authorization valid produce domain-verified.
Shorten but never extend the saved expiry. Preserve original TXT, certificate
and account ciphertext. Whole-image validation, fixed history and full backup/
recovery include intent/result. No reliable heap erasure or rollback protection.
Older binaries refuse new states/fields/actions. Completion capacity is reserved
across unrelated writes; capacity is not silently recycled.

The same card separates acknowledgement, request uncertainty, waiting, CA
failure and confirmed CA result. Only explicit consent contacts staging; no
page-load/poll/scheduler. Every refresh invalidates stale authority. The public
contract is v2; no private signer, internal resource URL or raw CA error output.
Domain verification is a saved CA observation, not certificate issuance, trust,
revocation or deployment. Expired observations grant no current verification.

Tests must cover actual library JWS against isolated fake TLS CA, changed digest
before ANY acceptance, multi-domain partial failure/no retry, read-only refresh,
ready/all-valid truth, strict authority, encrypted restore, UI late/hidden/body
limits and two-way intentional sabotage. VM tests are not visual browser QA;
public staging interoperability and independent release audit remain open.
The strict authorization parser currently requires a canonical future expires
value even for terminal failures; omitted/expired provider timestamps therefore
remain an uncertain refusal, not a usable verdict. Production interoperability
must cover these provider response variants without weakening verification.

Protocol reviewed: [RFC 8555 §7.5.1](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1)
and pinned golang.org/x/crypto v0.57.0 acme.Accept (default exact {} payload).
Later increments add separately reviewed key/CSR/certificate custody and
manual renewal before DNS-provider automation. No claim all four are complete.

## Local deliberate sabotage evidence

Temporarily replaced the valid ready/all-valid verdict with refusal:
`go test ./internal/acmeorder -run TestValidationVerdictRequiresReadyAndEveryAuthorization -count=1`
failed as intended. Restored. Temporarily removed the acknowledged TXT digest
equality check: `go test ./internal/acmestaging -run TestDNSValidationRejectsChangedOrPartialScopeBeforeAnyAccept -count=1`
failed as intended before publication. Restored. The focused validation suite
then passed. These exercise refusal of valid behavior and acceptance of unsafe
behavior independently. No sabotage remains in source.
