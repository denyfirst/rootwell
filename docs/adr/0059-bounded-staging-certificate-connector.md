# ADR 0059 — Bounded same-order staging certificate protocol connector

Date: 2026-10-12. Issuance wave, internal network-component increment.

Implement and exercise the maintained pinned x/crypto ACME client behind a
separate certificate transport, without yet exporting/wiring it to a live
route. No new UI control, custody write, signer lease, production enrollment or
can_issue authority. The complete issuance wave remains unfinished. Porch and
offline Workbench are unchanged. Architecture guards require a separate review
before any exported entry or production call site is introduced.

The unexported dependency seam is test-only, not runtime configuration. Inputs
are an account signer, exact account-bound saved order, earliest saved expiry,
canonical names and the exact prepared private key/DER CSR. Recheck existing
request policy, key/CSR signature and name binding before any connection;
account key reuse refuses. The private certificate key is only checked locally,
never signed with as an account or placed into a request. Only the exact DER CSR
leaves the daemon in a library-signed finalize request.

First-attempt and read-only reconciliation are distinct transport authorities.
Observe ready order and the complete exact-name/all-valid authorization set
before a SINGLE finalize; never create an account/order or accept a challenge.
Every authorization must be current and independently mapped, including
wildcard/apex distinction. Same-order refresh never finalizes, even if the CA
still reports ready; it returns the observed non-issued state. A valid order
can fetch its exact certificate URL after all authorization checks. Failed/lost
finalize response returns a fixed error and zero observation, never a replay.
The durable caller must retain uncertainty, not treat an error as unsent.

The pinned client's CreateOrderCert calls WaitOrder internally. A preflighted
processing response terminates ALL further transport authority (even nonce
HEAD), so automatic polling is stopped before I/O. Only a processing observation
without DER is returned. This is not issuance success or proof of storage.
Explicit future reconciliation can re-read the same saved order. Pending, ready,
processing and invalid observations have no certificate/trust authority.

Twenty-second overall context, maximum 23 requests (directory, nonce + one
order read, nonce + up to 8 authorizations, nonce + finalize, nonce + certificate).
Eight-name success exactly exercises 23; refresh needs at most 21. Each POST
destination is single-use. Any refusal permanently closes that operation.
Expiry can shorten, not extend; time/permission checks surround requests and
publication. Existing fixed staging host/TLS/public DNS numeric-dial pinning,
header/handshake limits, no proxy, no redirects, no retry or Link/AIA/OCSP/CRL/
alternate-chain fetch remain. No production/custom endpoint or verifier option.
CA HTTP errors, badNonce and rate limits are fixed refusals, not retry authority.
Future retry/backoff/rate-limit policy is separate reviewed work.

Only the exact derived finalize path and a canonical same-origin /acme/cert/
opaque identifier from the validated same-order response can be followed.
Order names/finalize/authorization membership cannot change after finalization.
JWS preflight checks exact KID/nonce/URL/ES256 headers, canonical base64url,
single exact csr field, or empty POST-as-GET payload. The maintained client
generates signatures; no custom crypto/ASN.1/JWS encoder is introduced.
Response headers/unknown metadata/errors are not reflected or followed.

Strict JSON and public PEM preflight precede upstream parsing. PEM may contain
1–5 certificates (the pinned client's narrower chain ceiling), each <=48 KiB,
DER total <=256 KiB and wire <=352 KiB. Standard PEM decode is isolated to the
FIRST envelope so its normal garbage-skipping behavior cannot conceal a broken
block; headers, mixed/private blocks, duplicates, malformed/trailing DER,
garbage/trailing text and excess count/size refuse without partial output.
This step parses, NOT verifies certificate policy/key/names/trust. The returned
DER is explicitly untrusted receipt input. ADR 0058 must be applied separately
under the custody writer lock before atomic pair storage; a protocol receipt
from a synthetic untrusted issuer is explicitly rejected by that real checker.

Before live wiring: commit authenticated intent before ANY CA request; reserve
completion capacity; lease the SAME sealed key/CSR/account/order; prohibit blind
finalize replay across restart/lost response; preserve read-only same-order
reconciliation; receipt revalidation and atomic pair transfer/test-only immutable
provenance; full backup/recovery; fresh-password/consent and simple bounded UI.
These are not implemented by this network component. No data mutation, live
CA/DNS contact, public interoperability, browser visual QA or audit is claimed.
Expired-order recovery/new orders/cleanup, renewal and DNS adapters remain.

Sources reviewed 2026-10-12: [RFC 8555 sections 7.4/7.4.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4),
[Let's Encrypt staging](https://letsencrypt.org/docs/staging-environment/), and
local pinned golang.org/x/crypto v0.57.0 acme/rfc8555.go CreateOrderCert,
WaitOrder, GetOrder and FetchCert. Synthetic isolated TLS tests verify actual
client JWS with an independent signature check; they are not live CA tests.

Required evidence: first-attempt and reconciliation success, exact CSR/account
JWS, processing without polling, HTTP/lost-response without retries, exact names/
all-valid authorization set, unsafe URLs/headers/errors, revocation/cancellation,
PEM/DER/count/size refusal, unchanged input and synthetic receipt trust refusal.
Parser fuzzing, no-live-wiring architecture, two-direction compiling sabotage,
full local/pinned gates and all required exact-head CI precede merge. Development
self-review is not an independent production audit.

Local evidence 2026-10-12: full shuffled Windows Go suite, fmt/tidy/module verify,
vet/build/staticcheck/gosec, Linux/macOS cross-vet, Linux-target gosec and
actionlint passed. All five existing ACME setup/directory/account/registration/
order UI VM scripts passed (not visual QA). Final parser fuzz seed set includes
order, PEM and JWS; twenty-second/two-worker run passed 317362 executions.
An earlier order/PEM-only run passed 200278. Package coverage was 88.4%, not a
security guarantee. Live govulncheck was attempted twice and unavailable because
vuln.go.dev DNS lookup failed; the required exact-head CI vulnerability/platform/
race/container/signature checks must pass before merge. No check was bypassed.

Actual two-direction compiling sabotage, then restored: replacing exact CSR
equality with a non-empty-field check made TestCertificateGuardExactCSRAndDenyByDefault
fail "altered CSR/JWS scope gained authority"; replacing the request ceiling with
>=0 made TestCertificateConnectorExactCSRAccountJWSAndReadOnlyReconciliation fail
"valid bounded certificate flow refused" with zero requests. Restored tests
passed; no sabotage retained. An attempted two-hunk patch in reverse line order
failed to apply and is not behavior evidence. The initial malformed-first-PEM
test exposed standard decoder garbage-skipping; first-envelope isolation plus
the nested-BEGIN refusal fixed it and the restored refusal tests passed.

Separate final-diff review added an explicit earliest-expiry recheck when
publishing a processing observation, matching receipt publication. Expired
processing/valid finalize-response tests refuse without polling or receipt.
The follow-up final head needs fresh exact-head CI and superseding self-review;
earlier-head checks cannot authorize it.

Final-head container CI found a genuine packaging failure, not an infrastructure
flake: the acmestaging test binary now links the receipt checker, whose embedded
public staging-roots.pem was excluded by .dockerignore. Add only the exact
internal/acmecertificate/staging-roots.pem exception AFTER the general PEM deny;
all other PEM/secret exclusions remain. Container configuration regression tests
require default deny, exact post-deny asset inclusion and only the reviewed
public PEM exception set. Real Docker build/volume/trust-drill CI must pass on
the new head. Staging roots are not copied into the system CA trust bundle.

Packaging sabotage was actually run and restored in both directions: deleting
the exact root exception failed "Public staging trust needs its exact final
build-context exception"; adding broad !internal/** failed "An unreviewed/broad
build-context inclusion is not permitted". The regression freezes all reviewed
source/public input negations, not merely PEM filenames. Restored Node checks
passed; no sabotage or weakened deny rule remains.
