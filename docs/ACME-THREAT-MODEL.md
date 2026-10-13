# ACME staged implementation boundary

Date: 2026-10-11. Single operator, existing loopback access gate. Porch is
excluded. Offline Workbench acquires no CA network capability.

## First increment: setup check, not issuance

Automation accepts 1–32 unique ASCII DNS identifiers and a manual DNS-01 or
HTTP-01 choice for one fixed Let's Encrypt staging provider. It performs only
bounded syntactic checks on the operator's own daemon. No DNS lookup, HTTP
request, account/key creation, terms acceptance, secret input, persistence,
challenge provisioning, renewal or deployment. Ready login, exact host/origin,
custom request header, POST-only strict JSON and no-store apply. Preview grants
no authority; a valid-looking name does not prove ownership, eligibility,
reachability, CAA permission or CA acceptance. Unicode and IP identifiers are
outside this initial policy. Wildcards require DNS-01.

Assets: private service names, future account key and account URL, certificate
keys/CSRs, DNS credentials, authorizations, orders, challenge values, instance
identity, backups and future explicit authority. Trust browser/daemon/host;
untrusted inputs include names, JSON, responses, CA-provided URLs, clocks,
storage images and stale sessions. Runtime strings/host compromise remain.

## Second increment: optional staging directory connection

ADR 0050 adds a separate explicit-consent, ready-session connection check.
Only one GET to the fixed staging directory; no names, keys, account or terms
decision. IP/DNS visibility is disclosed. System TLS trust, original SNI,
public-only bounded DNS with numeric dial pinning, no proxies/redirect/retry,
8-second deadline, 8 KiB headers, 32 KiB strict JSON, validated known endpoint
URLs, one in-flight operation and 30-second RAM cooldown. Cancellation and live
session checks surround network boundaries and result publication; already-sent
bytes cannot be recalled. Only a fixed reachability summary is returned; no
CA error/metadata reflection, filesystem write or issuance authority. Unknown
bounded extension metadata is ignored and never followed. Setup remains offline.
Tests use an isolated synthetic TLS CA, not the public staging service.
Live provider access is Linux/Docker-only; native platform verification may
perform additional OS-managed certificate retrievals, so Windows/macOS refuses
this capability before DNS. Local syntax/Workbench functionality is unchanged.

## Third increment: local account-key preparation, not registration

ADR 0051 saves one newly generated P-256 staging account key in a distinct
purpose-separated encrypted field of the complete image. Explicit local status
and preparation, fresh password, shared attempt/crypto budgets, displayed
generation, exact access revision and live permission under the writer lock.
Atomic history, certificate mutation preservation, full backup/restore and
offline password recovery apply. No key in browser/history/logs; only public
identity and prepared time. Native Windows/macOS refuses this custody.
No new outbound capability, CA registration, terms decision, email/domain,
key import/export/replacement or issuance. An uncertain save is reconciled by
refreshing the existing key's status, not generating/replacing it. Old binaries
refuse the new manifest field. Manual backups and complete-image rollback risks
remain. Preparation grants no authority to the directory-only connector.

## Fourth increment: explicit registration, not issuance

ADR 0053 adds a separate five-minute, single-use current-terms preview bound
to the ready session, revision, image generation and account fingerprint.
No automatic connection/terms agreement. Registration needs fresh Rootwell
authentication and explicit agreement; a fresh directory read must match the
displayed terms URL before nonce/POST. Only the account public JWK and signed
terms-agreement request leave the daemon; no domain/email/password/private key.
The maintained pinned ACME client supplies JWS, never custom signing code.

Encrypted pending intent commits before network authority. The private writer
lock spans the bounded operation; reserve a history/generation completion slot.
Failures retain the same key/pending state. Separate fresh-password confirmed
reconciliation uses onlyReturnExisting with no creation/terms fallback. A
strictly validated absence permits a new explicit preview/registration later;
a validated existing account is saved without exposing its account URL.
Whole-image validation, history, complete backup/restore and offline password
recovery retain key and registration identity. No account replacement/export.

At most directory GET, nonce HEAD and newAccount POST, to fixed staging paths,
ten-second total deadline and inherited pinned DNS/TLS/header/body/no-proxy/
no-redirect/no-retry policy. Strict request JWS and CA JSON preflight strips
extension/error/Link metadata before the upstream parser. Account/orders URLs
are validated, never fetched. Terms links are constrained to canonical Let's
Encrypt document URLs; the operator reads the external document, not Rootwell.
URL equality is not document-content verification or a legal interpretation.
One global provider operation, shared fresh-auth budgets and RAM cooldown; an
approved registration may immediately follow its own preview, not another read.

Tests use only a synthetic isolated TLS CA and verify real JWS. CI also restores
synthetic registered account metadata across actual container processes; it
does not register with the public CA. Browser VM tests are not visual QA.
Native preview remains offline. No order/challenge/issuance/renewal/deployment,
production enrollment, EAB, custom CA or anti-rollback claim. A lost response,
post-rename error, old complete backup or already-sent request can still require
manual same-key reconciliation. Repeat manual full backup after transitions.

## Subsequent capability gates

ADR 0062 connects fixed staging Certificate to durable exact-key/CSR lease and
atomic pinned completion through explicit Linux UI issue/read-only refresh.
Intent commits before I/O under one lock. Fresh password/consent/generation,
session/origin/provider/time budgets repeat; no receipt/key/root upload. Only
same-order reads after uncertainty, no finalize replay/new key/order. Earliest
CA expiry also bounds crypto/publication and persists without later extension.
V5 includes that deadline and scoped can_issue. Hidden/late/strict UI refuses;
saved/deleted requests close. Runtime trust overrides are architecture-blocked.
Fake TLS/VM/synthetic transaction and read-only browser evidence is not positive
live pinned-CA interop. Native refuses. Old complete rollback, host/runtime,
clock/material/history limits, new/expired order policy, renewal/DNS and audit
remain. See ADR 0062; earlier increment boundaries below are historical.

ADR 0061 adds internal atomic completion and historical saved-state UI, NOT live
connector wiring or can_issue. Repeat fixed independent staging Check under the
writer boundary; exact saved key/CSR/names/order/account/expiry/generation.
Move the same private bytes into matched material; keep only public CSR/scope
in the prepared request. One leaf/material/provenance/history image, no overwrite
or duplicate. Use the reserved final slots and release reservations on completion.
Full decode revalidates all links before public output. Historical authenticated
origin is NOT current issuer trust; list/restore must remain usable after expiry
or trust changes. Delete current pair/CSR but retain a no-replay public tombstone.
V4 order/key/issuance status is one snapshot; old DNS/key actions stop before
provider work once issuance started. Test-only UI and fake read-only browser demo
do not establish live CA interoperability. Production entry rejects the synthetic
custody fixture. Live fetch/lease/receipt/commit/fresh-auth/consent/budgets and
interactive issuance, oversized/duplicate/expired receipt policy, retention,
renewal/DNS and independent audit remain. Existing material-size limit may refuse
otherwise accepted protocol chains. No heap erasure or anti-rollback guarantee.

ADR 0060 implements only durable issuance intent/lease and the Linux custody
writer seam, not a network entry. Exact account/order/prepared key/CSR/names,
installation/purpose/generation/time authenticate before any public result.
Commit intent under the private lock before borrowing secrets; consume the
opaque image-bound lease once, even across copied handles. Lost/uncertain
results, reopen and full recovery permit only same-order reads. No first-attempt
replay, key regeneration or fabricated issued/valid observation. Historical
non-issued observations grant no authority; read-only refresh does not consume
another intent slot. Keep a final generation/history/record and 1 MiB headroom
reserved for future pair completion. Domain-validation mutation is blocked.
Full backup/password recovery preserves the exact keys/CSR and intent. Native
platforms refuse this custody. Trusted callbacks/host compromise, complete old
pre-intent rollback and reliable heap/scalar erasure are outside the guarantee.
Receipt/pair transfer/provenance, reservation release, fresh-auth/consent/budgets
and live/UI integration remain separate required work. No can_issue increase.

ADR 0059 adds a separately constrained internal certificate protocol component,
not a live export/route. Exact prepared key/signed CSR policy before I/O; ready
same-account order and complete all-valid exact-name authorization mapping
before one finalize. Read-only same-order reconciliation cannot finalize.
Processing stops even the library's automatic nonce/poll before outbound I/O;
lost/error responses give fixed refusal and no replay/partial receipt. Existing
pinned transport, 20-second/23-request maximum, expiry/permission checks,
strict JWS/JSON/PEM and stripped metadata apply. Five public certificates max
(upstream ceiling), 48 KiB each/256 KiB DER/352 KiB wire. DER remains untrusted;
ADR 0058 acceptance still required before any future atomic custody write.
This protocol component alone has no durable intent, pair or API/UI authority;
ADR 0060/0061 add those internal custody/status boundaries separately. No live
certificate CA contact yet; architecture still blocks connector wiring/export.
Full issuance/recovery/UI integration, renewal/DNS and production audit remain.

ADR 0058 supplies only the offline staging receipt-acceptance component of
gate 4. Exact prepared key/signed CSR, strict DNS-only SAN set (wildcards
included), explicit digital-signature/server usage, supported policy/current
time/critical extensions and complete ordered-path constraints are checked.
Bounded DER response: 8 certificates, 48 KiB each, 256 KiB total.
RSA response keys are additionally capped at 8192 bits before signature/path
arithmetic; small DER can still contain a huge modulus. Existing floors remain.
Four reviewed embedded self-signed staging root DER hashes supply independent
test-only trust;
no response/system root fallback or dynamic update. Supplied roots can appear
only as the exact independently trusted terminal member; every response member
must be used. No I/O, signer generation, route, write or new UI authority. Fixed
errors/no partial evidence, unchanged caller buffers. Standard parsers inspect
even otherwise ignored SAN types/key-usage bits; no custom crypto/ASN.1 encoder.
Synthetic acceptance tests do not prove live CA interoperability. Public source
HTTPS/root-hash review is not an independent out-of-band trust ceremony. CA
intent/finalize/reconciliation, atomic pair transfer/staging provenance and
full recovery/UI integration still need the next reviewed increment. Staging
roots never enter system/browser trust; no revocation/CT/deployment/audit claim.

ADR 0057 implements only the local signer/CSR custody part of issuance gate 4.
Unexpired ready/all-valid saved observation, explicit consent, fresh password,
exact generation/revision and live permission under the private writer lock.
One new P-256 signer, canonical PKCS#8 and signed exact-SAN/empty-subject DER
CSR; never reuse the account signer. New HKDF-purpose-separated AES-GCM field
binds installation, generation, account fingerprint, saved order and names.
Complete-image validation rechecks key/CSR/signature/policy/binding before any
output. Atomic public history, one remaining slot and nonce-budget checks;
full password/recovery backup and password recovery preserve identical material.
Only public prepared time/fingerprint reaches the v3 same-card UI. No CA I/O,
automatic generation, reset/delete/export/replacement, certificate record or
issuance authority. Shared auth/crypto budgets and hidden/late/strict-response
refusal apply. Existing account/order/certificate data is preserved. Native
platforms refuse before file/callback. No browser visual QA/live CA/audit claim.
Future finalize must use this exact CSR and reconcile the same order without
blind replay or client-managed polling; independently configured staging-only
trust is required before returned certificate/key pair storage. Unused-request
cleanup, expiry/new order policy, renewal and DNS adapters remain separate work.

ADR 0056 separately enables explicit staging DNS validation and read-only
same-order CA refresh. Before network, encrypt intent and invalidate the prior
verdict under the writer lock; reserve intent/result capacity. Complete exact
name/wildcard authorization mapping and recomputed acknowledged TXT/account
digests precede ANY Accept. Only registered KID, approved pending dns-01 URLs,
exact {} payload; no new order/finalize/certificate/DNS write. A later explicit
refresh never repeats Accept, even after partial or unknown completion. No
automatic polling. Same 20-second CA/25-second API/30-second scoped response/UI
limits; up to 35 requests, inherited pinned transport and strict JSON policies.
Ready order AND every valid authorization are required. Failed/pending/unknown
never become verified; expiry can shorten, not extend. Complete image, fixed
history and full restore preserve intent/result/account/certificates. v2 public
contract exposes no internal URI/signer/error. Partial unsent challenges,
expired/new orders, live staging interoperability, issuer trust for issuance,
renewal/DNS credentials and independent audit remain reviewed release work.
VM tests are not browser visual QA, no real CA/DNS testing in this increment.

ADR 0054 implements only manual DNS order/instructions/local acknowledgement
from gate 3, not domain validation or issuance. Exact registered KID/key and
up to eight names; encrypted intent before network and account-bound order URI
checkpoint before any body read. A failed creation without URI is blocked,
never reset or automatically recreated. Saved URI continuation is POST-as-GET,
not a new order. Private writer lock, exact revision/generation, fresh password,
explicit name disclosure and shared crypto/attempt/provider cooldown apply.
Fixed pinned staging transport, twenty-second CA budget/nineteen requests,
strict bounded UTF-8/unique JSON, empty read payloads, exact identifier set,
authorization/wildcard mapping and canonical DNS challenge digest. No broad
signer, Accept/finalize/certificate, retries, Link/error reflection, custom CA,
production or DNS credentials. The 25-second API context and scoped 30-second
write deadline do not relax the server's general timeouts. Unsupported response
writers refuse before any mutation. Returned instructions use the earliest
order/authorization expiry. Two values at one TXT name are never collapsed.

One typed HKDF-separated encrypted order field is part of complete-image
authentication, fixed history and full backup/recovery. Reserve intent/URI/
instruction slots before network. Certificate/account keys remain unchanged;
old binaries refuse the new field. Browser exposes only names/expiry/TXT/state,
never signer/account/order URLs or provider error data. Explicit local
acknowledgement is not DNS/CA verification. Hidden/late/source/timeout clears
authority and requires status refresh; cancellation is not rollback. Fake TLS
CA and VM tests do not establish live interoperability or visual browser QA.
No anti-rollback/heap-erasure claim; manual backups and uncertain post-rename
results remain. Missing-URI reconciliation, expired/new order policy and history
capacity must be solved in separate increments before production readiness.

1. Directory-only dependency/transport increment implemented in ADR 0050;
   broader ACME/Pebble protocol testing remains future work. Explicit ready-session opt-in
   must show destination and data sent. No production/custom URL fallback.
   Validate HTTPS URL/host/path/port, every directory/order/authorization/Link
   endpoint and redirect. Reject private/loopback/link-local/metadata addresses,
   DNS rebinding, env proxies and cross-origin redirects; enforce dial-time
   address checks, TLS verification, response/time/concurrency/retry limits.
   Test all redirects/SSRF/timeout/oversize cases; no real CA in default CI.
2. Account: separate staging/production identity; fresh instance authentication
   and explicit terms decision; purpose-separated encrypted signer, installation
   binding, exact generation and atomic account/history/full backup/restore.
   No account key/export/credential in logs, browser output, URLs or storage.
   Registration uncertainty must retain the same key and reconcile rather than
   blindly register again. Profile/account/domain authority is revalidated at
   each operation; no unlock lifetime extension. No EAB until separately reviewed.
3. Manual DNS-01 first: one bounded order, domain-bound challenge instruction,
   explicit user acknowledgement after provisioning; no fabricated TXT token
   during setup. Wildcard/apex can require separate values at one TXT name.
   Do not fetch arbitrary user endpoints or change DNS through full-account
   credentials. Provider tokens later need minimum zone/record scope and
   encrypted custody with explicit cleanup ownership and failure reporting.
   HTTP-01 later needs separately scoped webroot/listener permission, not a
   remote shell or the loopback access-gate listener made public.
4. Issue: new signer + signed exact-SAN CSR; reconcile returned non-CA
   certificate, exact public key/names, policy/time and issuer path using
   independently selected trust. Staging roots stay test-only, never system
   trusted. Save complete material atomically to Certificates; no overwrite,
   no duplicate new order on uncertain completion, no claimed deployment.
5. Manual renewal before scheduler: new issuance, preserved prior usable
   certificate until explicit replacement, bounded retries/backoff/jitter,
   Retry-After/CA rate limits, clock errors, pause/unlock and visible failures.
   Manual DNS is not unattended renewal. ARI/renewal rules need current review;
   do not hard-code assumed validity or renew every fixed number of days.
6. Deployment is separate: exact target/action authority, staging/validation,
   atomic replacement, reload, independent live verification and rollback.
   No Porch changes or shell/SSH capability in this increment. Production
   enrollment/release requires independent audit and explicit decisions.

## Closed request custody — ADR 0063

Explicit local closure requires fresh password/consent, exact generation and
writer revision/permission. Only completed or authenticated known-expired
scopes qualify; active or unknown creation refuses. Expiry/closure cannot prove
non-issuance, cancel/revoke at the CA or authorize old-order replay. A separately
sealed bounded archive retains exact nested ciphertext and validates all
bindings before output; no lease/network/reopen/export interface. New starts
are separate durable intents with fresh consent; archived URLs cannot be reused.
Saved material, notes, account and derived test-only origin remain. Deleting a
pair updates the historical deletion tombstone atomically. Full restore retains
archives; prior backups/host-clock rollback are not prevented. Maximum 32 scopes,
no silent pruning; pending prepared keys remain encrypted but have no historical
key-export UI. Manual renewal and retention/cleanup need separate decisions.

## Evidence required

Success, malformed/refusal, secret-free errors, no unapproved outbound/storage capability,
origin/setup/session/host, late/hidden/source-changed UI and two-way sabotage.
Every future increment must add its own protocol/crypto/permission/recovery
tests before enabling its capability. Green development CI is not audit.

Sources checked 2026-10-08: [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html),
[Let's Encrypt staging](https://letsencrypt.org/docs/staging-environment/) and
[challenge types](https://letsencrypt.org/docs/challenge-types/).
