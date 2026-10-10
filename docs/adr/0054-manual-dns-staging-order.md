# ADR 0054 — Durable manual DNS staging order and honest acknowledgement

Date: 2026-10-11. Linux/loopback single-operator development only; Porch and
the offline Workbench remain unchanged. Independent release audit is required.

## Increment and sequence

The approved wave is manual DNS order → issuance/pair storage → manual renewal
→ limited DNS-provider automation → production/readiness and independent audit.
Each increment has its own signed PR, refusal/sabotage evidence and full gates.
Provider selection/credentials, production terms/account authority and external
audit are not inferred. No real CA/DNS action is performed by development tests.
This first increment creates a staging order and shows real CA-derived TXT
instructions; explicit local acknowledgement is not domain validation.
No Accept/finalize/certificate download/issuance, DNS lookup/change or scheduler
capability is granted until the next separately tested increment.

## Authority and uncertainty

Ready exact-origin/fetch metadata, strict bounded POST, fresh Rootwell password,
explicit network consent, exact generation/revision, shared auth/crypto budget,
one global provider operation and cooldown apply. One active order, up to eight
unique normalized ASCII DNS names, wildcard DNS-01 included; no IP/HTTP challenge.
Display that names are disclosed to staging. Persist encrypted intent before any
network under the private writer lock; reserve completion history/generation.
Persist the canonical account-bound order Location before reading its body or
authorization resources. Failure retains intent/known URI; explicit refresh
reads only that saved order, never creates another. Missing Location after an
uncertain creation is blocked, not reset/retried; future reconciliation needs
an additional reviewed mechanism. No automatic clear/replace/cancel of orders.

Use the maintained pinned acme client for AuthorizeOrder, GetOrder,
GetAuthorization and DNS01ChallengeRecord, with stored registered KID/key.
Separate transport permits directory GET and bounded nonce HEAD/signed POSTs
only to the fixed staging origin and reviewed resource paths. New-order payload
has only exact DNS identifiers; resource reads are POST-as-GET with empty payload.
Preflight ES256/KID/nonce/URL/payload; no broad signing, JWK, new-account, polling,
retries, proxies, redirects, Link following, EAB or production fallback.
CA I/O is limited to twenty seconds and nineteen requests (directory plus up
to nine nonce/read pairs). The API operation has a 25-second context and only
this mutation response gets a 30-second write deadline; the server's default
15-second write timeout is unchanged. A writer that cannot enforce the scoped
deadline refuses before any mutation. The UI bounds headers/body to 30 seconds.

Strict UTF-8/unique-key/size-limited responses, exact identifier set, expiry,
one authorization per requested identity and one matching DNS challenge are
required. Wildcard authorizations must map back to the requested wildcard;
apex and wildcard can share a TXT name but have different values. Preserve both,
never overwrite another value. Challenge tokens must be canonical base64url with
at least 128 bits. Use the maintained library for the record digest. Foreign or
duplicate resources, aliases, changed identities and partial results refuse.
Provider errors/extension metadata and internal URLs never reach the browser.
Already-valid authorizations produce no invented TXT value. Instructions expire
at the earlier order/authorization deadline. Fixed Boulder resource path policy
is deliberately narrower than generic ACME; changed/unsupported responses refuse.

## Custody and UI

A purpose-separated typed sealed order entry binds installation/generation and
the registered account fingerprint. Every complete-image read authenticates it.
Order/challenge metadata, domains and TXT values are encrypted in full snapshots;
existing certificate/account keys and history are preserved. Old binaries refuse
new fields/actions; no downgrade. No anti-rollback or reliable heap erasure claim.
Repeat manual full backup after transitions. No certificate key is created yet.

UI: check saved order → enter names/confirm disclosure/password → get instructions
→ add all listed TXT values in own DNS panel → explicit local acknowledgement.
Show that acknowledgement is only the operator's statement, not a verified DNS
or issued certificate. No external operation/page-load request without consent;
no clipboard/storage/URL/log export of challenge data. Hidden/source/session
changes clear inputs and reject late results. Uncertain responses require status
refresh and same-order continuation. VM tests are not live visual browser QA.

Sources: [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html),
[DNS challenge guidance](https://letsencrypt.org/docs/challenge-types/),
[pinned client](https://pkg.go.dev/golang.org/x/crypto@v0.57.0/acme) and
[Boulder resource construction](https://github.com/letsencrypt/boulder/blob/main/wfe2/wfe.go).

## Development evidence and remaining release gates

Synthetic TLS CA verifies actual maintained-client ES256 JWS, KID, request
names and empty POST-as-GET; no public CA or DNS operation is run. Storage tests
cover encrypted intent/checkpoint/instructions, whole-image refusal, signer/
certificate preservation, reserved capacity and fresh restore/recovery. API
tests cover strict authority, shared limits, unsupported/native refusal,
revocation and acknowledgement without network. UI VM tests cover both TXT
values, explicit consent, blocked unlocated intent, expiry, malformed/late/
hidden/timeout refusal. These are not real browser visual QA or independent
audit. See C75 for named tests. Live staging interoperability, missing-URI
reconciliation, replacement/expired order policy, history capacity/retention,
issuance, renewal and production remain separate reviewed work.

The first Linux CI run exhausted Go's default ten-minute whole-package test
budget while a two-second existing API test was actively performing PBKDF2.
The growing race suite now has an explicit twenty-minute per-package budget
and a thirty-minute build-job cap. No test, assertion, production KDF iteration,
server/network deadline or required check is reduced or skipped. The new signed
head must pass the complete gate set; the timed-out run is not success evidence.
