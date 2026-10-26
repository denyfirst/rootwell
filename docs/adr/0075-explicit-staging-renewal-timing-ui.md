# ADR 0075 — Explicit staging timing UI and all-CA wait barrier

Date: 2026-10-26. Three connected development steps; no scheduler, production
enrollment, real CA/DNS test or Porch change.

## Decision

1. Every enrolled-store CA path consults the authenticated account-wide wait
   under the private Linux writer lock before intent or I/O: directory, terms,
   registration/reconciliation, order/renewal/resume, validation and certificate
   issue/read reconciliation. Local status, interruption retirement and DNS
   ownership cleanup remain available. The permit repeats live access and actual
   clock checks after potentially slow permission calls. Complete restore keeps
   the policy. An unenrolled access envelope cannot contain encrypted policy;
   its existing explicit directory-only check remains unchanged.
2. Connect ADR0073's fixed staging ARI protocol to ADR0074's exact-source
   intent/one-use lease/result transaction. The protocol rederives the public ID
   and produces only a source-bound observation or fixed typed failure. There is
   no caller URL, certificate upload, signer, DNS credential or window override.
   Ready Linux session, enrolled storage, exact generation/revision, fresh
   password, explicit one-check disclosure consent and shared crypto/auth/provider
   budgets are mandatory. POST status/check/interrupt accept exact bounded JSON;
   status is local, interrupt is local and preserves all waits/counters.
3. Add a compact inline result to the existing renewal overview, not another
   menu/settings page. Select a saved staging certificate, read its local status,
   then optionally consent to one check. Show suggested renewal time, wait/pause
   reason and one available next action; technical details stay collapsed.
   Certificates selection works before the order widget clears its public
   marker. Imported certificates remain manual. No page-load provider call,
   polling, automatic renewal, password retention or extra unlock lifetime.

## Failure and privacy boundaries

Persisted ARI failure hints govern all subsequent CA operations. This does NOT
add durable Retry-After persistence for every legacy non-ARI CA error; those
paths retain their prior uncertainty/reconciliation semantics. A wait is not
permission to replay a write. Cloudflare's independent DNS policy is unchanged.
Blocked hints remain maintenance-blocked; no reset or old-backup bypass UI.

Request body is at most 2 KiB, read deadline five seconds, API context 25 seconds
and scoped response deadline 30 seconds; unsupported writers refuse. Protocol
still has its eight-second budget. Only nine envelope and 22 public status fields
leave the daemon. No raw CA error, private key, password, token, account/order
URL or explanation URL. Browser refuses malformed/oversized (>16 KiB), hidden,
stale (>60s), late (25s), clock-skewed and changed-source results; it clears
password/consent and invalidates other mutation widgets on a committed result.
The CA can see the server IP and public certificate ID; local resolver can see
the fixed CA hostname. Cancellation cannot recall already-sent bytes. Uncertain
results require status refresh and explicit local retirement, never silent retry.

## Evidence

`TestLinuxProviderWaitCoversEveryCAPathBeforeIntentAndSurvivesRestore` exercises
the real common barrier, zero callbacks/writes and recovery. API Linux tests
exercise fresh auth, exact source, durable intent before callback, held lock,
local-only read/retirement, persisted wait blocking directory and malformed
receipt uncertainty. Native/strict parser/fake-TLS/architecture/UI tests cover
refusal and legitimate operation. `FuzzRenewalTimingRequest` is in scheduled
inventory. The read-only browser fixture contains explicitly fake dates/status;
password/consent and mutations stay disabled. No real secrets or CA connection.

Actual compiling two-way sabotage: removing the true-consent requirement failed
`TestRenewalTimingRequestStrictShapesAndNoPartialSecret` on unsafe input; inverting
the fixed provider match failed its legitimate status request. Both were restored.
All final-head CI checks and separate maintainer adversarial
self-review remain mandatory, not independent audit. Linux execution is a CI
gate, not inferred from Windows cross-vet. Full automation, session-only worker,
pause/failure flow, live operator-authorized interoperability and independently
audited production release remain further work. No anti-rollback, guaranteed
heap erasure, host-compromise resistance or current trust/revocation/deploy claim.
