# ADR 0080 — One complete test renewal in the original unlocked session

Date: 2026-10-29. Second stage of the authorised four-stage completion wave.

Add an explicit fresh-password grant for one complete Let's Encrypt staging
renewal, using an authenticated saved source and its exact domains/configuration.
The grant includes new order, required DNS TXT operations, CA verification,
independent new key/CSR, pinned receipt check, atomic pair save and owned cleanup.
Separate exclusive-DNS-editing acknowledgement is required. Existing pairs and
notes stay; no deployment, automatic source replacement or continuing renewal
loop is granted. Imported, superseded or unusable sources cannot start a new
cycle. Existing manual flows stay available without granting a background job.

One in-memory job stores only original session identity/revision/expiry, public
source/configuration scope, exact expected generation, counters and status.
Borrow live session key bytes only for one bounded step and clear them. The
original twelve-hour limit is never extended. Logout, lock, expiry, revision
change, daemon close/restart or unrelated storage/configuration change stops the
job. A browser page may close after an explicit grant; that does not create a
different session or permission. Timing watch and full renewal must not compete.

The same-image admission and each writer repeat source, lifecycle, credential,
capacity and current-permission checks. Reserve room for the full admitted
cycle, including closing an eligible old scope and future pending outcomes;
never start an order whose closure cannot fit. Do not automatically archive or
prune under renewal consent. Account/terms preparation remains an operator step.
Only fixed reviewed staging and Cloudflare connectors may execute. Arbitrary
URLs, roots, result verdicts or operator-supplied TXT scope are not accepted.

Scheduling respects saved ARI/lifetime selection and every longer provider wait.
Before automatic CA polling, capture bounded Retry-After metadata from the
existing CA operations and persist applicable waits under their writer boundary.
No hint is a trusted receipt or an instruction to retry a write. No provider
error can clear an older wait/block. Enforce fixed runtime spacing, bounded step/
poll counts and a monotonic session cap. Unknown/invalid results are visible and
cannot trigger an unbounded retry chain. Lost observations retain durable intent.

Every irreversible action keeps the existing intent-before-I/O and exact lease.
Unknown create/delete never replays; only scoped reads reconcile it. Bounded
ordinary read policy may proceed only under the new grant and saved wait. The
worker never invokes operator-only maintenance or silently restarts exhausted
policy. CA order/checkpoint/validation/finalize uncertainty follows the existing
same-order rules; an error needing operator action pauses instead of inventing
success, a replacement order/key or an absence verdict. Resume requires a fresh
grant and authenticated exact saved scope; restart/backup cannot recreate a job.

Confirm completion only after the new checked pair is saved and owned temporary
DNS cleanup is confirmed; borrowed records are untouched. A saved certificate
with unconfirmed cleanup is shown as saved with attention required. Stop is a
local cancellation without password/crypto-budget dependence and cannot undo
already sent bytes. The existing Automation card shows readable phase, next
time, pause reason and one next step; technical details remain optional. No new
top-level menu or false production/trust/deployment claim. Fake preview remains
read-only and cannot accept secrets or run a job.

Required evidence: complete policy/action sequence, refused/unknown/partial
paths, one-use intent/lease and no write replay; saved provider waits and full
recovery, actual Linux writer/API/cancellation; original session logout/expiry/
revision/restart bounds and no retained secret; source/configuration/generation/
capacity conflict refusal; pinned acceptance remains fixed; strict fresh scope,
origin/setup and bounded UI clearing/stale/hidden/late refusal; two-way compiling
sabotage, signatures, all final-head CI and separate maintainer self-review.
Layered synthetic tests do not prove live provider interoperability. Real tests
need the operator's dedicated domain/scoped token and terms decisions; isolated
production profile, release rehearsal and independent audit remain later gates.
No Porch changes.

Implementation checkpoint (not completion): bounded fixed-transport wait capture
is carried as transient `json:"-"` metadata on successful observations, or as a
fixed refusal error exposing only a typed wait. It preserves the existing refusal
identity through `errors.Is`; raw provider errors/headers never become records.
Successful result publication folds the wait into the same generation. Failed
callbacks can retain only a wait/event and the unchanged pending scope. Issuance's
model error redaction stays intact; its writer separately extracts bounded
transport metadata and returns the original fixed uncertainty error. If that
metadata cannot commit, report uncertainty. The future full worker must reserve
an error outcome and byte headroom before I/O; manual legacy admission does not
gain an unconditional extra-capacity guarantee. Current-clock, stale, longest/
sticky-block, dropped-lease, redaction and full-recovery tests cover this boundary.
The complete worker, its grant/UI and all final-head Linux/CI evidence remain
required before this ADR can be called implemented.

Worker/UI implementation checkpoint: `ReadRenewalCycle` projects only public
metadata from one fully authenticated image. The pure action policy composes
existing transactions, refuses unrelated interrupted timing work and requires
320 generation/event transitions plus 4 MiB of byte growth, a pair slot and
future closure(s). The conservative bound covers eight names, six ordinary DNS
attempts per phase, twelve ARI/validation/certificate read cycles, key/order/
ack/closure steps and a failed-call wait event. Actual writer reservations stay
in force. Only the job's committed generation delta and positive image growth
consume its runtime budget; freed bytes cannot mint new credit. No auto archive.

One memory worker borrows the original session key per step; expiry/revision/
logout/lock/restart, monotonic cap or unrelated generation/configuration changes
stop it. At most 160 actions, twelve reads per CA kind, at least one elapsed
minute per action and five after CA validation/certificate/timing operations.
Saved waits are additionally evaluated before every relevant call. Unknown DNS
creation/deletion uses ordinary reads, never recovery/maintenance. Failed CA
callbacks pause even if bounded wait metadata was saved. No new order on lost
Location; only exact known scope resumes after a fresh grant. The current
bound request may finish after its original source expires; no new cycle may
start from an expired/superseded original. A confirmed new pair may clean up
after source/order expiry or a CA hold, because that requires no new CA call.

The optional existing Automation card has strict local preview/status, fresh
password/exact-generation/`session-test-renewal` plus two confirmations for Start,
and owner-only Stop independent of crypto/provider budgets. Status includes no
provider URL/key/token/TXT. The renewal overview v2 distinguishes a job active
in this login; timing-only controls describe only their own narrower grant.
Source change, hidden/page exit, timeout and late/malformed/oversized responses
clear UI authority/password/consents. Fake preview has disabled inputs/start/
stop and returns 405 to mutations. Late stop/shutdown preserves completed status.

Layered Linux worker tests progress through real timing/order/DNS/ack/validation/
key/issuance transactions and deliberately hit the fixed checker's rejection
of a synthetic receipt. They assert one order, one Accept/finalize and no replay
after pause; separate policy/writer receipt tests cover saved-pair cleanup. No
runtime checker/root seam was added to obtain an artificial green end-to-end.
Actual Linux execution and all final-head checks remain pending at this point.

Local evidence, 2026-10-29: full native shuffled suite passed; subsequent
affected native suites, Linux cross-vet/staticcheck/gosec, build, module verify,
actionlint and vulnerability scan passed. New grant parser fuzz smoke completed
274078 executions. The real UI and read-only preview contract tests passed;
preview never accepts credentials or starts/stops a job. Deliberately allowing
an unknown-order replacement failed the positive sequence's expected pause;
inverting sufficient-headroom admission failed its legitimate order step.
Restored policy tests passed. Resume checks additionally refuse expired orders
even when unresolved DNS masks local close eligibility, and never provision a
new TXT record after CA validation has begun. Manual already-verified DNS can
continue without creating a new provider plan. These are admission improvements;
the existing writers retain their own expiry/no-replay checks.

Adversarial follow-up: a saved long CA hold must not mask an already lost
order or failed validation/issuance as merely waiting. Policy now reports those
fixed stop reasons immediately while preserving the hold; healthy same-order
reads still wait. `TestRenewalCycleLongCAWaitCannotHideAnAlreadyUncertainWrite`
and the complete policy suite pass. The first Linux renewal/CA-wait smoke passed
on `bec68d5`; the changed final head still needs every required check/full race.

Wait-boundary sabotage (2026-10-29): allowing a later success to clear a prior
blocked hint failed `TestCAOperationWaitBoundedStickyAndSecretFree` with
`invalid hint unblocked or shortened`; inverting exact-generation admission
failed `TestCAOperationWaitFoldsIntoExactResultAndKeepsLongerPolicy` on its valid
observation. Both restored targeted suites passed. Native shuffled tests and
Linux cross-vet/staticcheck/gosec passed for the initial wait integration; actual
Linux callback/full-recovery tests still require CI execution. Callback test
refusal assertions use `errors.Is` to preserve the fixed refusal identity while
also checking the bounded typed metadata and unchanged zero partial output.
