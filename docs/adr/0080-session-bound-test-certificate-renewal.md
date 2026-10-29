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

Wait-boundary sabotage (2026-10-29): allowing a later success to clear a prior
blocked hint failed `TestCAOperationWaitBoundedStickyAndSecretFree` with
`invalid hint unblocked or shortened`; inverting exact-generation admission
failed `TestCAOperationWaitFoldsIntoExactResultAndKeepsLongerPolicy` on its valid
observation. Both restored targeted suites passed. Native shuffled tests and
Linux cross-vet/staticcheck/gosec passed for the initial wait integration; actual
Linux callback/full-recovery tests still require CI execution. Callback test
refusal assertions use `errors.Is` to preserve the fixed refusal identity while
also checking the bounded typed metadata and unchanged zero partial output.
