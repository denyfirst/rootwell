# ADR 0074 — Source-bound durable staging renewal timing

Date: 2026-10-26. Internal development custody, not a scheduler or live ARI UI.
Porch, real customer secrets and actual CA/DNS operations remain excluded.

## Decision and boundary

Persist timing for one exact, authenticated Rootwell staging completion, not an
uploaded/imported certificate or a caller-supplied URL/window. Whole-image
authentication rederives the public certificate ID and test-only origin, matches
the retained private pair and checks source/generation/time before any output.
Use separate HKDF purposes and existing AES-GCM installation/record/generation
contexts for optional `renewal_timings` and one `staging_provider_wait` field.
Absent fields preserve existing images. Earlier binaries reject the new fields;
they must not silently discard timing or provider policy.

One randomized lifetime fallback is saved once. A valid new ARI window chooses
once; the same window never rerolls. Later changed windows cannot postpone an
existing ARI choice; an earlier one can advance it. Stale/unsupported/error ARI
cannot hide an earlier saved fallback. Effective timing is still subordinate to
the provider barrier. Source expiry or a completed successor stops read authority;
retained old pairs are not silently removed or scheduled again.

## Intent, wait and interruption

The Linux private writer lock spans exact access revision/generation checks,
atomic intent, a one-use exact-image lease, a bounded trusted callback and atomic
outcome. The callback receives only detached public DER plus a repeated live
permit; no signer, private key, token, provider ID, internal URL or trust override.
The borrowed slice is cleared, not a claim of reliable heap erasure. Lease copies
share one atomic consumption flag; expiry is twenty seconds and clock rollback
refuses. Revoked/late/wrong-source/partial-error results cannot publish output.
An uncertain committed write retains the normal inspect/refresh requirement.

Before I/O, persist pending/count (saturating at six) and conservative six-hour
read wait. A confirmed error uses the existing bounded 1/2/4/8/16-minute policy
for temporary failures, then six hours; other failures wait six hours. There is
no automatic retry loop or terminal read-attempt limit in this model. Pending
intent cannot run again until explicitly retired; retirement preserves its
choice/count/wait and only releases its outcome reservation. It does not cancel
or revoke a CA order or abandon DNS ownership. Unsupported advertisement keeps
fallback and waits twenty-four hours; a success preserves the bounded check time.

Provider wait is separately account-bound and never shortened; malformed or
over-seven-day hints block pending future reads. It survives deletion of the
source certificate/timing entry and full recovery, so selecting another source
cannot erase it. Deletion removes only that source's timing record. Global timing
policy is not copied into archived request scopes as historical authority.

Reserve an outcome generation/history slot and 8 KiB outer-image growth per
pending read, additive to DNS cleanup and issuance reserves. Ordinary note/import/
closure writes cannot consume these reservations. Existing bounded history,
archive, record and image limits still refuse; no pruning/reset or anti-rollback
guarantee. Complete old-image restoration and host-clock/host compromise remain
outside this protection.

## Deliberately not enabled

Architecture permits only the model and Linux lock wrapper consumers. Native
platforms refuse before files/permission/callback. No protocol export/adapter,
HTTP route, job/worker, browser polling, new operation form, independent unlock
credential or production CA capability. Existing activity UI merely recognizes
four fixed timing events and explicitly says that no certificate was renewed.

Before any live route is enabled, the next review MUST enforce the persisted
provider-wide barrier on **every** CA operation (not only ARI), bind the fixed
protocol receipt to saved DER, add fresh auth/privacy consent/shared budgets and
repeat ready-session/revision/expiry at publication. The eventual opt-in worker
must stop at logout/lock/restart and never extend the existing twelve-hour unlock.
No `replaces`/renewal-exemption or deployed/production-ready claim is made.

## Evidence

Model success, source refusal, stable choices, earlier/later/stale windows,
unsupported result, expiry/supersession, ordinary import, wrong context/key/image/
generation, semantic sealed tamper, provider maximum/fractional wait/block and
deletion, additive DNS/issuance capacity, copied concurrent handles, late/revoked/
partial results and fixed output are tested. Linux tests check intent on disk
inside the callback, held lock, 0600 output, unsafe-file refusal, post-commit
revocation, pending/confirmed snapshots with password and recovery-code restore
and subsequent password recovery. Linux execution/race is a required CI gate;
native tests and cross-vet alone do not establish it.

Actual compiling two-way sabotage: removing the certificate-ID receipt check
failed the wrong-ID refusal; inverting current-source expiry acceptance failed
the legitimate intent. Restored three shuffled repetitions pass. New payload
fuzz target is scheduled; 153626 executions in a 15-second smoke pass. The first
smoke found an empty-input harness assumption (Seal intentionally refuses empty
plaintext); the harness now asserts that refusal and retains the empty corpus.
No production guard was relaxed. Final gates belong to the PR evidence.
These are development tests and maintainer self-review, not an independent audit
or real CA/DNS interoperability test. No new visible UI flow is claimed here.
