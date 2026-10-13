# ADR 0063 — Prepare a new request without losing prior custody

Date: 2026-10-13. Development, staging only. No real CA/DNS action or Porch change.

Explicit local close-request uses fresh password/consent/displayed generation
and writer revision/permission lock. Eligible only when complete (saved/deleted)
or a known authenticated deadline has expired. Unknown-URI creation and active
unexpired work refuse. Expiry is not proof the CA never issued a certificate;
closure is not CA cancellation/revocation or permission to replay the old order.

Archive the exact encrypted order/preparation/issuance scope under a separately
HKDF-separated AES-GCM closed-request field, then clear active scope atomically.
Keep every certificate, matched key, note, account and historical test-only origin.
Closed pending prepared keys remain encrypted for recovery, not accessible as a
new active lease. Archives have no network/lease/reopen/export/reset API. Maximum
32, bounded 64 KiB sealed payload each; no silent pruning. Full-image validation
checks every closed scope against its exact live material or deletion tombstone,
unique order URL/closure generation/time and independently derived eligibility.
Historical pending scopes waive only active completion-capacity reservations,
never binding/crypto checks. Deleting an archived pair updates its closed scope
in the same record deletion transaction; old backups still retain keys.

A later separate explicit start creates a new durable order intent. Reject a CA
URI reused from any closed scope before checkpoint/instructions. New key/CSR is
prepared later, never copied from history. Old complete-image restore/clock/host
rollback is not prevented. No claim that local closure erases data or cancels a
remote request. Public status exposes only availability/reason/count; fixed
history identifies the account, never encrypted blobs/private/CSR/provider URL.

V6 same-card UI: Prepare a new request → enter new domains → explicit Get DNS
records. Saved results still link to Certificates. Explain retained records,
closed/no-resume old request and possible unknown CA outcome; fresh consent for
each separate action. No automatic creation/polling/renewal. Native remains
read-only; real browser preview is fake and every mutation stays disabled.

Tests cover complete/expired closure and exact key/provenance preservation,
metadata/export/delete, repeated new cycles, unknown/active/stale/clock/limit/
tamper/reused-URI refusal, old lease image mismatch, whole-image no-partial output,
Linux atomic revision/permission/full restore, strict API/UI and two-way sabotage.
Pinned local gates, exact-head race/platform/signature/CI and separate maintainer
self-review precede merge. Production audit, live staging QA, history retention,
manual renewal and DNS adapters remain later work.

## Development evidence

Windows shuffled full Go suite, ten repeated complete/expired tests, module
tidy/verify, formatting, vet/build, staticcheck 0.7.0, actionlint 1.7.12 and
gosec 2.28.0 passed. Linux vet/gosec and Darwin vet passed, not local execution
of Linux custody. Govulncheck 1.6.0 found zero reachable/imported-package findings;
one module-only unused OpenPGP finding remains architecture-forbidden.
`FuzzClosedStagingRequest` ran 20 seconds/two workers: 16,286 executions, PASS;
it is added to scheduled fuzz inventory. V6 VM tests and read-only fake browser
completed-request form were verified; no real CA or production key used.

Actual compiling sabotage (then fully restored): allowing every known future
deadline to close failed `TestClosedExpiredRequestPreservesKeyButCannotReopenLease`
with “active uncertainty replaced”; refusing a legitimate completed request
failed `TestClosedCompletedRequestPreservesPairOriginNotesDeleteAndNewOrder`
with “valid completed closure refused”. Both real tests subsequently passed
ten repetitions. Malformed/tampered, 32-cycle capacity, no-partial, old lease/URI,
Linux writer/restore/password recovery and real fresh-auth HTTP fixtures are
included. Exact-head Linux race/platform/security/CI and separate recorded
adversarial maintainer self-review are merge gates, not an independent audit.

Residuals: archived pending keys have no export/cleanup UI; all archived scopes
are revalidated on each image read (bounded but cost grows); no anti-rollback,
cryptographic erasure, CA cancellation or unattended renewal is claimed.
