# ADR 0068 — Durable order-bound DNS planning and retry intent

Date: 2026-10-14. Single-operator Linux/loopback development only.

## Decision and current boundary

After PR #98, the next increment binds future DNS work to the actual saved CA
request and the exact encrypted Cloudflare configuration. This is INTERNAL
custody, not a DNS operation UI or completed automation. No live Cloudflare,
CA call, token borrower, production release, scheduler or Porch change.

The pure store and private Linux writer can prepare one plan, record an attempt
before future I/O, and save a bounded provider wait. Architecture tests prevent
the runtime/UI/CLI from calling these new operations before a separately
reviewed connector transaction and fresh-auth/consent route. Current manual
DNS/issuance remains available; no new provisioning button is advertised.

## Source, encryption and recovery

No user-supplied DNS values, record types, provider IDs or ownership evidence.
Only the saved unexpired dns-ready/dns-acknowledged order provides pending TXT
rows. Registered account identity, exact order URL, canonical name/value,
selected zone/configuration generation and preparation chronology bind the
plan. At most eight required rows, all within the one selected zone. Already
CA-valid rows are skipped. Same TXT name with different wildcard/apex values
remains two entries; duplicate name/value tuples refuse rather than silently
guessing shared ownership. Sorted unique domains and distinct nonzero 128-bit
cryptographically random owner markers authenticate per-row identity.

A new `dns_plans` field is HKDF-purpose-separated and AES-GCM sealed with the
existing installation/record/generation context. Full manifest authentication
and every payload/source/configuration binding validate before ANY public output.
Malformed/duplicate/orphan/wrong-purpose/changed-context/unsupported-state,
missing required row, changed active token configuration and stale generation
refuse. Token bytes are only cleared after validating configuration metadata;
they never enter this plan or an exported borrower. Public planning status
contains domain/name, local state, counts/wait/blocking, preparation/expiry only;
no TXT value, marker, provider ID, token/digest, signer or internal URL. History
uses only existing public account identity and fixed planning/intent/wait labels.

Actual complete password/recovery-code snapshots and offline password recovery
retain the exact encrypted owner/order/configuration/attempt bytes. Old binaries
refuse the new field. Old complete-image rollback and host/runtime copies remain
outside this guarantee. Historical scope never gains a new lease or first attempt.

## Attempt and uncertainty

Before any future transmission, Begin saves creating and consumes the bounded
retry count, even if a crash happens before transmission. The process-local
opaque handle binds the exact complete image hash, generation, row and direction.
Reopened/restored creating scopes can mint read-only handles only; there is no
reset. First-write permission is NOT currently connected to any network code.

At most six attempts per row, exponential 30–960 second minimums with uniform
crypto/rand 0–30 second jitter. Early/backwards/expired/invalid clocks, blocked
policy and exhausted budget refuse without mutation or partial result. The
effective deadline is the smaller frozen/current CA expiry; it never extends.
Defer consumes the exact handle once (copies share atomic state) and preserves
longer Retry-After waits. Malformed/overlong hints save a blocked flag while
retaining the previous intent/count/wait, never resetting to a new request.
No raw provider error/URL/header/body is saved or reflected. A failed validation
also consumes the handle. Defer is only a local wait transition, not an assertion
that a record exists, was borrowed, was deleted, or that DNS/CA is verified.

Linux exact-revision private writer locks cover read/prepare/intent/wait commits.
Permission repeats before replacement and publication. Disk-full/pre-rename
failure retains the old image; post-rename sync or post-commit permission loss
returns uncertainty and no usable handle/public result. Refresh/authenticate
again to reconcile saved state. Native Windows/macOS refuse before filesystem
or permission borrowing. These internal methods do NOT themselves authenticate
an HTTP user: that remains a mandatory future fresh-password/consent route gate.

## Closure and capacity

A creating row cannot silently disappear on expiry or local closure. New-request
status reports dns-cleanup-needed; existing V8 UI accepts only that scoped new
refusal reason, explains the uncertainty and blocks replacement of completed/
expired requests while keeping saved certificates accessible. Active manual
issuance is not treated as a new DNS ownership verdict.

For each uncertain row, reserve THREE minimum future transitions (reconciled
result, cleanup intent and cleanup result), plus the independent pending CA/
issuance reservation. Nonce/history reservations and byte headroom are additive,
not overlapping: DNS keeps 64 KiB in addition to any 1 MiB issuance reserve.
Begin requires two further slots for its intent and wait observation. Ordinary
certificate/note operations cannot consume these reserved slots. This is a
minimum boundary, NOT a implemented cleanup retry transaction or a guarantee
that provider/network/capacity failures can always be resolved automatically.

Only an unattempted plan can be archived with a completed/known-expired request
in this increment. Its exact nested ciphertext and pre-closure generation are
validated. It survives later token rotation/removal without active authority;
closed scopes cannot be reopened. Creating cannot archive even with a valid
outer MAC. Borrowed/created/deleting/deleted states and cleanup result acceptance
are intentionally not yet introduced, so fabricated ownership cannot be saved.

## Evidence

Positive cases: real synthetic saved CA/account/config source, distinct same-name
values/markers, encrypted public status/history, persisted longer waits, bounded
counts and no replay after reopen, harmless archive/rotation, private material
preservation, additive issuance/cleanup reserves, and already-valid row skipping.
Refusal: stale/foreign row, wrong zone/order/account/config/purpose/installation,
tampered ciphertext, missing/duplicate/reordered/changed records, invalid clocks,
exhausted/blocked policy, copied/empty/changed-image lease and expiry closure.
Linux tests cover writer contention/revision/permission/0600, pre/post-rename
faults and post-commit revocation, both full-snapshot unlock paths plus offline
password recovery with exact encrypted-image equality and no early retry.

Actual compiling two-way sabotage, restored and passing:

- Removing exact CA TXT value binding failed malformed/no-partial-output.
- Reversing that equality refused the legitimate source and failed success.
- Removing one-use consumption failed copied-handle refusal.
- Reversing consumption refused the legitimate provider-wait save.

FuzzDNSPlanPayload embeds fuzzed records/retry in a genuine generated immutable
source/configuration-bound fixture; malformed raw payloads are also sealed and
rejected. Three-second/two-worker sample: 287 executions, not exhaustive proof.
Existing fixture helpers now take testing.TB so fuzzing can reuse one generated
immutable context rather than spend each iteration preparing an account/order.
Actual rebuilt public Go WASM lifecycle tests cover the new history labels;
ACME UI VM tests cover the explicit no-replacement uncertainty notice. They are
not browser visual QA or live provider interoperability.

Full shuffled native Go suite, module/format/vet/build, pinned static/security/
vulnerability checks, platform vet and exact-head Linux/race/full-recovery CI
remain merge gates. Separate adversarial maintainer self-review is required;
green CI and self-review are not an independent production audit.

## Next required integration and residuals

Next: one writer-lock-spanning token/lease/Cloudflare transaction, repeat exact
intent/expiry/permission checks, verified record result and cleanup ownership
states, uncertain create/delete reconciliation, sufficient complete cleanup retry
capacity and explicit fresh-auth UI. Exhausted/blocked pending scopes need an
explicitly reviewed recovery policy; do not invent a reset or abandonment button.
Do not enable the network with only these separate local writer calls.

ADR 0066's provider permission/GET-to-DELETE concurrent-edit and narrow response
profile residuals remain. Provider waits must commit before subsequent authority;
lost/uncertain commits require same-scope reconciliation, not assumed success.
Future cleanup may need manual operator/provider action. No atomic provider CAS,
DNS propagation, current certificate trust, revocation, deployment, always-on
renewal, unattended unlock or anti-rollback claim. Audit and live interoperability
checks remain required before production-user secrets or release.
