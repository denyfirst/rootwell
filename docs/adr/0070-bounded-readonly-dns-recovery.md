# ADR 0070 — Explicit bounded read-only DNS recovery

Date: 2026-10-26. Development, Linux, single operator. Porch excluded.

After the ordinary six checks are exhausted, offer a separately confirmed
read-only recovery policy, not a reset of those attempts. Each phase has at
most six additional persisted checks, with independent backoff/Retry-After,
intent before credential borrowing, the same exact-image one-use lease and
writer lock. Never POST/DELETE, including after restart, full restore or expiry.
Only exact owned creation or protocol-confirmed deletion can advance state.
An empty creation listing remains uncertain; a present deletion remains pending.
Foreign or ambiguous records never become owned or cleaned. No user verdict,
record ID, token or scope may enter the API.

Reserve every remaining recovery intent/outcome in addition to normal cleanup,
issuance and permanent unresolved slots. Admission may refuse at capacity;
already valid older images retain their original reservations and readability.
Recovery adds optional encrypted fields; older binaries reject them rather than
misinterpret authority. All counters/waits survive full backup/password recovery.
No history pruning, abandonment, retry reset or unlimited repair claim.

A blocked phase (invalid/unbounded provider hint), blocked recovery, exhausted
recovery, insufficient capacity or indefinitely unknown creation still fails
closed. These require further reviewed maintenance, not an unsafe escape hatch.
The UI explains manual provider inspection and keeps separate CA verification.
This increment is the exhausted-check recovery part of the larger operator
recovery/history-capacity milestone, not completion of that entire milestone.

Acceptance: positive creation/deletion reconciliation, unchanged counters,
durable waits, exhausted/blocked/stale/malformed/revoked refusal, capacity,
Linux writer/full restore/API, UI hidden/late/source checks, two-way sabotage,
browser synthetic demo, pinned gates, signed PR/all CI and separate maintainer
self-review. No real DNS/CA/customer secret, scheduler or production release.

## Local evidence

Actual compiling two-way sabotage: removing the read-only checkpoint refusal
failed both creation and cleanup recovery tests (`recovery authorized mutation`).
Reversing ordinary-exhaustion admission failed both legitimate recovery paths.
Both guards restored; the targeted recovery suite passes. Shuffled native suite,
native/Linux vet/staticcheck, Linux gosec, module/format/build, actionlint and
govulncheck pass (zero reachable/imported-package findings; inherited unused
module-only residual). UI VM/history/demo tests pass. Actual Linux writer,
full recovery and race execution remain the exact-head CI gate, not cross-vet.
