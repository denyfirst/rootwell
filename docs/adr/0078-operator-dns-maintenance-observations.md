# ADR 0078 — Explicit operator-only DNS maintenance observations

Date: 2026-10-29. Part of the user's four-stage completion request.

An ordinary or recovery policy's terminal block remains terminal. Add a separate
manual observation authority: fresh password, exact generation/record, archive-
safe persisted counter, explicit `operator-dns-read-only` scope and reviewed-error
acknowledgement. This is never granted to a scheduler or inferred from prior
consent. It uses the existing pinned Cloudflare read-only connector/one-use lease
and private writer, committing intent before I/O. It cannot POST or DELETE.

Only terminal unknown create/delete phases qualify. Preserve all original
attempts, block flags, ownership and known waits. First observation waits at least
one day from the last policy attempt; a blocked/uninterpretable hint requires
seven days and explicit operator review. Every later manual grant waits at least
one day; malformed/unbounded hints again impose seven days. Longer retained
finite waits win. This manual exception does not reinterpret an unknown hint as
a safe retry time or promise that the provider has lifted a restriction; the
operator must review it. Automatic policies remain blocked. Counter max 65535,
global generation/history/byte caps, time validity and normal reservations remain.
Each grant is one bounded observation, never a continuing retry policy.

Only the connector's exact owned-record or confirmed deletion result resolves a
phase. Empty creation remains unknown, no operator-supplied verdict/record ID or
scope is accepted. Persist a maintenance receipt while retaining original flags;
only its validated resolution permits the normal next phase. Cancellation or
lost publication retains intent/count/wait. Full backups and recovery retain all
of it. No reset, abandonment, new order, credential replacement or production
release authority is introduced here.

Evidence: model tests cover both phases, terminal-policy preservation, exact
scope/read-only checkpoint, one-use lease, stale/revoked grant, lost intent,
unknown empty create, future wait, malformed receipt, capacity and counter cap.
Both recovered phases can close an expired request without erasing their old
terminal policies or either resolution receipt. Malformed UI maintenance state,
invented completion and response counter/wait resets are explicitly refused.
Native custody refuses before callbacks. UI tests require independent review
consent, immutable old counters/waits, a single scoped request, secret clearing,
and refuse stale/hidden/late/malformed output. The read-only demo cannot submit
credentials or invoke maintenance. Linux tests exercise durable intent under the
writer, zeroed borrowed token, full snapshot/recovery and the fresh-auth API;
their execution is a required Linux CI gate, not a native cross-vet claim.

Two-way compiling sabotage, 2026-10-29: removing the read-only checkpoint guard
made both creation/deletion tests fail with `maintenance checkpoint authorised
mutation`; inverting terminal admission made both fail with `terminal maintenance
guidance absent`. Restoring both guards passed all `TestDNSMaintenance` tests.
A ticking-clock positive test also checks that a confirmed observation receipt
survives a later publication timestamp without extending any grant.

The full authorised wave remains: (1) terminal DNS/capacity recovery, (2) separately
consented session-only full renewal, (3) isolated production profile and real
provider tests using operator-owned test domain/token, (4) install/upgrade/restore/
UI release rehearsal and independent release audit. Missing real credentials or
audit do not turn synthetic tests into real proof. No Porch changes.
