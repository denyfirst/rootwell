# ADR 0077 — Explicit lossless encrypted history archives

Date: 2026-10-28. Linux single-operator development. Porch excluded.

Keep the existing 1024 active-event limit and allow an explicit, authenticated
repack of a 512–1024-event active log into one of four retained history pages.
Move each existing event ciphertext and installation/generation context unchanged.
The authenticated manifest covers page order and the original history-start
boundary. Open all pages and active events before any record/history/status output.
Check continuity across every page through the current generation; damaged,
reordered, replayed, oversized or shifted-start pages return no partial output.

This frees active event slots, not disk bytes. Retain all old events, including
deleted certificate identities. At most 4096 archived plus 1024 active events.
Generation and 96 MiB image limits are unchanged, never recycled. Exhausted page,
byte, nonce or reserved headroom refuses the whole write. No automatic eviction.
All certificate/key/note/account/order/closed-request/DNS/timing/wait ciphertext
stays unchanged, including pending ownership, blocked state and retry counters.
Existing completion/outcome reservations still apply. A new generation and
`history-archived` event record the action; old leases/stale tabs cannot adopt it.
An unrelated generation change pauses a timing watch under ADR 0076.

The private Linux writer checks exact revision, expected generation and live
permission before atomic replace, rechecks afterward and returns no partial
success on uncertainty. Separate scope, fresh password, backup acknowledgement,
ready session, origin/fetch/header and shared auth/crypto budget apply. Status is
read-only. API body 2 KiB, response 4 KiB, 25-second context, read/write deadlines.
UI validates exact UTF-8/schema/count/time, clears passwords/consent before
awaiting, and refuses hidden/stale/late/uncertain results. Lost response requires
status, never blind replay; exact generation also refuses duplicate writes.

Use Certificates → Change history → History storage, linked from Automation's
optional headroom details. Require acknowledgement of a current complete backup
and compatible binary. Old binaries reject the optional archive manifest fields.
Make another complete backup after archiving. Full snapshot/password recovery
retain all pages; no separate archive file, password or key is introduced.
The existing history viewer reads all retained events, renders 50 at a time,
and is bounded to 5120 events/40 MiB streamed response (including worst-case
64-fingerprint imports). Activity reads share the derivation slot and recheck
the session before output. Read amplification is bounded, not a scalable audit DB.

Evidence: full active capacity → lossless archive → next successful write,
unchanged ciphertext/history, original-start/gap/replay/corruption/identity/clock/
limit refusal, unchanged pending DNS/timing, and pagination beyond 1024 events.
Actual compiling two-way sabotage removed the original-start guard and failed
the missing-prefix refusal; inversion refused legitimate full-log archiving.
Both were restored and targeted model tests passed. Linux writer/API/private-
permission/full restore, native refusal, request fuzz, malformed/hidden/late/lost
UI and read-only browser examples are additional gates. Native/cross-vet are not
Linux execution; all final-head CI and a separate self-review precede merge.

This is the history-capacity part of maintenance. Terminal unknown/blocked/
exhausted DNS and closed-request-archive capacity remain open. There is no reset,
replay, abandonment, new network authority or full automatic renewal. Empty
creation listing is not cancellation. Real provider/production/deployment/audit
remain separate. Old valid image rollback, trusted host/operator compromise,
clock rollback and guaranteed heap erasure are not solved. Retained encrypted
local history is not independent audit evidence.
