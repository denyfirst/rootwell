# ADR 0044 — Public comparison, encrypted history and session-bound monitoring

Status: implemented for development behind the signed PR/CI gate; not audited.

User authorized the four-part pre-ACME wave on 2026-10-06. This increment reuses
the current single-operator Linux inventory, atomic image replacement and full
snapshot. No Porch mutation, private custody, CA request, email or webhook.

Comparison explicitly requests one saved DER at an exact generation through
the ready-session same-origin/header gate, then compares a local candidate in
Go WASM. Candidate bytes do not enter HTTP. Strict single public certificates,
64 KiB each, exact fingerprints, DNS/IP/email/URI SAN sets, public-key identity,
subject/issuer and validity changes are displayed. It neither verifies trust
nor automatically replaces, saves, revokes or renews either certificate.
Hidden/changed/refreshed selections invalidate late work; UI errors are fixed.

History events are encrypted inside the authenticated complete inventory
image, atomically committed with the associated mutation, and included in
existing full snapshots. Events hold fixed action, server time, image generation
and public fingerprints only, not previous notes, passwords, keys or DER.
At most 1024 events; capacity refuses new mutations, never silently truncates.
Legacy images with no history remain readable; earlier activity is unknown.
Old binaries cannot read images containing new fields: do not downgrade after
new writes. Events are not independent audit or an external rollback anchor.
Deleted fingerprints remain in history and backups; deletion is not erasure.

Daemon monitoring checks the authenticated image once a minute using an existing
ready session's memory-held key. It never extends its 12-hour lifetime or writes
the image. Closing the page is independent of daemon scheduling; logout,
session expiry, changed access revision, restart, bad clock and unavailable
storage clear observations and expose a paused/unavailable status. No password
or new unattended unlock credential is stored. A 30-day local attention inbox
is RAM-only and is recomputed, not a durable external notification queue.
Session revocation during a read must discard late results. A compromised host
or same-user writer and a false server clock remain outside guarantees.

The final wave gate covers actual Go WASM comparison, codec history/refusal/
tampering/capacity, authenticated API boundaries, no-browser monitor tick,
revocation/expiry/clock/error, old-image compatibility, full restore, UI late
work and read-only synthetic preview. Linux race/platform/security/CodeQL and
signed PR gates remain mandatory. Independent audit precedes real-user release.

## Evidence and separate maintainer self-review

Actual Go WASM exercises same/different certificate, key/name/date changes,
strict private/bundle/malformed/oversize refusal and no candidate HTTP in
`scripts/test-inventory-lifecycle.mjs`. Source generations, whole history,
pagination, bad unlock deadlines and hidden/late work are tested. The page
refresh integration test prevents automatic refresh cancelling a comparison.

Codec tests authenticate events before returning records, reject tampering,
generation replay and capacity, and demonstrate legacy unknown history and
atomic import/edit/location/delete events. Linux integration checks the
authenticated source/activity routes, unchanged ciphertext after reads,
independently scheduled checks and history preserved by fresh full restore.
Monitor tests cover expiry, logout during read, clock reversal, storage error,
changed/unreadable access revision and repair without silently restoring keys.

Deliberate mutations were restored after each expected test failure: rejecting
valid same-key comparison / accepting empty candidates; refusing valid history
events / accepting over-capacity history; refusing an unlocked session /
publishing a result after logout. These are maintainer tests, not independent
audit. The final diff was separately reviewed for route authority, exact
snapshot identity, lock ordering, session lifetime, buffer cleanup, whole-image
history authentication, no-write reads, backup compatibility and UI boundaries.

The UI mutation gate also detected refusing a valid source, accepting an
expired monitor unlock deadline, and removing the comparison refresh pause;
each mutation was immediately restored and the tests passed afterward.

Windows browser evidence uses actual WASM with a synthetic read-only API;
history is a fixture and the monitor correctly reports not-running. There is
no local Docker/WSL runtime. Actual Linux durability/background/restore and
race execution run in CI, not falsely presented as a local Linux browser test.

Residuals before release: no uninterrupted 24/7 unlock; no history archive/
clear policy at the 1024-event capacity; no downgrade after new writes;
no independent audit, rollback anchor, tamper-evident external log, hostname/
chain/revocation validation or protection from a compromised host/browser.
