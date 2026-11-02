# ADR 0083 — Separate local production account key

Date: 2026-11-02. Local custody only; production registration/issuance remains
disabled. Independent release audit and live provider evidence remain pending.

The fixed production catalog/receipt trust in ADR0081 must not reuse a staging
account identity. Add one separately generated P-256 account key to the existing
whole authenticated encrypted image, without changing legacy staging ciphertext
or labels. This is the first production custody increment, not a production
CA connection, profile switch or migration of existing requests.

The new optional `production_acme_accounts` slot contains at most one encrypted
record. Its ID and standard HKDF key use the fixed production namespace and
installation binding, separately from the data key and staging account purpose.
Its strict canonical payload has only exact provider, local-key state, time and
PKCS#8 key. It cannot contain a registration, account URL or terms verdict.
Every image reader authenticates this slot, even when reading staging or public
records. Corruption in an unselected scope blocks the whole image. Empty legacy
images remain byte-compatible; old binaries refuse the new unknown field.

One shared root generation/history/image budget applies. Preparation advances
once and preserves all staging account/order/DNS/timing/wait state and reserved
completion capacity. No overwrite, removal, signer export, key adoption or
second quota counter. A later production registration payload/intent/lease and
all other environment scopes need their own reviewed increment before use.
Complete encrypted backup/restore and offline recovery carry both identities.

Linux custody uses the existing private-file writer lock, exact revision and
generation, fresh permission before publication and atomic replacement. Failures
return zero partial evidence. Other platforms refuse before invoking permission.
The authenticated local account-key API has two fixed routes for production
status/preparation, rejects staging JSON or unknown authority fields, and shares
the existing derivation/password-attempt budget, ready-session/same-origin/
fetch-metadata gates and fresh-password requirement. No connector is called.

The existing Automation account card gains one collapsed Advanced panel saying
local-only and not registered. It does not change the staging issuance provider
selector. Status must be read first; password and separate consent are wiped
before await and on collapse, hidden/page exit, timeout, stale status or errors.
Response size, JSON fields/capabilities/profile/generation/dates and late results
are checked. No application browser storage or secret logging. Demo inputs and
preparation remain disabled and mutations return 405.

Evidence is recorded below before merge. Required coverage includes independent
keys in both creation orders, no overwrite/stale admission, whole-image refusal
on wrong-purpose/corrupt/unselected records, pending staging reserve, malformed
payload fuzz, native refusals, actual Linux lock/atomic/recovery/API/no-network
tests, UI consent/clearing/late/refusal and read-only demo. Compiling sabotage in
both directions, complete native/race/platform/lint checks and signed final-head
PR review remain mandatory. No Porch files or configuration are changed.

Local evidence (2026-11-02): complete native shuffled suite passed after a
review-driven exact-route change removed an unnecessary `strings` import
refused by the existing account no-network architecture guard. The guard was
not broadened. Linux cross-vet/staticcheck/gosec, module tidy/checksums/build,
actionlint and reachable-vulnerability checks passed. Actual WASM history UI,
existing/new account UI and read-only demo tests passed; a browser review
confirmed disabled demo secrets/preparation and clear local-only text.

Payload fuzz passed 83,357 executions. Its first run found an empty-input
harness assumption: sealing empty plaintext correctly refuses with `ErrSize`;
the harness now asserts that refusal and retains the empty regression corpus.
No product parser was relaxed. Disabling unselected-slot validation compiled
and failed the corruption refusal test. Inverting legitimate account presence
compiled and failed the positive preparation test. Both source changes were
restored and the affected model/architecture suites passed. Final-head Linux
atomic/full-recovery/API/no-network smoke and full race remain CI merge gates.
