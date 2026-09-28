# ADR 0028 — Exact deletion from the current public inventory image

**Status:** accepted, 2026-09-28.

## Decision

The operator may explicitly remove one saved public certificate and all its
manual notes. The UI requires the displayed SHA-256 fingerprint to be typed
in full and a warning checkbox; the API requires the fingerprint twice, a
fixed confirmation phrase, a ready authenticated same-origin session, and
the displayed image generation. These are accident/stale-tab defenses, not
proof of user intent against a compromised browser. The storage layer opens
and authenticates the entire image before lookup, then commits a new complete
image with only that record removed under the existing writer lock. Remaining
records are not resealed or edited. Empty inventories remain valid. A later
explicit import of the same public certificate is allowed.

Deletion does not securely erase disk blocks, snapshots, browser memory, or
external copies. It does not revoke a certificate or undeploy it from any
server. Existing full snapshots can restore the record; a new full snapshot
is manual and captures its absence. Rootwell does not automatically delete
records at expiry or purge older backups. The operator controls backup
retention and should not interpret the UI success message as a global erase.

## Rejected alternatives

Silent expiry cleanup risks loss of operator records and would confuse a
browser-clock observation with retention policy. Cascading backup deletion
would damage recoverability and exceed this product boundary. Soft-delete
would retain the record in the active image while implying it is gone.
