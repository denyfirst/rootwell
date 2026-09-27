# ADR 0016 — Explicit legacy identity installation on Linux only

**Status:** accepted for the internal core, not an operator-facing migration.

## Decision

The v1-to-v2 candidate from `PrepareIdentityUpgrade` may be committed only
under ADR 0015's Linux private-directory advisory lock. Before any write, the
installer compares the exact source revision, authenticates the ready v1 file
with the current password, authenticates the v2 candidate with that password,
and confirms identical data keys and the candidate's authenticated new ID.
Invalid, stale, setup, and already-upgraded states fail without replacement.

The existing same-directory temporary-file writer syncs the candidate file
before Linux rename. The installer then syncs the directory and reads back the
exact installed bytes. A sync/readback error after rename is **uncertain**:
the caller must inspect the current file, not repeat the migration blindly.
The old and new envelopes use the same password and data key, so a crash that
leaves either valid version does not by itself lose the key. Orphan encrypted
temporary files may remain after a crash and require a separately reviewed
cleanup policy. This core does not create a recovery wrap, backup, restore
command, or inventory record.

Non-Linux platforms refuse installation. Linux network/distributed filesystems
are not approved; advisory locking and filesystem durability vary there. The
operator-facing ceremony remains gated on a tested local-filesystem policy,
session coordination, backup/recovery enrollment, and release audit. No
production data directory is migrated automatically.
