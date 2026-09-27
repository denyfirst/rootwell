# ADR 0018 — Access-only snapshot and fresh restore on Linux

**Status:** accepted for internal core only; not a complete inventory backup.

## Decision

Before persistent records exist, prove the recoverability of the access
envelope itself without marketing it as a full disaster-recovery backup.
Export requires the current password and independently stored offline recovery
code, so both ways of obtaining the same data key are tested at creation.
Under the private source writer lock, the exact encrypted ready v3 access
file is copied into a bounded versioned snapshot. A random snapshot ID and
HMAC-SHA256 keyed by the 256-bit data key authenticate the entire header and
access bytes. The password, code, and plaintext key are never serialized.

The snapshot is written with exclusive creation in a separate owner-private
directory, mode 0600, file sync, directory sync, and exact readback. Existing
files are never replaced. A verifier may authenticate it with either the
password or recovery code. Restore validates the entire snapshot before any
destination write, requires a fresh otherwise empty private directory, then
creates and syncs only `access.json`. It cannot overwrite a live instance.
If a write may have happened before an error, the outcome is uncertain and
requires inspection rather than blind retry. A restore with only the code
does not silently change the old password; an explicit reset is needed.

The source can change after the export lock is released; the snapshot remains
a coherent historical copy, not necessarily the latest active state. An old
valid snapshot can be replayed on a fresh directory, and an old code can
unlock its historical key. No trusted monotonic counter is supplied by this
format. The snapshot includes no inventory records or vault secrets. Future
full backups need a separately versioned manifest binding access identity,
record set, generations, and restore policy, with end-to-end drills and
anti-rollback assumptions. The snapshot and code must be kept in separate
offline locations, and backup storage itself needs independent redundancy.

This Linux-only core is not exposed through CLI or browser; it does not claim
production recovery, network filesystem safety, or Windows ACL support.
It follows OWASP's guidance on separate key backup and restore planning in
the [Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
and Linux's [fsync(2)](https://man7.org/linux/man-pages/man2/fsync.2.html)
file/directory durability distinction.
