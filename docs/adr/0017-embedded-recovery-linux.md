# ADR 0017 — Embedded offline recovery authority on Linux

**Status:** accepted for internal core only; no CLI/browser ceremony.

## Decision

Recovery enrollment must not leave an access envelope and a separate recovery
wrap in a crash-inconsistent pair. A ready v2 access file can be replaced by a
v3 envelope that contains its password-wrapped data key, the offline
recovery-code wrap, the authenticated installation ID, and a keyed confirmation
of the data key and recovery wrap. The password AEAD authenticates all of these
fields. Both the password path and code path must agree on the same 256-bit
data key. The recovery code is 256 random bits, not a memorized password.

Linux enrollment, rotation, and password reset use the private advisory writer
lock and the existing file-sync, same-directory rename, directory-sync,
readback sequence. Enrollment and rotation require the current password;
reset requires a valid code and a policy-compliant new password. Reset changes
neither the data key nor installation ID, and issues a fresh code. The code is
returned only after a verified durable replacement. If the post-rename result
is uncertain, no code is returned and the operator must inspect current state
before any retry. A password-authorized rotation can repair a committed wrap
whose newly generated code was lost during an uncertain result.

The active access file rejects an old code after rotation/reset. Older copied
access files and backups cannot be remotely revoked; anyone possessing an old
backup and its corresponding code can recover the historical data key offline.
This is inherent in offline recovery and must be explained during enrollment.
The wrap belongs in protected instance data; the code belongs in a separate
offline location. A compromised running process or same-user filesystem writer
is outside this at-rest claim.

No production command, browser endpoint, automatic migration, backup export,
record store, or Windows writer is enabled by this ADR. An operator ceremony
must stop the daemon, securely collect credentials without argv/logs, display
the code exactly once, and conduct a fresh restore drill before durable records
are allowed. Linux local filesystems are the reviewed target; network mounts
are not detected or approved. This design follows the separation of offline
saved recovery codes described in [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html)
and the file-plus-directory sync durability distinction documented in
[fsync(2)](https://man7.org/linux/man-pages/man2/fsync.2.html).
