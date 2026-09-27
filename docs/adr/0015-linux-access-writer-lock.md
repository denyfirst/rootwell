# ADR 0015 — Linux access-envelope writer lock first

**Status:** accepted for the development gateway, not a persistent-inventory
or production-host security claim.

## Context

Identity-upgrade preparation produces an encrypted candidate but does not
install it. A source revision hash is not an atomic compare-and-swap. Existing
password changes also need serialization before an installer can share the
access file. The first intended self-hosted storage target is a private local
Linux/Docker volume. Native Windows support remains a separate gate: Go's
[`os.Rename` documentation](https://pkg.go.dev/os#Rename) does not promise
atomic rename on non-Unix systems, and file mode `0600` does not establish a
private Windows DACL. Microsoft's
[`LockFileEx`](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex)
and [file security](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights)
APIs need their own implementation and tests.

## Decision

On Linux, password changes take a nonblocking exclusive advisory lock on a
stable, persistent file in the private installation directory. The directory
must be owned by the process user with no group/world permissions; the lock
must be a same-inode regular file owned by that user with no group/world
permissions. A competing writer receives a distinct busy error and does not
modify access. The lock file is **not** removed on release, avoiding a split
lock across old and newly created inodes. After replacing the access file,
the writer syncs the directory; a sync failure is reported as an uncertain
outcome, never as proof that the old password still works.

Linux [`flock`](https://man7.org/linux/man-pages/man2/flock.2.html) is advisory:
it serializes cooperating Rootwell writers, not arbitrary same-user processes
or an attacker controlling the host. Network/distributed filesystems are not
approved for this protocol without separate verification. This change does
not install an identity-upgrade candidate or enable persistent inventory.

Non-Linux password changes retain their development behavior so existing
Workbench access is not broken. They are not considered safe for durable
inventory or identity installation. A later installer must fail closed on
unsupported platforms and recheck the source revision while holding this
lock, validate the candidate, sync and verify the result.
