# ADR 0021: Linux private inventory file and complete snapshot

The first durable public inventory implementation is Linux-only. The data
directory must be owned by the current user with no group/other permissions.
The inventory image is a complete authenticated file; imports validate it,
write a new `0600` temp file, sync it, atomically rename, sync the parent,
then read it back. A stable advisory writer lock serializes cooperating
changes. The daemon's operation lock excludes offline backup/restore while
serving. Native Windows ACLs and container-volume semantics need separate
validation; we do not interpret Windows mode bits as a security guarantee.

Activation is explicit and requires a ready v3 access envelope, its current
password, and its recovery code. It writes an authenticated complete snapshot
of the empty inventory to a new file in a separate private directory before
creating the durable inventory file. Export of later generations must be
repeated after imports; backup is not automatic. A full snapshot binds exact
encrypted access bytes to the exact encrypted inventory image under the data
key. Verification uses either password or recovery code. Restore refuses
nonempty destinations, writes inventory first and access last, and never
deletes a partial result automatically.

The complete snapshot supports a fresh-instance restore drill, not protection
from a fully compromised host or a malicious same-user process. Older intact
snapshots can be replayed. Advisory locks do not constrain external writers
or network filesystems. The public certificate inventory is not private-key
custody, verified trust, certificate renewal, or a production release.
