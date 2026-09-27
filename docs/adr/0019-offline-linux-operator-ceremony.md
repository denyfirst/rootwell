# ADR 0019 — Local terminal recovery ceremony and daemon exclusion

**Status:** accepted for Linux development use only; production audit pending.

## Decision

Expose the v3 recovery and access-only snapshot core only through explicit
`rootwelld` commands on the local Linux host. Both stdin and stdout must be
real terminals. Passwords and recovery codes are read with
`golang.org/x/term.ReadPassword`, without local echo; command arguments contain
only paths and `password|code` selectors. No HTTP/browser endpoint, pipe,
environment variable, or password file is accepted. After a successful
enrollment/reset, the new recovery code is shown once on stdout with an
instruction to store it separately from snapshots. Failure to display it
returns a secret-free error and the known login password can rotate recovery.
Go strings and terminal scrollback remain outside reliable zeroization.

The daemon and every offline Linux write operation acquire an exclusive
advisory lock on a persistent owner-private operation-lock inode. The daemon
holds it until shutdown; offline functions acquire it before the shorter
access writer lock. This prevents cooperating instances from resetting access
while the Workbench is live. It does not bind older builds or hostile
processes that ignore the protocol. Never remove lock files as routine cleanup.

Restore requires a pre-existing, empty 0700 destination directory. It first
authenticates the snapshot, then creates only `access.json`. A code-based
restore retains the historical password until the operator explicitly runs
`recovery-reset`; failures between those steps are recoverable with the same
code. Existing installations are never overwritten.

Dependency review: `golang.org/x/term` v0.46.0 is maintained by the Go team,
BSD-3-Clause licensed, and provides the narrow `IsTerminal`/`ReadPassword`
primitives used here. Its only module dependency is `golang.org/x/sys`
v0.48.0, also Go-team maintained and BSD-3-Clause licensed. No parser or
cryptographic primitive is added. Module checksums, vulnerability scanning,
and all CI gates are required. See the official
[`x/term` API](https://pkg.go.dev/golang.org/x/term) and
[`x/term` source](https://github.com/golang/term).

This ceremony is access-only. It is not a backup of certificate inventory,
private keys, or future vault data; it is not anti-rollback, native Windows
storage, remote administration, or a production disaster-recovery guarantee.
An independent release audit and fresh restore drills remain mandatory.
