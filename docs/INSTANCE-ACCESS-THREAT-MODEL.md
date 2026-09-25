# Instance access foundation threat model

**Scope:** local key-envelope package only; no HTTP login, persistence API, vault,
or encrypted inventory is shipped by this increment.

The installation password is a secret known to the operator. A random 256-bit
data key is wrapped using PBKDF2-HMAC-SHA256 (600,000 rounds, 128-bit salt) and
AES-256-GCM with a fresh nonce. The authenticated setup state is bound as AEAD
associated data. The access file contains the wrapped key, not the password.
The initial password is generated independently for each installation. A setup
password cannot be used through `Open` to obtain the data key; only an explicit
successful change makes the file ready. Password changes rewrap the same data
key, so future encrypted records need not be rewritten.

The file must live in a private, operator-controlled directory. Creation
refuses existing paths and uses mode 0600; reads are bounded to 4 KiB and
reject symlinks, non-regular files, and (on POSIX) group/world permissions.
The Windows file mode does not prove a restrictive ACL. Parent-directory
ownership, symlink races, ACLs, crash durability of directory rename, and
concurrent writers require platform-specific hardening before a server or
secret vault may use this package in production. In particular, this increment
must **not** be wired to an HTTP gate yet.

The package never prints a password. A future local interactive init command
may show the generated password exactly once on its terminal, not daemon
stderr, application logs, CLI arguments, URLs, or browser storage. Initial
password loss before change cannot be recovered from the access file. After
activation, lost password means encrypted data is inaccessible without a
separately designed offline recovery method; deleting the access file is not
recovery. Rootwell will not silently reset it.

The data key exists in process memory after a valid open. Go strings and
internal copies cannot be reliably zeroized. A compromised host or process
can read memory and is outside this encryption-at-rest claim. PBKDF2 is a
standard-library conservative KDF choice pending dependency review for
Argon2id; its cost is bounded by requiring exactly the configured round count
on reads. No rate limiting is provided by this package; the future HTTP gate
must supply it before exposing any password check.

Required next review: server origin/TLS and loopback policy, session fixation,
CSRF, rate limiting across restarts, first-login restricted session,
concurrent password changes, OS ACL/locking, backup/restore, and recovery.
