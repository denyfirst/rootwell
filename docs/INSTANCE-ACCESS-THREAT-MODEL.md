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

The file must live in a private, operator-controlled directory. File operations
are scoped to an `os.Root` opened on that directory. Creation refuses existing
paths and uses mode 0600; reads are bounded to 4 KiB and reject symlinks,
non-regular files, and (on POSIX) group/world permissions. A read compares the
opened file identity with the file checked before opening, so a swapped final
path cannot silently redirect the read.
The Windows file mode does not prove a restrictive ACL. Parent-directory
ownership, symlink races, ACLs, crash durability of directory rename, and
concurrent writers require platform-specific hardening before a production
server or secret vault may rely on this package. The separately reviewed
loopback-only development gateway is described in
[`LOOPBACK-GATE-THREAT-MODEL.md`](LOOPBACK-GATE-THREAT-MODEL.md); it does not
enable production secret custody.

The package never prints a password. The local interactive init command
shows the generated password exactly once on its terminal, not daemon
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

Required next review for production: TLS/reverse-proxy policy, rate limiting
across restarts, concurrent process instances, OS ACL/locking,
backup/restore, and recovery. The loopback gateway separately tests its
origin, session fixation, CSRF, and first-login restrictions.

New installations use access envelope v2: a random 128-bit installation ID
is authenticated together with the setup/ready state when the same 256-bit
data key is wrapped. The ID is not secret and is visible in the access file.
Password rotation preserves the key and ID. Existing v1 envelopes remain
readable and password-rotatable, but have no ID; future durable inventory must
refuse them until an explicit, separately reviewed enrollment operation is
available. This change does not migrate or rewrite existing user files.
An ID alone does not stop record rollback, make backups recoverable, or prove
host integrity.

A ready v1 file can now be authenticated to prepare an encrypted v2 candidate
in memory. Preparation records the exact SHA-256 revision of the source and
preserves its data key and password under a new random ID. It does not replace
the source file, write a candidate, enroll a recovery code, or change a
running daemon. Repeating preparation creates a different candidate; only one
may be committed later. The revision is not a compare-and-swap lock: a future
installer must hold exclusive single-writer control, compare the source again,
atomically replace it, and verify the result. Do not manually overwrite the
operator's access file with a candidate.

The separate in-memory recovery-wrap codec generates a 256-bit random code
and wraps the existing 256-bit data key with AES-256-GCM, authenticating the
expected v2 installation ID. It returns a bounded binary wrap and a printable
code only to its caller. It does **not** persist the wrap, display a code in
the UI, enroll an existing installation, reset a password, or restore records.
Anyone who obtains both wrap and code can recover the data key offline; the
code must be stored separately from the wrap and access file. There is no
online guessing endpoint, but stolen wraps allow unthrottled offline attacks;
the code's random entropy, not a memorized password, is the protection.
The printable Go string cannot be reliably erased from process memory.
Loss of both the login password and recovery code remains irrecoverable.
