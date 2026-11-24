# ADR 0088: Rootwell's foundation, the Keybash way

## Status

Accepted on 22 November 2026, for Phase 3 of `PRODUCT-PLAN.md`. As each part
lands, it replaces these earlier decisions, which stay as history:

- the password-derived unlock and the offline ceremonies (ADRs 0013 to 0021);
- the single-image store (ADRs 0020 and 0021);
- the session-bound automation (ADRs 0071 to 0080).

**Note, 23 November 2026 (Phase 3a, part 2).** The session-bound automation,
the hidden Renewals page, `internal/inventorystore`, `internal/inventoryseal`
and the offline inventory commands were removed before their replacements
landed, not as each one lands. Nothing has been released, there are no users,
the page was hidden, and keeping them would have meant moving them to the
vault only to delete them in Phase 3c. The ACME protocol packages stay for
Phase 3c. Until 3b brings `key-export` and `key-rotate`, the recovery code
`init` prints is used by `rootwelld key-restore <data-dir> <key-file>`, which
rebuilds a lost key file, with the service stopped, once the code opens the
vault in that data directory. The access-file commands stay until part 3; they
concern only the sign-in password.

**Note, 24 November 2026 (Phase 3a, part 3).** Accounts, phone codes,
sessions, limits and fresh codes landed as decided below, and
`internal/instanceaccess`, the access file and its offline commands were
removed. HTTPS is split into the next pull request; until it lands the
service stays plain HTTP on loopback. Where this part fills in or departs
from the text below:

- **Setup codes:** the one-time bootstrap code `init` prints works for
  24 hours. `rootwelld setup-code <data-dir> <key-file>` makes a new one, with
  the service stopped, and a new code replaces the last. With an account's
  name it makes a code that replaces that account's password, phone and
  recovery codes: the way back after losing the password, or the phone
  together with the recovery codes.
- **Accounts:** each account is one sealed vault record. One administrator
  account is the limit in this release; a setup code for a second is refused.
- **Sessions** stay in memory, so a restart signs everyone out. A password
  change ends every session; a new phone or new recovery codes end every other
  session and keep the browser that made the change, under a new token.
- **Fresh code:** of the list below, only downloading a key and deleting a
  certificate with a key exist yet. Changing the password, the phone or the
  recovery codes needs one too. Showing a key on screen does not exist.
- **Platform:** `rootwelld` runs only on Linux; the Windows and macOS preview
  without a vault is gone. The `rootwell` command and the browser tools are
  unchanged.

## Context

**Today's design** comes from three choices, each careful on its own:

- The data key opens only from the sign-in password, and only for a session
  of at most 12 hours.
- The store is one encrypted image, with fixed limits on its history and its
  capacity.
- The service is plain HTTP on loopback.

**Together they leave a manager that cannot do its job:**

- Renewal stops whenever nobody is signed in.
- Backups need the service stopped, plus the password and the offline code.
- The store refuses every write after about 5,120 of them (audit RW-01).
- A server needs an SSH tunnel to be reached at all.

**The way out is already proven.** Keybash, the sibling product, solved the
same problems for SSH and RDP credentials. Nothing has been released and no
installation exists, so the old paths are replaced, not migrated.

## Decision

### Keys

- The **instance key** is 32 random bytes in its own `0600` file, outside the
  data directory:
  - It is never in the database or in a backup.
  - `rootwelld init` prints a recovery copy once, as `RW1-` plus grouped
    base32.
  - `rootwelld key-export` prints it again, with the service stopped.
- **Every secret** gets its own random 256-bit data key and an AES-256-GCM
  seal. Secrets are private keys, ACME account keys, DNS tokens and TOTP
  seeds. The data key is wrapped under a key derived from the instance key
  with HKDF-SHA256. The derivation label names the record kind.
- **Additional data** binds each seal to its kind, its record ID and its
  version, so a ciphertext moved to another record is refused.
- **Record IDs** are an HMAC of the certificate fingerprint under a derived
  key. A backup therefore no longer lists the managed domains (RW-12).
- **Rotation:** `rootwelld key-rotate` re-wraps every data key under a new
  instance key in one transaction, and prints the new recovery copy (RW-04).
- **The service opens secrets without a person.** Unattended renewal needs
  it, and the operating system protects the key file. A live host
  compromise reveals the keys, as it would for any renewer. Rootwell says so
  in the documents and does not pretend otherwise.

### Store

- **bbolt**, the store Keybash uses, with one bucket per kind of record.
  - The file is `rootwell.db` in the data directory: `0700`, owned by the
    service user.
  - `go.etcd.io/bbolt` is the one new dependency; Keybash's review of it
    applies.
- **A secret is opened only when it is used.** Listing certificates reads
  public records only (RW-11).
- **History** is a rolling log of the last 2,000 events. It never refuses a
  write (RW-01).
- **Generations:** the meta record counts every committed write, and history
  and backups name the generation they hold. Swapping in a whole older file
  is not detected; RW-13 stays a documented limit until there is an outside
  anchor.
- **Backups:**
  - A backup is a consistent copy made in one read transaction, so the
    service keeps running. It is started from the Installation page or by
    `rootwelld backup`.
  - It holds no instance key.
  - A restore writes into an empty directory and needs the instance key or
    its recovery copy.

### Accounts and sign-in

These follow Keybash:

- **First account:** `rootwelld init` prints a one-time bootstrap code. The
  first account is created on the web with it. There is no default password
  and no open registration.
- **Passwords:** Argon2id (64 MiB, three passes, four lanes) over at least 15
  characters, checked against a blocklist. There is one length limit
  everywhere: 1,024 bytes (RW-09).
- **Second factor:**
  - Mandatory TOTP: RFC 6238, SHA-1, six digits, 30 seconds, one step of
    drift, and a code used once is refused again.
  - Ten one-time recovery codes.
  - Enrolment shows a QR code, drawn by the in-tree encoder Keybash uses.
- **Sessions:**
  - The token is 256 bits; only its hash is stored.
  - The cookie is `__Host-`, Secure, HttpOnly and SameSite=Strict.
  - A session ends after 15 minutes idle and 8 hours at most.
  - Every session ends on a password or factor change.
- **Limits:** only failures count, per account name and per source address,
  with backoff. A success costs nothing (RW-07).
- **Fresh code:** a phone code from the last ten minutes is asked only to:
  - show or download a private key;
  - delete a certificate that has a key;
  - save, replace or remove a DNS token;
  - register a CA account;
  - change a delivery target.

  Nothing else asks again.
- **Roles:** the first release has one administrator. User and auditor roles
  come later, in Keybash's model.

### HTTPS

- **HTTPS only.** By default it listens on `127.0.0.1` and `[::1]`, holding
  both addresses (RW-03). `--listen` adds named LAN or VPN addresses. Every
  request must carry one of the configured names as its host, and an exact
  matching Origin (RW-02).
- **Certificate:**
  - `rootwelld init` makes a local CA: P-256, ten years, with name
    constraints limited to the configured names. It prints the CA's
    fingerprint for the browser.
  - The CA signs the server certificate: P-256, 90 days. `rootwelld` renews
    it itself.
  - Once public ACME works, an installation can use a public certificate for
    its own name instead.

### Renewal (Phase 3c)

- **A managed certificate** has:
  - names;
  - a CA profile, Let's Encrypt production or staging;
  - a challenge, Cloudflare DNS-01 or manual DNS;
  - an optional delivery target.
- **Scheduling:**
  - A scheduler inside `rootwelld` wakes every ten minutes.
  - It renews inside the CA's ARI window when there is one, otherwise at two
    thirds of the lifetime.
  - Failures back off from one hour up to a day.
  - No person is needed, and no session is involved.
- **Each step is saved before it is taken:** the order URL, the
  authorizations, the CSR and the key. After an unknown outcome, the engine
  reads the order again before it repeats any request. A `badNonce` answer
  is retried once with a fresh nonce (RW-06).
- **Reused code:** the protocol pieces of `acmestaging` (directory,
  registration, order, certificate, Cloudflare and ARI), each with one fixed
  CA host per profile.

### Delivery (Phase 3d)

- **Targets** are defined by root in `/etc/rootwell/targets.d/*.conf`. Each
  names:
  - a directory;
  - the file names;
  - the group and the mode;
  - optionally, one systemd unit to reload.

  A page can attach a certificate to a target root defined. It can never
  name a path or a command.
- **Writing:**
  - Files are written atomically: a temporary file, `fsync`, then `rename`.
  - The previous set stays as `*.previous`.
  - The key file is written only when the matching certificate is valid for
    the target's names.
- **Reloading:** the installer adds a polkit rule that lets the service user
  reload exactly the named units, and nothing else.

### What goes

These are removed as their replacements land:

- `internal/instanceaccess`;
- `internal/inventorystore` and `internal/inventoryseal`;
- the session layer of `cmd/rootwelld/gate.go`;
- the timing watch, the session renewal job, the closed-request pages, the
  history archives and DNS maintenance;
- the offline ceremony commands.

The `rootwell` command and the browser tools stay as they are.

## Order of work

1. **3a:** the instance key, the bbolt store with sealing per record,
   accounts with TOTP, sessions and HTTPS. The Certificates page moves onto
   the new store; the old store and unlock are deleted.
2. **3b:** online backup and restore, key rotation, and the Installation
   page.
3. **3c:** the renewal engine and the new Renewals page; the old automation
   is deleted.
4. **3d:** delivery targets, and the website check after delivery.
5. **3e:** install, upgrade and uninstall scripts, and signed reproducible
   releases.

Each step is its own pull request. Each comes with success, refusal,
malformed-input and sabotage evidence, and with the audit findings it
closes.

## Consequences

- **Threat model:** Rootwell's model becomes Keybash's.
  - A stolen database or backup is protected while the instance key stays
    apart.
  - A compromised live host is not.
- **Losing both** the instance key and its recovery copy loses every secret.
  Onboarding says so plainly.
- **Development data** from earlier builds is not carried forward.
