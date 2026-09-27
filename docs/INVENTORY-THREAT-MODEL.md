# Public certificate inventory: first boundary

**Status:** Linux-only private-file persistence, complete access+public
inventory snapshots, and an explicit loopback Inventory UI/API are implemented.
Native Windows storage is disabled. This boundary is development-only and not
externally audited. No vault or private-key storage is shipped.

## Data and trust boundaries

Public X.509 DER is not a private key, but certificate subjects, SANs, owner
names, and server/location labels may reveal internal topology. Treat the whole
future inventory as sensitive metadata. The present `publicinventory.Catalog`
accepts only the existing bounded public certificate parser's DER/PEM inputs,
then reuses its strict X.509 inspection. PFX, private-key blocks, mixed text,
malformed objects, oversized certificates, and cross-import duplicates are
rejected. A multi-certificate import is all-or-nothing. Unknown owner and
location remain explicitly empty rather than guessed. Inputs and returned
records are detached copies. There is no trust, hostname, revocation, live
endpoint, renewal, or private-key-possession verdict.
One certificate object is identified by its fingerprint; the same certificate
can later be associated with multiple deployment/location objects. Rejecting
a repeated import must not be mistaken for proof it runs on only one server.

The draft holds up to 500 records in one process. Each DER certificate is at
most 64 KiB, labels at most 128 UTF-8 bytes and free of controls/formatting
characters. It creates no file and makes no network request. It has no data
retention promise because it is not exposed as a user-facing inventory yet.

## Gate before durable storage or an import API

1. The first codec is versioned and binds record type/schema, installation
   identity, certificate identity, and expected generation as AES-256-GCM
   authenticated context. Go's standard-library random-nonce AEAD supplies a
   fresh 96-bit nonce on each seal. It accepts only 32-byte keys and bounded
   plaintext/ciphertext. It does not validate record payloads or supply a
   persisted monotonic generation source. The access envelope now provides an
   authenticated stable ID for new v2 installations only; existing v1
   installations need explicit enrollment. A v1-to-v2 candidate preparer and
   Linux-only locked internal installer exist, but no operator-facing
   migration, backup enrollment, or automatic migration does. An
   authenticated complete-image manifest codec now supplies an image-local
   generation source and validates every encrypted record before returning any
   result. A Linux private-file writer now uses an owner-private directory,
   an advisory writer lock, a bounded read, and an atomic single-file replace
   followed by directory sync/readback. An older complete authenticated image
   can still be replayed: there is no external anti-rollback anchor. The
   installation data key must never appear in logs, URLs, browser
   storage, or configuration. The random-nonce
   AEAD has a per-key message-count limit; the future storage layer must count
   writes and rotate keys well before that limit. Ciphertext length remains
   visible even when its contents are encrypted.
2. Establish a single-writer/locking strategy, private data-directory checks
   for every supported OS, bounded reads, disk-full and crash-fault tests,
   and rollback/corruption behavior. Windows `0600` is not proof of a private
   ACL. A container volume does not itself provide key recovery.
3. Design and test backup of both the access envelope and encrypted records,
   a restore drill on a fresh instance, and a separate offline lost-password
   recovery ceremony. Existing installations have no recovery credential and
   must not silently acquire one or start storing durable records. Deleting
   `access.json` must never be treated as recovery.
   The Linux-only v3 access writer embeds a recovery wrap with the access
   envelope and can reset a password with a code. A Linux complete backup
   now pairs an authenticated access snapshot with the
   exact encrypted inventory image, requiring password and separately stored
   recovery code at export. It is verified with either credential and restored
   only to a fresh private directory, inventory first and access last.
   Inventory initialization writes a matching empty full backup before
   enabling storage. Offline export and restore exclude a live daemon via the
   operation lock. Access-only snapshots remain insufficient for inventory.
   Operators must make new full snapshots after imports; backups are not
   automatic. The standalone codec alone is not an enrolled credential.
4. The loopback API is bounded and requires a **ready** authenticated session.
   Its POST requires exact same origin and a custom request header; GET
   requires the header and refuses cross-site fetch metadata. A ready Linux
   session holds a copy of the installation data key in server process memory
   for its existing 12-hour lifetime. Revocation makes a best-effort erasure,
   not a reliable Go heap wipe. Import is an explicit Save action on a separate
   Inventory page. The standalone Workbench remains an offline public-file
   processor and does not silently upload files. The server parses the public
   file again and refuses PFX, private keys, malformed bundles, labels, and
   duplicates. A rejected batch leaves storage unchanged. API output omits
   DER bytes and reports `verification: not-performed`. Browser-clock expiry
   is not trusted time, notification, or renewal. Import generation records
   order; the optional save timestamp comes from the server clock. Neither is
   a tamper-evident audit log.
5. Linux container bind-volume permissions and fresh restore now have a
   disposable CI drill. The local Compose profile keeps the server's backup
   mount absent and runs maintenance without a network; its Linux host network
   mode is necessary for the existing loopback bind but reduces container
   network isolation. This is not a production remote-access recipe. Before a
   production or public-release claim, independently audit this storage
   boundary, test offsite recovery on actual target infrastructure, and resolve
   the remaining platform and operational risks.

An operator-controlled filesystem or browser process can still inspect
plaintext in memory while Rootwell is unlocked. Encryption at rest does not
protect a fully compromised host. Automatic deletion is not part of the
planned inventory retention policy; explicit deletion and its backup effects
need their own review.
An older, intact ciphertext can be replayed with the same context unless a
future trusted manifest rejects stale generations. The codec alone is not an
anti-rollback or recoverability solution.
