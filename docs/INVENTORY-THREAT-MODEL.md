# Public certificate inventory: first boundary

**Status:** in-memory data model, encrypted-record codec, and a standalone
authenticated complete-image codec only.
Linux access-envelope recovery and access-only snapshots are separate; no
persistent inventory, HTTP import endpoint, browser save button, inventory
backup, or vault is shipped. Do not place real operational records here
expecting them to survive a restart.

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
   result. It has no filesystem transaction or external anti-rollback anchor;
   an older complete authenticated image can still be replayed. A safe
   persisted writer and full restore drill remain required before any storage
   write. The installation data key must never appear in logs, URLs, browser
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
   The Linux-only internal v3 access writer now embeds a recovery wrap with
   the access envelope and can reset a password with a code. It is not yet an
   full inventory backup, fresh restore drill with records, and stopped-daemon
   coordination remain required before any inventory write. A Linux terminal
   ceremony now supports recovery enrollment/reset and an access-envelope-only
   snapshot with a fresh access restore drill. It contains no inventory
   records and cannot substitute for the future full backup. The standalone
   codec alone is not an enrolled credential.
4. Only then expose a bounded, authenticated, same-origin API to **ready**
   sessions. The current standalone Workbench remains an offline, public-file
   processor. Any browser-to-server import is an explicit new capability and
   must be visible to the operator. No private key or PFX is accepted.
5. Before a production or public-release claim, test Linux/container volume
   permissions and restore, and independently audit this storage boundary.

An operator-controlled filesystem or browser process can still inspect
plaintext in memory while Rootwell is unlocked. Encryption at rest does not
protect a fully compromised host. Automatic deletion is not part of the
planned inventory retention policy; explicit deletion and its backup effects
need their own review.
An older, intact ciphertext can be replayed with the same context unless a
future trusted manifest rejects stale generations. The codec alone is not an
anti-rollback or recoverability solution.
