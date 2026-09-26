# Public certificate inventory: first boundary

**Status:** in-memory data model only. No persistent inventory, HTTP import
endpoint, browser save button, backup, recovery key, or vault is shipped by this
increment. Do not place real operational records here expecting them to survive
a restart.

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

1. Define a versioned encrypted record format and bind record type, schema,
   installation identity, and record identity as authenticated context. Use a
   reviewed standard-library AEAD with unique nonces; the existing installation
   data key must never appear in logs, URLs, browser storage, or configuration.
2. Establish a single-writer/locking strategy, private data-directory checks
   for every supported OS, bounded reads, disk-full and crash-fault tests,
   and rollback/corruption behavior. Windows `0600` is not proof of a private
   ACL. A container volume does not itself provide key recovery.
3. Design and test backup of both the access envelope and encrypted records,
   a restore drill on a fresh instance, and a separate offline lost-password
   recovery ceremony. Existing installations have no recovery credential and
   must not silently acquire one or start storing durable records. Deleting
   `access.json` must never be treated as recovery.
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
