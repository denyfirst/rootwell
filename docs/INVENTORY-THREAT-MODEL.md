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
One certificate object is identified by its fingerprint; it can now hold up
to 32 exact, operator-declared location labels without a duplicate DER copy.
The first remains the legacy `location` field; older encrypted images open
unchanged. A label is a manual note, **not** proof the certificate runs on
that host. Duplicate certificate import is still refused. Association is a
separate authenticated POST with a displayed-generation precondition, bounded
JSON, and no certificate upload. A changed generation, missing fingerprint,
duplicate/invalid/excess location, or unsafe image is refused without a write.
The record is resealed under a new image generation while original import
generation/time remain unchanged. The full backup after that change is still
manual; see [ADR 0023](adr/0023-operator-declared-certificate-locations.md).
An owner is also an unverified manual note. A separate generation-bound,
same-origin authenticated POST can replace it or explicitly clear it to
unknown without altering DER, locations, or original import provenance.
Malformed, stale, unchanged, and unauthorized corrections do not write.
This is not an edit history; old snapshots can retain the previous owner.
See [ADR 0024](adr/0024-explicit-owner-note-correction.md).
Exact manual locations can also be renamed or removed under the same
authentication, generation, and writer-lock boundary. Removing the last
location makes it unknown while the certificate remains saved. The operator
must explicitly confirm note removal in the UI; this does not contact or
change a named server. Old snapshots can retain old labels. See
[ADR 0025](adr/0025-explicit-location-note-correction.md).

The catalog holds up to 500 records in one process. Each DER certificate is at
most 64 KiB, labels at most 128 UTF-8 bytes and free of controls/formatting
characters. The catalog itself creates no file or network request. Durable
storage and an explicit user-facing loopback API are separate boundaries below.

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
   original import order even after a manual metadata correction; the
   optional save timestamp comes from the server clock. Neither is a
   tamper-evident audit log. The browser can locally sort and filter the
   authenticated inventory response by expiry, unknown owner/location, and
   text. Its clock is untrusted; expiry at the exact NotAfter instant is
   expired. Filtering does not send terms, read selected files, persist search
   terms, notify, renew, or change stored records. An incorrect device time
   can mislead the operator. See [ADR 0026](adr/0026-local-expiry-triage.md).
   The earlier browser-only JSON metadata export was removed from the
   Inventory UI after user testing: it confused saved-record management with
   certificate conversion and disclosed internal notes as a plain download.
   The historical decision is in [ADR 0027](adr/0027-explicit-public-inventory-export.md).
   Certificate download remains in the Workbench Explore/Verify flows;
   encrypted full inventory backup is a separate offline operation. The
   fake-data development demo binds loopback only and rejects all writes;
   it is not authenticated storage.
   Deleting one public record requires a ready session, exact same-origin
   request, duplicated typed fingerprint, fixed confirmation phrase, and the
   displayed generation. The complete encrypted image authenticates before
   one record is removed and atomically replaced. Other records retain their
   ciphertext and import provenance. This is current-image removal, not
   cryptographic erasure, certificate revocation, or remote undeployment.
   Earlier full snapshots can restore the record, and a fresh snapshot after
   deletion captures its absence. There is no automatic retention expiry or
   backup deletion. See
   [ADR 0028](adr/0028-explicit-certificate-record-deletion.md).
5. Linux container bind-volume permissions and fresh restore now have a
   disposable CI drill. The local Compose profile keeps the server's backup
   mount absent and runs maintenance without a network; its Linux host network
   mode is necessary for the existing loopback bind but reduces container
   network isolation. This is not a production remote-access recipe. Before a
   production or public-release claim, independently audit this storage
   boundary, test offsite recovery on actual target infrastructure, and resolve
   the remaining platform and operational risks.

## Server-clock expiry reminders (ADR 0041)

The ready-session inventory read now derives expiry and remaining days from
one whole-second server-clock instant after authenticating the complete image.
This supersedes the browser-clock expiry display described above and in ADR
0026; neither clock is a trust source. Reads do not write inventory or advance
its generation. The page offers ephemeral 7/14/30/90-day windows, quiet in-app
reminders, a clock-disagreement warning, and a stale-result warning after two
minutes. Visible-page reads use a one-minute interval, ten-second deadline and
streaming 4 MiB response cap. Failure clears records and pauses retries;
hidden/pagehide views discard metadata, abort reads and reject late results.
Returning authenticates again. There is no new background scheduler, private
key storage, email/webhook, endpoint scan or automatic renewal. A closed page
cannot notify the operator. See [ADR 0041](adr/0041-server-clock-inventory-reminders.md).

An operator-controlled filesystem or browser process can still inspect
plaintext in memory while Rootwell is unlocked. Encryption at rest does not
protect a fully compromised host. Automatic deletion is not part of the
inventory retention policy. Explicit deletion removes only the current image
entry; snapshots and any external copies remain the operator's responsibility.
An older, intact ciphertext can be replayed with the same context unless a
future trusted manifest rejects stale generations. The codec alone is not an
anti-rollback or recoverability solution.
