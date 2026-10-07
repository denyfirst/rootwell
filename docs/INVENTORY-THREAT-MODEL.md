# Public certificate inventory: first boundary

**Status:** Linux-only private-file persistence, complete access+public
inventory snapshots, and an explicit loopback Inventory UI/API are implemented.
Native Windows storage is disabled. This boundary is development-only and not
externally audited. This document describes the public import boundary.
The separate, explicit certificate-library custody route of ADR 0046 adds
optional matched leaf keys; it does not make this public importer accept
secrets. The UI now presents one Certificates library. See
[certificate custody threat model](CERTIFICATE-CUSTODY-THREAT-MODEL.md).

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

## Explicit Workbench opening (ADR 0042)

Inventory card Inspect/Verify buttons send only an exact public fingerprint,
displayed generation and destination via native same-tab POST. This route has
mandatory same-origin navigation metadata instead of the JSON custom header;
the ready revision-bound Linux session and complete-image authentication are
unchanged. Only one public DER enters an inert, no-store Workbench response;
notes/keys/credentials do not. Workbench consumes it in memory and reparses its
identity before rendering, without acquiring network or storage capabilities.
Stale selection, malformed form, missing metadata, anonymous/setup access and
unsupported platforms release no source. Explicit issuer additions do not
select trust. Already-open snapshots are local copies, not server-revocable
objects; browser/OS memory/history erasure is not promised. See
[ADR 0042](adr/0042-explicit-inventory-workbench-handoff.md).

## Local public bulk preview (ADR 0043)

The later lifecycle wave below adds comparison, history and session-bound
background checks; this earlier bulk increment alone granted none of them.

An operator-controlled browser process can inspect public preview bytes.
ADR 0043 adds 1–8 file local public preview and one exact
canonical PEM Save via the existing atomic append, not a new import API.
Private/mixed/malformed files and selected duplicates refuse the entire
preview; saved duplicates are displayed and block Save. A concurrent duplicate
is still refused by the server. Preview grants no trust. Selected source
changes/hidden views clear pending work; aborting after POST cannot roll back
a commit, so uncertain Save requires refresh. The authenticated Inventory-only
WASM asset loader sends no selected bytes. Workbench's loader and offline
capabilities do not change. Windows fixture preview is synthetic/read-only,
not durable custody; the underlying browser/OS cannot promise memory erasure.

An operator-controlled filesystem or browser process can still inspect
plaintext in memory while Rootwell is unlocked. Encryption at rest does not
protect a fully compromised host. Automatic deletion is not part of the
inventory retention policy. Explicit deletion removes only the current image
entry; snapshots and any external copies remain the operator's responsibility.
An older, intact ciphertext can be replayed with the same context unless a
future trusted manifest rejects stale generations. The codec alone is not an
anti-rollback or recoverability solution.

## Public lifecycle wave (ADR 0044)

This supersedes the ADR 0041 scheduling limitation, not the trust boundary.
The daemon checks the authenticated image once per minute even with no page
open, using an existing ready session's memory-held key. It retains no new
unlock credential, extends no session and writes no inventory. Logout, expiry
(up to 12 hours), restart, invalid access revision, storage failure and a
backwards clock clear the RAM-only 30-day attention list. Late reads cannot
revive a revoked session's result. Stale age/generation/unlock deadline is
reported separately; this is not reliable unattended 24/7 monitoring or
external notification. A false host clock remains an operator risk.

Explicit comparison reads one saved public DER at an exact fingerprint and
generation. A single local PEM/DER candidate up to 96 KiB (DER up to 64 KiB)
stays in the browser and is parsed by Go WASM. It reports exact certificate,
SPKI, subject/issuer encoding, DNS/IP/email/URI names and validity differences;
there is no trust, private-key possession, automatic save or replacement.
An opened saved snapshot is a local copy, not a live deployment observation.
Automatic page refresh pauses during comparison; explicit refresh/hidden page
invalidates the selection. Already exposed browser memory is not revocable.

One encrypted history event is atomically included with each successful
mutation and retained by full snapshots. Fixed actions, UTC second, generation
and fingerprints are included; previous notes, DER and credentials are not.
Whole-image and event authentication precede output. Legacy history is unknown;
1024 events refuse further writes. There is currently no history archive or
clear operation: production retention/capacity needs an explicit policy before
release, not silent truncation. Old binaries reject new history-bearing images;
do not downgrade after writes. Deleted identities stay in history/backups.
This is local provenance, not an independent audit log or rollback protection.
Windows preview displays synthetic history and honestly reports no running
worker; Linux tests exercise actual durable storage, restore and scheduling.
