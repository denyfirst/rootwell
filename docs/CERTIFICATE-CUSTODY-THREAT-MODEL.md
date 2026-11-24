# Certificate library custody — development boundary

Date: 2026-10-07, updated 2026-11-24 for Phase 3a, part 3, HTTPS, passkeys
and Phase 3b.
Decisions: [ADR 0046](adr/0046-unified-certificate-library.md), ADR 0047,
ADR 0048, ADR 0087 and [ADR 0088](adr/0088-keybash-foundation.md). Single
operator, Linux daemon over HTTPS, on loopback and on any LAN or VPN address
named with `--listen`; not externally audited or ready for real-user secret
custody. Porch and the offline Workbench remain separate.

ADR 0047 updates the first matched-only increment. New imports accept one
primary certificate or related public PEM bundle (16 certificates, 768 KiB;
JSON 1200 KiB), plus one strict optional key. Check is optional; Save repeats
validation. Computed mismatch may be retained only with explicit
acknowledgement. Malformed/password/CA-key failure still refuses. Included issuer signatures are
checked, but roots are not trusted, and neither names, time, revocation nor
deployment is verified. Ambiguous primary selection requires an explicit exact
fingerprint. Unrelated or ambiguous issuer collections refuse.

Since 23 November 2026 (ADR 0088) a saved certificate lives in the vault,
`rootwell.db` in the private data directory, as two sealed records: the
certificate record holds the canonical public DER collection, the notes and
the key status; the key record holds the PKCS#8 key and any mismatch
acknowledgement. No client status, password, filename or raw input is
persisted. Every certificate record is decoded strictly, without unknown
fields, and must sit under its own fingerprint's record ID before anything is
listed; one damaged record stops the list. The old single encrypted image,
its manifest fields and its full snapshots are gone; development data from
earlier builds is not carried forward.

Matching-pair ZIP refuses a mismatch. Encrypted key-only PEM needs the same
fresh code, exact generation and output-password policy. Public bundle
download includes supplied roots
without assigning trust. The archive remains unencrypted. ADR 0087 prepares
PFX contents locally; original PFX containers are not stored. Plaintext custody
export, an internet-facing listener, multiuser policy and production claims
remain excluded.

## Assets and trust

ADR 0087 adds browser-only preparation of one bounded modern PFX/P12 in the
same Add form. Original container/password never enter the normal API. A
separate one-shot worker authenticates the exact input, preserves every related
public certificate and returns a newly encrypted PKCS#8 key with a random
temporary password. The trusted UI sends both to the existing API for
independent match/chain checks and the vault write; this does not isolate keys
from a compromised UI/server. No raw key view, server PFX decoder, storage
format or extra network authority is introduced. The source digest/file
identity binds Check/Save; randomized encrypted output is not used as source
identity. Ready-first transfer, 90s worker/150s operation deadlines, Clear
selection/hidden/pagehide/source/generation/error clearing and late output
refusal apply. Current password remains in the form for explicit Check/Save,
not preview state or persistence. Legacy/empty/non-ASCII passwords,
ambiguous/multiple matching keys/certificates, CA keys and unrelated
collections refuse. Same host/runtime/hidden-KDF/backup/rollback residuals
remain. See ADR 0087.

ADR 0048 adds only a key to a saved certificate that has none, never a
replacement. Check/Save accept exact fingerprint/generation and one strict key,
not new certificate/notes/status. Save needs a signed-in session and the one
slot for expensive checks, but no fresh code, since it hands nothing out; the
vault write repeats validation and
keeps the certificate, bundle and notes as they were, with the key as a record
of its own. Lost confirmation after a committed write is uncertain, including
logout/cancellation. The Convert handoff of ADR 0048 was retired on
22 November 2026 with the page rebuild: Convert now works only on files a
person chooses, and Certificates downloads a saved certificate and key itself.
See [ADR 0048](adr/0048-saved-key-attachment-and-convert-handoff.md).

The staging issuance paths of ADRs 0061 and 0062, which wrote checked staging
pairs into the old image, were retired on 23 November 2026 with the
session-bound ACME automation (ADR 0088). Renewal returns in Phase 3c.

Certificate DER, optional matching private key, key-input password, the
account's password, phone key and recovery codes, setup codes, session
tokens, output password, the instance key file, its recovery code, the key of
Rootwell's own certificate authority, backups and copies of the data
directory, and internal service notes are sensitive. Public key is
part of the selected certificate, not a second standalone input. Notes declare
intended usage; matching a key proves mathematical identity, not trust or
deployment.

Browser, same-origin scripts, authenticated daemon, Go/JS runtimes and host are
trusted. Files, names, JSON, timings, client metadata, the database file and
old sessions are hostile inputs. Host administrators, compromised
daemons/browser extensions and runtime copies can access secrets; encryption at
rest does not protect against them. The running service holds the instance
key, so a compromised live host reveals every key. This is not end-to-end
encryption or multi-user RBAC.

## Controls and refusal paths

- Signed-in sessions only. The one account is made with a setup code printed
  on the server, and signs in with its password and then a phone code or a
  recovery code; sessions live in memory, end after 15 minutes idle and
  8 hours at most, and only failures count against the name and the address
  (invariants C108–C110). HTTPS with TLS 1.3 only, an exact covered Host and
  `https://` Origin (C112), same-origin custom header, POST-only operation,
  no query fields, no-store responses and the existing CSP apply. `rootwelld`
  runs only on Linux.
- Optional passkeys (WebAuthn, C113) stand in for the phone code, at sign-in
  and as a fresh code. A passkey signs only for the name it was made on, so a
  look-alike site cannot reuse its answer; it needs the person verified by a
  fingerprint, face or PIN, and a challenge of 32 random bytes kept with the
  session, for one purpose, two minutes and one answer. The account keeps
  only public keys, up to ten. Attestation is not checked, so Rootwell takes
  the authenticator's word that it verified the person. Adding or removing
  one needs a fresh code and ends the account's other sessions, and a setup
  code that replaces the sign-in removes them all. TOTP stays mandatory and
  a way in, so it can still be phished. Browsers allow no passkeys on an IP
  address.
- Explicit Check uploads to the operator's own daemon, not third parties.
  Certificate <=96 KiB, key <=64 KiB, JSON <=1200 KiB, passwords <=256 bytes.
  Single strict certificate; strict bounded PKCS#8/PKCS#1/SEC1 or supported
  encrypted PKCS#8. Mixed/private certificate inputs, unsupported formats,
  CA private custody, unmatched keys, ambiguous JSON and duplicates refuse.
- One slot for expensive work: password checks and file parsing. Private
  export needs a fresh code: a phone code, a recovery code or a passkey from
  the last ten minutes (C111); wrong codes and refused passkey answers count
  against the account's and the address's failure limits, and five end the
  session. Authenticated Check/Save have bounded inputs and concurrency
  but no separate per-operation rate budget yet.
  Listing opens no key, and there is no background monitor. The list holds at
  most 500 certificates; authenticated operator resource exhaustion remains a
  release-review item.
- Save revalidates certificate/key identity and the exact displayed
  generation; a stale page gets 409. Changing source/password invalidates
  preview. Prepare produces no partial result on failure. Both records are
  written in one vault transaction; a failed write keeps nothing.
- Vault sealing: each record is sealed with AES-256-GCM under its own random
  key, wrapped under a key derived from the instance key with HKDF-SHA256, and
  bound to the vault, the record's kind, its ID and its revision. Record IDs
  are HMACs of the fingerprint. A record moved to another certificate's ID, a
  changed byte or revision, and unknown fields refuse before public output.
  The key record is opened only for a download.
- Lists include only public metadata, key presence and key status. No
  input/output password, filename or raw decoder error is persisted or
  returned. Browser renders only fixed error messages and textContent. No
  browser storage.
- Private ZIP download requires a fresh code from the last ten minutes, the
  same signed-in session at the same account revision, the generation and the
  fingerprint, then session/cancellation checks again before output. Exported
  key is password-encrypted PKCS#8 under the previously reviewed PBKDF2/AES
  profile; certificate stays public, ZIP is not encrypted. Output password
  must meet the existing encrypted-export policy: 20–128 non-space ASCII
  characters. Prefer a fresh
  randomly generated password; length alone is not an entropy guarantee.
  No plaintext secret custody export or key reveal route exists here.
- Browser work is bounded/timed; changed/hidden/pagehide state aborts requests,
  clears owned bytes/passwords and discards late responses. Cancellation after
  Save transmission cannot guarantee the server did not commit. An uncertain
  result requires refresh. Browser downloads have no overwrite/permission claim.
- Note changes leave the key record alone. Deleting a certificate that has a
  key needs a fresh code from the last ten minutes. Delete removes both
  records in one transaction, not source files, backups or copies of the
  data directory.
- Backups (C114): the Installation page downloads a copy of the whole vault,
  made in one read transaction while the service runs, after a fresh code;
  up to 64 MiB, and a larger vault is copied on the server with the service
  stopped. It holds every key and account sealed, and never the instance
  key, so it opens only with the key the vault had when it was made.
  `rootwelld restore` writes a backup only into an empty data directory and
  keeps it only if it opens with the key file or its recovery code.
  `rootwelld key-rotate` moves the vault to a new instance key in one
  transaction, after its new recovery code is confirmed as saved; the vault
  then refuses the old key. `key-export` prints the key's recovery code
  again. All three need an interactive terminal, and `key-rotate` and
  `key-export` refuse while the service holds the vault (`RECOVERY.md`).

## Closed staging requests — ADR 0063

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088).

## Manual test renewal — ADR 0064

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088).

## Residuals and acceptance evidence

The renewal result of ADR 0065 was retired on 23 November 2026 with the
session-bound ACME automation (ADR 0088).

No reliable runtime/OS zeroization, external anti-rollback anchor,
cryptographic erasure, CA signer custody, HSM isolation or production
assurance is provided. The instance key file, or its recovery code,
together with a backup or a copy of the data directory opens every record it
holds. A backup keeps the keys it held, even after they are deleted, and a
key rotation cannot reach it: it still opens with the old key and its old
code, so that code needs the same care for as long as such backups are kept.
After a rotation the old key opens no record of the current vault, but it
still derives the index and one-time-code keys the vault keeps, so with the
current file it can tell whether a certificate it already knows is kept
there. A backup downloaded from the page passes through the browser and
lands where the browser saves files. An older `rootwell.db` swapped in
whole, or an older backup restored, is not detected. Losing both the key
file and the recovery code loses every saved certificate and key. The
account's password, its phone codes, its passkeys and the export password do
not protect a compromised host. On
`localhost` the session cookie is shared with other local ports (C112).
Obtain independent specialist review before
real-user custody. Do not import production secrets into a development build.

Evidence: certificatepair generated RSA/ECDSA/Ed25519 and encrypted-key tests;
vault and certstore sealing, atomicity, refusal and record-binding tests; Linux
API check/save/key-later/download/delete/restart integration; the container
volume drill; strict HTTP request tests; bounded stale/hidden/late/read-only UI
tests, account, session, limit and fresh-code tests, HTTPS and serving
authority tests, passkey tests with two fuzz targets, backup, restore,
rotation and export tests, and actual public WASM tests. Invariants C68,
C69, C107 and C108–C114 name them.
Exact commands and deliberate sabotage outcomes are recorded in the PR and
ADR. Green CI and self-review are not independent audit.
