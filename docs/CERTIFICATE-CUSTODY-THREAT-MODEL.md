# Certificate library custody — development boundary

Date: 2026-10-07, updated 2026-11-23 for Phase 3a, part 2. Decisions:
[ADR 0046](adr/0046-unified-certificate-library.md), ADR 0047, ADR 0048,
ADR 0087 and [ADR 0088](adr/0088-keybash-foundation.md). Single operator,
Linux loopback daemon only; not externally audited or ready for real-user
secret custody. Porch and the offline Workbench remain separate.

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

Matching-pair ZIP refuses a mismatch. Encrypted key-only PEM uses the same
sign-in password check, shared attempt/KDF budgets, exact generation and
separate output-password policy. Public bundle download includes supplied roots
without assigning trust. The archive remains unencrypted. ADR 0087 prepares
PFX contents locally; original PFX containers are not stored. Plaintext custody
export, remote listener, multiuser policy and production claims remain excluded.

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
not new certificate/notes/status. Save needs the current sign-in password
through the shared attempt/KDF budget; the vault write repeats validation and
keeps the certificate, bundle and notes as they were, with the key as a record
of its own. Lost confirmation after a committed write is uncertain, including
logout/cancellation. The Convert handoff of ADR 0048 was retired on
22 November 2026 with the page rebuild: Convert now works only on files a
person chooses, and Certificates downloads a saved certificate and key itself.
See [ADR 0048](adr/0048-saved-key-attachment-and-convert-handoff.md).

The staging issuance paths of ADRs 0061 and 0062, which wrote checked staging
pairs into the old image, were retired on 23 November 2026 with the
session-bound ACME automation (ADR 0088). Renewal returns in Phase 3c.

Certificate DER, optional matching private key, key-input password, sign-in
password, output password, the instance key file, its recovery code, copies of
the data directory, and internal service notes are sensitive. Public key is
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

- Ready sessions only: mandatory setup-password change, exact loopback
  host/origin, same-origin custom header, POST-only operation, no query fields,
  no-store responses and existing CSP. Without a vault (any host but Linux)
  the routes say saving is off.
- Explicit Check uploads to the operator's own daemon, not third parties.
  Certificate <=96 KiB, key <=64 KiB, JSON <=1200 KiB, passwords <=256 bytes.
  Single strict certificate; strict bounded PKCS#8/PKCS#1/SEC1 or supported
  encrypted PKCS#8. Mixed/private certificate inputs, unsupported formats,
  CA private custody, unmatched keys, ambiguous JSON and duplicates refuse.
- One expensive parse/KDF slot; private export uses the shared five-attempts
  per minute authentication limit. Authenticated Check/Save have bounded
  inputs and concurrency but no separate per-operation rate budget yet.
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
- Private ZIP download requires the current sign-in password, exact session
  revision, generation and fingerprint, then fresh session/cancellation checks
  before output. Exported key is password-encrypted PKCS#8 under the previously
  reviewed PBKDF2/AES profile; certificate stays public, ZIP is not encrypted.
  Output password must differ from the sign-in password and meet the existing
  encrypted-export policy: 20–128 non-space ASCII characters. Prefer a fresh
  randomly generated password; length alone is not an entropy guarantee.
  No plaintext secret custody export or key reveal route exists here.
- Browser work is bounded/timed; changed/hidden/pagehide state aborts requests,
  clears owned bytes/passwords and discards late responses. Cancellation after
  Save transmission cannot guarantee the server did not commit. An uncertain
  result requires refresh. Browser downloads have no overwrite/permission claim.
- Note changes leave the key record alone. Delete removes both records in one
  transaction, not source files or copies of the data directory. Until Phase
  3b, a backup is a copy of the data directory made with the service stopped,
  and the key file never goes with it (`RECOVERY.md`).

## Closed staging requests — ADR 0063

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088).

## Manual test renewal — ADR 0064

Retired on 23 November 2026 with the session-bound ACME automation (ADR 0088).

## Residuals and acceptance evidence

The renewal result of ADR 0065 was retired on 23 November 2026 with the
session-bound ACME automation (ADR 0088).

No reliable runtime/OS zeroization, external anti-rollback anchor,
cryptographic erasure, CA signer custody, remote TLS gateway, HSM isolation or
production assurance is provided. The instance key file, or its recovery code,
together with a copy of the data directory opens every record. A copy of the
data directory keeps the keys it held, and an older `rootwell.db` swapped in
whole is not detected. Losing both the key file and the recovery code loses
every saved certificate and key. The sign-in password and the export password
do not protect a compromised host. Obtain independent specialist review before
real-user custody. Do not import production secrets into a development build.

Evidence: certificatepair generated RSA/ECDSA/Ed25519 and encrypted-key tests;
vault and certstore sealing, atomicity, refusal and record-binding tests; Linux
API check/save/key-later/download/delete/restart integration; the container
volume drill; strict HTTP request tests; bounded stale/hidden/late/read-only UI
tests and actual public WASM tests. Invariants C68, C69 and C107 name them.
Exact commands and deliberate sabotage outcomes are recorded in the PR and
ADR. Green CI and self-review are not independent audit.
