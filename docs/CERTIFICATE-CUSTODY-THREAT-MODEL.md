# Certificate library custody — development boundary

Date: 2026-10-07. Decision: [ADR 0046](adr/0046-unified-certificate-library.md).
Single operator, Linux loopback daemon only; not externally audited or ready
for real-user secret custody. Porch and the offline Workbench remain separate.

ADR 0047 updates this historical matched-only increment. New imports accept
one primary certificate or related public PEM bundle (16 certificates, 768 KiB;
JSON 1200 KiB), plus one strict optional key. Check is optional; Save repeats
validation. Computed mismatch may be retained only with explicit acknowledgement
as a loose attachment. Malformed/password/CA-key failure still refuses. Included
issuer signatures are checked, but roots are not trusted, and neither names,
time, revocation nor deployment is verified. Ambiguous primary selection requires
an explicit exact fingerprint. Unrelated or ambiguous issuer collections refuse.

A separate `materials` manifest field and purpose-separated encrypted payload
hold canonical public DER collection, optional PKCS#8 key and mismatch consent.
No client status, password, filename or raw input is persisted. Every material
is authenticated/reparsed, constrained to its primary record and its match
status recomputed before metadata output. Legacy key attachments keep strict
matched-only validation; duplicate/orphan/cross-context material refuses.
Old binaries refuse the new field. Atomic note/delete/full backup/restore must
preserve these semantics. Authenticated complete-image rollback is still possible.

Matching-pair ZIP refuses loose mismatch. Encrypted key-only PEM uses the same
fresh instance authentication, shared attempt/KDF budgets, exact generation and
separate output-password policy. Public bundle download includes supplied roots
without assigning trust. The archive remains unencrypted. No PFX custody,
plaintext custody export, remote listener, multiuser policy or production claim.

## Assets and trust

ADR 0048 adds only a key to an existing public-only record, never replacement.
Check/Save accept exact fingerprint/generation and one strict key, not new
certificate/notes/status. Save uses fresh instance authentication through the
shared attempt/KDF budget; the locked writer repeats validation and atomically
retains certificate/bundle/provenance/order/notes with a key-added history event.
Mismatch consent, legacy key refusal, metadata/deletion/full restore and manual
backup requirements remain. Lost confirmation after a committed write is
uncertain, including logout/cancellation. The public Convert handoff transfers
only selected public DER, not its key/bundle/notes or trust authority. Private
conversion requires explicit encrypted export and input selection. See
[ADR 0048](adr/0048-saved-key-attachment-and-convert-handoff.md).

Certificate DER, optional matching private key, key-input password, fresh
instance password, output password, image key, recovery code, complete backups,
and internal service notes are sensitive. Public key is part of the selected
certificate, not a second standalone input. Notes declare intended usage;
matching a key proves mathematical identity, not trust or deployment.

Browser, same-origin scripts, authenticated daemon, Go/JS runtimes and host are
trusted. Files, names, JSON, timings, client metadata, storage images and old
sessions are hostile inputs. Host administrators, compromised daemons/browser
extensions and runtime copies can access secrets; encryption at rest does not
protect against them. This is not end-to-end encryption or multi-user RBAC.

## Controls and refusal paths

- Ready sessions only: mandatory setup-password change, enrolled installation,
  exact loopback host/origin, same-origin custom header, POST-only operation,
  no query fields, no-store responses and existing CSP.
- Explicit Check uploads to the operator's own daemon, not third parties.
  Certificate <=96 KiB, key <=64 KiB, JSON <=240 KiB, passwords <=256 bytes.
  Single strict certificate; strict bounded PKCS#8/PKCS#1/SEC1 or supported
  encrypted PKCS#8. Mixed/private certificate inputs, unsupported formats,
  CA private custody, unmatched keys, ambiguous JSON and duplicates refuse.
- One expensive parse/KDF slot; private export uses the shared five-attempts
  per minute authentication limit. Authenticated Check/Save have bounded
  inputs and concurrency but no separate per-operation rate budget yet.
  Revalidation of all keys during list/monitor can cost CPU up to image limits;
  authenticated operator resource exhaustion remains a release-review item.
- Save revalidates certificate/key identity and exact displayed generation;
  changing source/password invalidates preview. Prepare produces no partial
  result on failure. Both objects enter one durable atomic authenticated image.
- Separate attachment encryption: HKDF-SHA256 purpose/record domain separated
  from public record encryption; existing AES-256-GCM with installation,
  record and generation context. Entire manifest is authenticated first.
  Every attachment must match a unique non-CA record; orphan, duplicate,
  changed-context and tampered ciphertext refuse before public output.
- Lists/history include only public metadata and key-presence boolean. No
  input/output password, filename or raw decoder error is persisted or returned.
  Browser renders only fixed error messages and textContent. No browser storage.
- Private ZIP download requires current instance password, exact session
  revision, generation and fingerprint, then fresh session/cancellation checks
  before output. Exported key is password-encrypted PKCS#8 under the previously
  reviewed PBKDF2/AES profile; certificate stays public, ZIP is not encrypted.
  Output password must differ from instance password and meet the existing
  encrypted-export policy: 20–128 non-space ASCII characters. Prefer a fresh
  randomly generated password; length alone is not an entropy guarantee.
  No plaintext secret custody export or key reveal route exists here.
- Browser work is bounded/timed; changed/hidden/pagehide state aborts requests,
  clears owned bytes/passwords and discards late responses. Cancellation after
  Save transmission cannot guarantee the server did not commit. An uncertain
  result requires refresh. Browser downloads have no overwrite/permission claim.
- Existing metadata mutations preserve attachments. Delete removes both from
  current image, not source files/history/old backups. Complete snapshot/restore
  authenticates and preserves attachments. Downgrade refuses the new manifest.
  Backup remains manual. A new full backup is required after every mutation.

## Residuals and acceptance evidence

No reliable runtime/OS zeroization, external anti-rollback anchor, cryptographic
erasure, CA signer custody, always-on monitoring credential, remote TLS gateway,
HSM isolation or production assurance is provided. A leaked instance data key
opens public records and attachments despite purpose separation. Old complete
backups retain old keys. Separate installation password and export password do
not protect a compromised host. Obtain independent specialist review before
real-user custody. Do not import production secrets into the Windows demo.

Evidence: certificatepair generated RSA/ECDSA/Ed25519 and encrypted-key tests;
inventorystore atomicity/preservation/deletion/tamper/context tests; Linux API
check/save/step-up/export/full restore integration; strict HTTP request tests;
bounded stale/hidden/late/read-only UI VM tests and actual public WASM tests.
Exact commands and deliberate sabotage outcomes are recorded in the PR and
ADR. Green CI and self-review are not independent audit.
