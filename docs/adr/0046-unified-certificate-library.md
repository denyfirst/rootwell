# ADR 0046 — One certificate library with optional matched-key custody

Date: 2026-10-07. Status: implemented for development; required CI gates and
independent release audit apply, not production approval.

## Decision and authorization

The operator requested a single Certificates section rather than separate
Inventory and Vault choices. Certificate + optional private key + optional
service note form one visible record. SSH, PGP and interactive remote access
are not part of this increment; their earlier roadmap entries are deferred to
a separate future product decision. Public-only storage remains useful.

The existing public-only Workbench and public import API keep refusing secrets.
A separate ready-session, same-origin certificate-library API performs an
explicit Check and an explicit Save on the operator's own loopback daemon.
The UI must explain that Check sends selected material to that daemon; this
is not the offline Workbench. No third-party request or remote listener is added.
Native Windows refuses custody; its preview is synthetic and read-only.

## Custody boundary

One strict PEM/DER certificate (maximum 96 KiB input, 64 KiB DER) may be paired
with one strict key (maximum 64 KiB). Existing bounded PKCS#8/PKCS#1/SEC1 parsing
and the reviewed encrypted-PKCS#8 decoder are reused. Existing-key passwords
are transient; filenames and raw decoder errors are never reflected. A key
must match the certificate's canonical public key. CA-key custody is refused.
Match is not trust, revocation, deployment or proof of uncompromised custody.

Save rechecks the immutable selected inputs, the displayed certificate identity
and image generation. There is no check token that bypasses validation. One
atomic authenticated image contains the public record and a separate encrypted
key attachment, identified by the exact certificate fingerprint. Attachment
encryption uses the existing AES-256-GCM codec under a purpose-separated HKDF
key. Listing/monitoring/history return only a key-present boolean, never key
bytes. Public note corrections preserve attachments; deletion removes both
from the current image. Existing complete-image backups include attachments.
Older binaries must refuse attachment-bearing images instead of losing keys.

Private download requires fresh instance-password authentication under the
existing global attempt/KDF limits, exact ready-session revision, generation
and fingerprint. The initial supported download is a public certificate PEM,
or ZIP with certificate PEM and password-encrypted PKCS#8 key. The ZIP itself
is not encrypted. Plaintext-key formats remain in the separately reviewed
Workbench; there is no hidden plaintext custody export. Download filenames
are generated, not derived from notes/domains. Passwords are not saved in
browser storage, URLs, logs, history or the encrypted record.

## UI and evidence gates

One Certificates menu entry; no second Vault destination. Compact rows show
identity, server-clock expiry and key-present state. Details reveal optional
notes and existing Workbench operations. Notes remain unverified declarations.
Changing a file/password clears the checked state. Hidden/navigation state
cancels work and clears owned buffers/password fields. A stale/uncertain Save
requires refresh; cancellation after transmission does not undo a commit.

Required evidence: generated RSA/ECDSA/Ed25519 pair round trips; mismatch,
encrypted wrong-password, malformed/mixed/oversized/CA refusal; unchanged
storage on failure; no key/password in lists/history/errors/images; ciphertext
tamper/swap/context refusal; metadata/delete/backup/restore preservation;
anonymous/setup/cross-origin/query/duplicate-JSON/stale/session-revocation
refusal; fresh reauthentication and export-password policy; positive and
negative deliberate sabotage; UI reset/late-result/no-storage tests; Linux
durable/race integration and required CI checks.

## Residual risks

This is single-operator development custody, not multi-user authorization or
production deployment. Loopback HTTP is not a remote TLS transport guarantee.
The trusted daemon and browser necessarily see selected secrets in memory;
runtime/OS copies, swap, extensions, screenshots and compromised hosts cannot
be reliably erased. Source files and old snapshots retain keys. HKDF separation
does not provide cryptographic erasure or external anti-rollback protection.
Weak instance/output passwords, manual backups and session-bound monitoring
remain operator risks. Independent specialist review is required before
real-user custody; no audited or universal-format claim is made.

## Reproducible development evidence

- `go test -shuffle=on ./...` on Windows; Linux custody runtime/race and
  supported-platform vet are required CI, not a Windows runtime claim.
- `go vet ./...`, module tidy/verify, `go build -trimpath ./...`, pinned
  staticcheck v0.7.0, gosec v2.28.0, govulncheck v1.6.0, actionlint v1.7.12.
- `node scripts/test-certificate-library.mjs`, existing inventory/demo/UI
  tests and actual Workbench WASM tests. Visual fixture is read-only and
  displays synthetic public records, not successful private storage.
- Deliberate sabotage: ignoring the public-key match caused
  `TestPrepareCertificatePairsAndRefusals` to fail on unrelated RSA, EC and
  Ed25519 keys; always rejecting the same match caused all valid pairs to fail.
  Enabling Save before Check and permanently disabling Save each caused the
  new UI VM test to fail at the appropriate assertion. All mutations restored;
  positive/refusal tests rerun. This proves those assertions detect both
  directions, not that every security defect has been excluded.
- Separate adversarial maintainer self-review is recorded in the PR after
  implementation. It is not an independent audit. Custody CPU/host/memory,
  output-file policy, manual backups and old-snapshot risks stay explicit in
  [the threat model](../CERTIFICATE-CUSTODY-THREAT-MODEL.md).
