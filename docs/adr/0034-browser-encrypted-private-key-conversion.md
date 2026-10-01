# ADR 0034: First browser private-key conversion remains encrypted-only

**Status:** accepted for development Workbench; not a release or vault approval

**Date:** 2026-09-30

This record describes the first increment. ADR 0035 separately authorizes
bounded encrypted PKCS#8 input and explicit plaintext targets; the
encrypted-only restrictions below remain historical for that first increment.

## Context and decision

The user-facing product is the self-hosted UI, not a collection of CLI-only
converters. Format support is based on cryptographic object and encoding, not
an appliance brand. The first browser secret-bearing increment accepts exactly
one explicitly chosen, unencrypted PKCS#8, RSA PKCS#1, or EC SEC1 key in strict
PEM/DER, with the existing 64 KiB and 16,384-bit bounds. Ed25519 is accepted
in PKCS#8. It shows only input format, algorithm, size/curve, and a SHA-256
fingerprint of the canonical public key. On a separate explicit click it
re-reads and reparses that file, checks the full displayed public fingerprint,
and exports only new password-encrypted PKCS#8 PEM. The same pinned encoder and
explicit 600,000-iteration PBKDF2-HMAC-SHA-256/AES-256-CBC profile as ADR 0033
are used; only self-generated output is decoded for equivalence checking.
The browser does not accept attacker-supplied encrypted PKCS#8. No plaintext
private key, PFX, key reveal, or vault save is exposed by this increment.

The existing public Inspect and Verify inputs remain public-only and separate
from the private Convert file picker. All selected bytes are processed by the
same-origin WebAssembly core and are never sent to the inventory/daemon API or
a third party. The file-reading script has no network, persistent storage,
dynamic-code, service-worker, or markup-injection capability; the asset loader
may fetch only the same-origin WebAssembly asset and has no selected-file or DOM
capability. Browser output is validated as an encrypted-key response and
requested as a browser-managed download with a random filename. Key bytes,
password bytes, and encrypted output buffers are cleared on a best-effort basis.
The password inputs are cleared on use and file selection change. An immutable
JavaScript password string and runtime copies may remain until collection.

## Threats and non-claims

The self-hosted `rootwelld` route protects the Workbench with the existing
ready-session gate and no-store headers; directly serving the static assets is
an **unauthenticated development preview**, not a private workstation vault.
No per-user key ownership/RBAC or durable private-key storage exists yet.
An operator chooses their own input file; Rootwell cannot establish that they
are authorized to own it. A malicious extension, modified same-origin asset,
compromised browser/OS, screen capture, swap, crash dump, or backup may obtain
secret material. CSP and zero-upload tests reduce exposure, not eliminate it.
The browser/OS controls the download destination and permissions; Rootwell
cannot promise CLI-style private file ACLs or no overwrite. This is why only
encrypted output is enabled first. The 20–128 printable-character rule is not
an entropy guarantee; users should choose a fresh random password and not
reuse the Rootwell sign-in password. PBKDF2/AES-CBC has no ciphertext
authentication. This operation establishes format equivalence, not certificate
trust, signing capability, algorithm strength, revocation, or deployment.

## Next format sequence

1. Extend the same Convert screen with compatible targets only: RSA PKCS#1,
   EC SEC1, and PKCS#8 PEM/DER. Plaintext output needs an explicit warning,
   new browser-download tests, and an honest save-permission non-claim.
2. Add bounded PFX/PKCS#12 import and creation with separate password handling
   and worker/time-limit isolation for its hidden encrypted-safe KDF risk.
3. Add deliberate reveal with fresh PFX password for PFX input or instance
   reauthentication for a future stored vault key, short auto-hide, and no
   log/history/storage path.
4. Add optional, product/version-specific appliance recipes only where a
   tested import format differs; no generic vendor mode overrides the format
   engine. JKS, OpenSSH, and PGP are separate object families, not implied by
   the X.509 conversion matrix.

This change receives local positive/refusal/malformed/stale tests, WebAssembly
interop, static/security checks, signed PR, and adversarial self-review. It
still requires independent audit before real-user release.
