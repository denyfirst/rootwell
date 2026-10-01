# ADR 0035: Bounded encrypted PKCS#8 import and explicit plaintext export

**Status:** accepted for development Workbench; independent release audit pending

**Date:** 2026-10-01

The private Convert picker now accepts one encrypted PKCS#8 PEM/DER key in
addition to the strict unencrypted inputs of ADR 0034. The current input
password and new output password are separate; neither is saved or reused.
Inspection clears the current password, so export asks for it again and
rechecks the full public-key fingerprint of the freshly read source. Wrong
password, malformed input, changed key, unsupported profile, and mismatched
target produce no download.

Untrusted encrypted input is preflighted before the pinned `youmark/pkcs8`
decoder runs. Only one strict EncryptedPrivateKeyInfo with PBES2,
PBKDF2-HMAC-SHA-256 (8–32 byte salt, 1–1,000,000 iterations), AES-256-CBC
(16-byte IV), one bounded block-aligned ciphertext, and at most 64 KiB total
input is accepted. Unsupported algorithms and legacy PEM encryption fail
closed. After decryption, the key is re-encoded and passed through Rootwell's
strict private-key parser and size/algorithm checks. The imported key's
original container metadata, attributes, and password are not preserved.
The low input-iteration floor is for reading existing weakly protected files,
not an endorsement of their storage security. New encrypted output continues
to use 600,000 iterations and a new 20–128 printable-character password.

Encrypted PKCS#8 PEM is the default output. Deliberately selecting no password
requires an additional checkbox and produces PKCS#8 PEM/DER, RSA PKCS#1
PEM/DER, or EC SEC1 PEM/DER as compatible with the input key. Ed25519 has only
PKCS#8 targets. The Go core reparses plaintext output and checks its public
fingerprint before publication. The UI warns that browser-managed downloads
have no Rootwell-controlled file permissions and may persist in Downloads or
backups. No automatic Inventory/Vault save, upload, reveal, PFX, or Porch
integration is added.

The imported CBC container is not authenticated, and the pinned decoder is
not constant time. Malformed input and tested wrong passwords refuse, but
tampering may go undetected; parsing does not prove source authenticity or
integrity. KDF work is bounded but runs in the current browser WebAssembly
context; a dedicated worker/deadline remains a hardening task before wider
encrypted-container support. JavaScript strings, Go runtime copies, browser
extensions, OS memory, and downloaded plaintext copies cannot be reliably
erased by Rootwell. A public release still requires independent audit.
