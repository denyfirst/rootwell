# ADR 0038: PFX creation accepts a bounded encrypted input key

**Status:** accepted for development; release audit pending

**Date:** 2026-10-05

The existing Create a PFX form accepts the encrypted PKCS#8 PEM/DER profile
already supported by private Convert: PBES2, PBKDF2-HMAC-SHA256, AES-256-CBC,
bounded salt/IV/ciphertext and at most 1,000,000 iterations. Legacy encrypted
PEM, other KDF/cipher profiles, mixed objects and trailing data remain refused.
No new dependency or encryption primitive is introduced.

The operator enters the current key password separately from the new PFX
password. The current password may be at most 256 UTF-8 bytes and must be empty
for an unencrypted key. Password reuse is refused in the UI and Go core.
The PFX output retains the existing 20–128 non-space printable ASCII policy.
The same one-shot PFX worker receives the input password as its operation-specific
second password, with the existing 90-second output deadline and abort behavior.
The key is never downloaded in plaintext as an intermediate step.

The private converter lends a strict-validated parsed key to the PFX encoder
for one callback. The encoder independently compares canonical public keys,
checks certificate policy and issuer order, and verifies the encoded round-trip.
Owned password/file/output buffers are cleared best-effort; fields are cleared
when inputs change and after operation submission. JS/Go/runtime/OS copies,
extensions, browser downloads and a compromised host retain the limitations
described in ADR 0037. This change adds no trust decision, storage or network call.

Evidence includes RSA/ECDSA and PEM/DER success, wrong/missing password,
unexpected password on a plaintext key, reuse, mismatch, malformed input,
invalid chain and limits. The WASM test consumes an independently encoded
encrypted key from Node's OpenSSL-backed crypto implementation. UI tests verify
that the password is forwarded only for the requested creation, that buffers
are cleared, and that a late result after password change downloads nothing.
