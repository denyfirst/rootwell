# ADR 0030: Pinned PKCS#12 encoder for offline creation

**Status:** accepted for the Linux development CLI, not production custody

**Date:** 2026-09-29

## Decision

Use `software.sslmate.com/src/go-pkcs12` v0.7.3 only behind
`internal/pfxcreate` for the first offline PFX creation increment. Use the
explicit `Modern2023.WithIterations(100000)` profile, never the moving
`Modern` alias, `Legacy`, `LegacyDES`, `LegacyRC2`, or `Passwordless` encoders.
The profile uses PBES2/PBKDF2-HMAC-SHA-256/AES-256-CBC and an HMAC-SHA-256
container MAC. PKCS#12 is an interoperability container, not a vault.

The Go standard library has no PKCS#12 encoder. `golang.org/x/crypto/pkcs12`
is frozen/read-only. We will not implement the container, ASN.1 encoding, or
password encryption ourselves. The dependency is BSD-3-Clause and actively
maintained enough to have a June 2026 v0.7.3 release. An upstream
authentication-bypass advisory affected v0.6.0–v0.7.1 and was fixed in
v0.7.2; v0.7.3 is above the patched version. A wrong-password regression is
part of Rootwell's tests, and `govulncheck` remains a required gate.

The module's indirect `golang.org/x/crypto` requirement is selected at
v0.57.0 by Rootwell rather than the library's older v0.11.0 minimum. The
`go.mod`/`go.sum` checksums and `go mod verify` pin the imported code.
`govulncheck` reports one module-level warning for the unmaintained
`x/crypto/openpgp` package, which Rootwell does not import or call. This is
recorded rather than misreported as zero module warnings. The maintainer owns
upstream advisory monitoring and reviewed version updates; no automatic
dependency upgrade is authorized.

## Scope and safety conditions

- CLI only, Linux only, no network, no browser/server import, and no vault.
- One strict non-CA leaf and matching unencrypted RSA/ECDSA key. Rootwell's
  existing TLS algorithm policy applies. Ed25519 PFX creation is unsupported
  until the selected library's round trip is verified.
- Optional strict PEM issuer bundle must be nearest-issuer-first, signature
  linked, duplicate-free, and exclude a self-signed root. Included issuers do
  not become trusted anchors.
- A fresh terminal-entered 20–128-byte printable ASCII password is required
  twice. Length alone cannot prove entropy; operators must use a random value.
  The instance login password must not be reused.
- Output is published only into an existing owner-private Linux directory as
  a new 0600 file after encode/decode equivalence and read-back. Existing
  paths/symlinks are not replaced. A post-link sync failure is uncertain, not
  success. Windows refuses until an ACL-specific implementation is tested.
- No plaintext key output, stdout key/PFX bytes, password argv/env/URL, weak
  legacy fallback, or automatic trust/deployment claim.

Rootwell verifies its own encoded result and a Linux test asks OpenSSL to
parse it with the fixture password passed by file descriptor, not argv.
Malformed, mismatch, wrong-password, tampered, permissions, overwrite and
non-TTY paths are tested. The same-library decode is not an independent
cryptographic audit; OpenSSL interop is an additional check. External audit
remains required before first real-user release under `ENGINEERING.md`.

## Remaining risks and replacement plan

PKCS#12's password-based KDF is not memory-hard; even 100,000 iterations do
not rescue a weak password. Go strings and crypto/runtime copies cannot be
reliably zeroized. A malicious same-user process, privileged host, crash dump,
swap, backup, or terminal compromise can expose keys. A hard-link-unsupported
filesystem fails closed. The early CLI does not support encrypted input keys,
PFX import, key extraction, Windows secret output, or appliance-specific
compatibility profiles. Later profiles require explicit decisions and tests.

The library is isolated in `internal/pfxcreate`. Replacing it requires the
same exact-input/output, wrong-password, OpenSSL, and resource-limit tests;
public CLI and browser contracts need not change.

Primary sources checked 2026-09-29:

- [SSLMate package documentation and explicit encoder profiles](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12)
- [Upstream repository, maintenance, and BSD-3-Clause license](https://github.com/SSLMate/go-pkcs12)
- [Upstream security advisory GHSA-mpwr-8vm7-h73f](https://github.com/SSLMate/go-pkcs12/security/advisories/GHSA-mpwr-8vm7-h73f)
- [Go x/crypto PKCS#12 documentation](https://pkg.go.dev/golang.org/x/crypto/pkcs12)
