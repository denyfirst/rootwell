# ADR 0033: Offline encrypted PKCS#8 export from a bounded PFX

**Status:** accepted for the Linux development CLI, not production custody

**Date:** 2026-09-30

## Decision

`rootwell pfx-extract-key --input <file> --sha256 <matching-fingerprint>
--output <new-private-file>` exports only the private key that matches the
selected non-CA certificate from the authenticated modern PFX profile. It
never prints a key or emits plaintext key bytes to a file. The output is one
`ENCRYPTED PRIVATE KEY` PEM block containing PBES2/PBKDF2-HMAC-SHA-256 with
600,000 iterations, a 16-byte random salt, and AES-256-CBC. The output
password is new, terminal-entered twice, 20–128 printable ASCII bytes, and
must differ from the PFX password. A high-entropy randomly generated password
is required in practice; length is not a proof of entropy. The instance login
password must not be reused.

The CLI reads at most 1 MiB once, checks the PFX profile before prompting,
then uses the same 10-second one-shot process deadline as inspection. Full
strict `pfxinspect.Inspect` succeeds before `DecodeChain` is allowed to expose
the key inside this package. The returned leaf must be byte-identical to the
inspected matching certificate and the key's public half must match. The
encrypted output is decoded and its public half checked before publication.
`secretfile.WriteNew` requires Linux, an existing owner-private output
directory, a new destination, private permissions, and staged readback/sync.
On any uncertain post-link state, the caller receives an explicit error and
must inspect the destination before retrying.

## Dependency review

The Go standard library marshals unencrypted PKCS#8 and PKCS#1 but does not
provide encrypted PKCS#8 output. We use `github.com/youmark/pkcs8` pinned at
`v0.0.0-20240726163527-a2c0da244d78` only to encode the selected key and to
read back Rootwell's own freshly generated output. It is MIT-licensed. Its
direct external crypto dependency is `golang.org/x/crypto`, already selected
by Rootwell at a newer version than the library's minimum. The chosen options
are explicit; its weaker 10,000-iteration/8-byte-salt defaults are never used.
No new ASN.1, KDF, or encryption primitive is implemented by Rootwell.

The upstream's last published module snapshot is from July 2024, so ongoing
maintenance is a concern. Its parser does not cap attacker-supplied KDF work
and its AES-CBC decrypt path does not remove padding before handing plaintext
to Go's X.509 parser. Rootwell does **not** use it to import arbitrary
encrypted key files: the readback sees only bytes generated with fixed
parameters in the same call. This does not make the dependency risk vanish.
`govulncheck` and upstream advisory review remain gates; independent audit is
required before first real-user release. OpenSSL integration tests decode the
output independently of the new library. The implementation owner should
replace or update this encoder if a better-maintained interoperable option
becomes available.

Primary references checked 2026-09-30: [Go X.509 APIs](https://pkg.go.dev/crypto/x509),
[upstream pkcs8 source/license](https://github.com/youmark/pkcs8), and
[package API and version](https://pkg.go.dev/github.com/youmark/pkcs8).

## Boundaries and remaining risk

The first key export is deliberately Linux CLI only. There is no browser,
daemon, inventory, vault, network, stdout/JSON, Windows ACL, or Porch path.
The public Convert picker continues to reject PFX and private keys. A later,
separate encrypted-only browser private-key picker is scoped by ADR 0034; it
does not import PFX.
PKCS#8 encryption is password-based and AES-CBC does not authenticate the
ciphertext; a weak password or tampering cannot be ruled out by the format.
Runtime copies, swap, backups, terminal compromise, and a malicious local
administrator remain outside the confidentiality claim. The PFX encrypted-
safe hidden-KDF risk from ADR 0031 remains; a timeout is safe only in the
one-shot CLI process. The format does not establish certificate trust,
hostname validity, revocation, or deployment state.

Plaintext PKCS#1 (`RSA PRIVATE KEY`) output and visual key reveal are separate
opt-in capabilities, not aliases for this encrypted export. FortiGate's PFX
and separate certificate/key import modes do not establish a universal
"Fortinet" profile for FortiWeb, FortiNAC, or every firmware version.
