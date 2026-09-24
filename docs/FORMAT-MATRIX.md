# Workbench v0.1 format matrix

This is a scope boundary, not a promise that every listed operation already
exists. `planned` means implementation and its security tests are still
required. Anything not listed is unsupported and must fail explicitly.

| Object | Encoding/container | Inspect | Match | Verify | Convert/write | v0.1 notes |
|---|---|---:|---:|---:|---:|---|
| X.509 certificate | PEM | implemented (single) | implemented | implemented (TLS server) | planned | exactly one header-free `CERTIFICATE` block |
| X.509 certificate | DER | implemented (single) | implemented | implemented (TLS server) | planned | exactly one certificate; trailing data rejected |
| Certificate chain | PEM bundle | planned | n/a | implemented (explicit roots/intermediates) | planned | strict role separation; order is not a trust signal |
| CSR / PKCS#10 | PEM | planned | planned | n/a | planned | signature checked after parsing |
| CSR / PKCS#10 | DER | planned | planned | n/a | planned | trailing data rejected |
| RSA private key | PKCS#8 PEM/DER | planned | implemented (unencrypted) | n/a | planned | encrypted import requires a password-input decision |
| ECDSA private key | PKCS#8 PEM/DER | planned | implemented (unencrypted) | n/a | planned | encrypted import requires a password-input decision |
| Ed25519 private key | PKCS#8 PEM/DER | planned | implemented (unencrypted) | n/a | planned | encrypted import requires a password-input decision |
| RSA private key | PKCS#1 PEM/DER | planned | implemented (unencrypted) | n/a | planned | legacy import; write defaults to PKCS#8 |
| ECDSA private key | SEC1 PEM/DER | planned | implemented (unencrypted) | n/a | planned | legacy import; write defaults to PKCS#8 |
| Certificate and key bundle | PKCS#12/PFX | planned | planned | planned | planned | dependency and password-input decision required first |
| Java keystore | JKS | deferred | deferred | deferred | deferred | target profile phase, not v0.1 |
| SSH key | OpenSSH and RFC 4716 | deferred | deferred | deferred | deferred | separate lifecycle and threat model |
| OpenPGP key | RFC 9580 | deferred | deferred | deferred | deferred | separate lifecycle and threat model |

## Parsing limits

Initial limits are deliberately conservative and become code constants with
tests when parsing begins:

- maximum public-object input per command: 16 MiB;
- maximum private-key input for matching: 64 KiB;
- maximum accepted private-key size: 16,384 bits;
- maximum decoded PEM blocks: 64 for verification bundles; inspection accepts exactly one;
- maximum certificates in one chain operation: 64;
- one DER object must consume the complete bounded input;
- duplicate, unrelated, or unknown PEM blocks are reported rather than ignored;
- no parser follows embedded URLs or consults the network;
- file extension never overrides content classification.

Increasing a limit requires an abuse-case test and a reason grounded in a real
interoperability need.

## Algorithm policy

The parser may recognize legacy algorithms to explain an existing object.
Recognition is not permission to generate, sign, or recommend it.

The initial TLS verification policy accepts SHA-2 RSA and RSA-PSS signatures,
SHA-2 ECDSA signatures, and Ed25519. Accepted public keys are RSA with at least
2048 bits and exponent at least 65537, ECDSA P-256/P-384/P-521, and Ed25519.
This is not a FIPS claim. The generation policy will be defined separately
before `key generate` exists; Rootwell currently generates no user keys.

## Password handling

Passphrases are never accepted as a command-line value, URL parameter, or
ordinary environment variable. Interactive TTY input, protected descriptor/
file input, OS stores, and automation-safe secret providers require a separate
decision and platform tests before encrypted import or export is enabled.
