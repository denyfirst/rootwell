# Workbench v0.1 format matrix

This is a scope boundary, not a promise that every listed operation already
exists. `planned` means implementation and its security tests are still
required. Anything not listed is unsupported and must fail explicitly.

| Object | Encoding/container | Inspect | Match | Verify | Convert/write | v0.1 notes |
|---|---|---:|---:|---:|---:|---|
| X.509 certificate | PEM | implemented (single) | planned | planned | planned | exactly one header-free `CERTIFICATE` block |
| X.509 certificate | DER | implemented (single) | planned | planned | planned | exactly one certificate; trailing data rejected |
| Certificate chain | PEM bundle | planned | n/a | planned | planned | order is preserved and validated |
| CSR / PKCS#10 | PEM | planned | planned | n/a | planned | signature checked after parsing |
| CSR / PKCS#10 | DER | planned | planned | n/a | planned | trailing data rejected |
| RSA private key | PKCS#8 PEM/DER | planned | planned | n/a | planned | unencrypted first; encrypted import reviewed separately |
| ECDSA private key | PKCS#8 PEM/DER | planned | planned | n/a | planned | unencrypted first |
| Ed25519 private key | PKCS#8 PEM/DER | planned | planned | n/a | planned | unencrypted first |
| RSA private key | PKCS#1 PEM/DER | planned | planned | n/a | planned | legacy import; write defaults to PKCS#8 |
| ECDSA private key | SEC1 PEM/DER | planned | planned | n/a | planned | legacy import; write defaults to PKCS#8 |
| Certificate and key bundle | PKCS#12/PFX | planned | planned | planned | planned | dependency and password-input decision required first |
| Java keystore | JKS | deferred | deferred | deferred | deferred | target profile phase, not v0.1 |
| SSH key | OpenSSH and RFC 4716 | deferred | deferred | deferred | deferred | separate lifecycle and threat model |
| OpenPGP key | RFC 9580 | deferred | deferred | deferred | deferred | separate lifecycle and threat model |

## Parsing limits

Initial limits are deliberately conservative and become code constants with
tests when parsing begins:

- maximum input per command: 16 MiB;
- maximum decoded PEM blocks: 256 for future bundle operations; inspection accepts exactly one;
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

The initial generation policy will be defined before `key generate` exists.
Until then Rootwell generates no keys and makes no FIPS claim.

## Password handling

Passphrases are never accepted as a command-line value, URL parameter, or
ordinary environment variable. Interactive TTY input, protected descriptor/
file input, OS stores, and automation-safe secret providers require a separate
decision and platform tests before encrypted import or export is enabled.
