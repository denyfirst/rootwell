# Workbench v0.1 format matrix

This is a scope boundary, not a promise that every listed operation already
exists. `planned` means implementation and its security tests are still
required. Anything not listed is unsupported and must fail explicitly.

For a single public browser export, `.crt` and `.cer` are allowed filename
extensions for either PEM or DER certificate bytes; they are not separate
encodings. `.pem` is paired only with PEM and `.der` only with DER.
Browser Explore accepts 1–8 public files, each parsed separately, with a
16 MiB/64-certificate combined limit and no trust inference. CLI `explore`
still accepts one file.

| Object | Encoding/container | Inspect | Match | Verify | Convert/write | v0.1 notes |
|---|---|---:|---:|---:|---:|---|
| X.509 certificate | PEM | implemented (single) | implemented | implemented (TLS server) | browser public-only export and CLI PEM/DER conversion | exactly one header-free `CERTIFICATE` block |
| X.509 certificate | DER | implemented (single) | implemented | implemented (TLS server) | browser public-only export and CLI PEM/DER conversion | exactly one certificate; trailing data rejected |
| Certificate chain | PEM bundle | implemented (CLI/browser `explore`) | n/a | implemented (CLI explicit roots/intermediates) | browser export of one selected public certificate; other conversions planned | exploration is not trust verification; order is not a trust signal |
| CSR / PKCS#10 | PEM | browser Request certificate | returned-certificate key/SAN comparison | n/a | browser generation and PEM/DER export | one signature-checked DNS/IP request; 64 KiB; unknown attributes/extensions refused |
| CSR / PKCS#10 | DER | browser Request certificate | returned-certificate key/SAN comparison | n/a | browser generation and PEM/DER export | exact object; same bounded profile; comparison is not trust |
| RSA private key | unencrypted PKCS#8 PEM/DER | browser format summary | implemented | n/a | encrypted PKCS#8 PEM default; opt-in plaintext PKCS#8/PKCS#1 PEM/DER | separate modern PFX creation also accepts matching bounded encrypted PKCS#8 input |
| ECDSA private key | unencrypted PKCS#8 PEM/DER | browser format summary | implemented | n/a | encrypted PKCS#8 PEM default; opt-in plaintext PKCS#8/SEC1 PEM/DER | separate modern PFX creation also accepts matching bounded encrypted PKCS#8 input |
| Ed25519 private key | unencrypted PKCS#8 PEM/DER | browser format summary | implemented | n/a | encrypted PKCS#8 PEM default; opt-in plaintext PKCS#8 PEM/DER | no PKCS#1/SEC1 target exists for Ed25519 |
| RSA private key | unencrypted PKCS#1 PEM/DER | browser format summary | implemented | n/a | same compatible private targets | plaintext requires explicit warning |
| ECDSA private key | unencrypted SEC1 PEM/DER | browser format summary | implemented | n/a | same compatible private targets | plaintext requires explicit warning |
| RSA/ECDSA/Ed25519 private key | encrypted PKCS#8 PEM/DER, bounded PBES2/PBKDF2-SHA256/AES-256-CBC | browser password-gated public summary | n/a | n/a | same compatible private targets | input password distinct from output password; unsupported profiles refused |
| Certificate and key bundle | PKCS#12/PFX | offline CLI and browser public summary for bounded modern profile | matching cert/key checked, not a separate Match command | no trust verification | offline Linux CLI and browser create, public certificate extraction, and encrypted PKCS#8 matching-key extraction | browser accepts at most 1 MiB modern authenticated PFX; creation accepts matching unencrypted RSA/ECDSA or bounded encrypted PKCS#8 key and optional ordered issuers; no plaintext PFX-key export, vault, universal vendor profile, or trust claim |
| Java keystore | JKS | deferred | deferred | deferred | deferred | target profile phase, not v0.1 |
| SSH key | OpenSSH and RFC 4716 | deferred | deferred | deferred | deferred | separate lifecycle and threat model |
| OpenPGP key | RFC 9580 | deferred | deferred | deferred | deferred | separate lifecycle and threat model |

## Parsing limits

Inspection summaries remain public-only. ADR 0039 adds an explicit transient
PKCS#8 PEM view: fresh current-file password for encrypted keys/PFX, renewed
screen-exposure consent for plaintext files, 30-second clearing and page/source
cancellation. This is not a download or Vault save.

Initial limits are deliberately conservative and become code constants with
tests when parsing begins:

- maximum public-object input per command: 16 MiB;
- maximum private-key input for matching: 64 KiB;
- maximum accepted private-key size: 16,384 bits;
- maximum decoded PEM blocks: 64 for verification and public exploration bundles; single-certificate inspection accepts exactly one;
- browser Explore collection: at most 8 files, 16 MiB total, 64 distinct certificates, and 1 MiB aggregate subject/issuer text;
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
This is not a FIPS claim. Browser Request certificate generates RSA
2048/3072/4096 (default 3072) or ECDSA P-256/P-384/P-521 with crypto/rand;
the new key is exported only encrypted as PKCS#8, together with its public CSR
in an unencrypted ZIP. Existing supported modern keys may sign a CSR without
being exported. No CLI key-generation or CSR command is claimed.

## Password handling

Passphrases are never accepted as a command-line value, URL parameter, or
ordinary environment variable. Interactive TTY input, protected descriptor/
file input, OS stores, and automation-safe secret providers require a separate
decision and platform tests before encrypted import or export is enabled.
