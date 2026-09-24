# Certificate/private-key match contract

`rootwell match` determines whether one local X.509 certificate and one local
unencrypted private key contain the same public key. It performs no network
request and never writes either input.

```text
rootwell match --cert certificate.pem --key private-key.pem
rootwell match --json --cert certificate.der --key private-key.der
```

Flag order is not significant. `--cert` and `--key` are mandatory and may
occur only once. Passphrases are never accepted as arguments or environment
variables.

## Accepted input

- certificate: exactly one PEM `CERTIFICATE` block without headers, or one
  complete DER X.509 certificate; maximum 16 MiB;
- private key: unencrypted PKCS#8, PKCS#1 RSA, or SEC1 ECDSA in strict PEM or
  DER; maximum 64 KiB;
- PKCS#8 algorithms: RSA, ECDSA, and Ed25519;
- maximum private-key size: 16,384 bits.

Extensions do not choose the parser. Extra blocks, trailing bytes or fields,
PEM headers, malformed keys, unknown algorithms, and encrypted keys are rejected.

## Verdict and exit code

`match: true` exits `0`. `match: false` is a completed negative verdict and
exits `1`. Parse, read, resource, and output failures also exit `1`, but use a
fixed diagnostic on stderr. Invalid arguments exit `2`.

The verdict proves only that canonical public keys are equal. It does not
prove trust, certificate validity, algorithm strength, key provenance,
exclusive possession, or deployment to a live endpoint. Human and JSON output
therefore state:

```text
algorithm-policy: not-evaluated
certificate-trust: not-evaluated
network: disabled
```

## JSON

`--json` emits the versioned `rootwell.match.v1` schema identifier in the
`schema_version` field. The document contains the boolean verdict,
certificate/key encodings, public-key algorithm details, and a SHA-256
fingerprint of the private key's public SubjectPublicKeyInfo.
Paths, input bytes, certificate names, private parameters, and passphrases are
not schema fields.

Schema additions may be backward-compatible. Removing or changing the meaning
of an existing field requires a new schema identifier.

## Memory boundary

Rootwell clears its file-input and decoded DER buffers after matching and
zeroes parsed RSA and Ed25519 private values on a best-effort basis. Go's ECDSA
scalar fields are not modified because direct access to them is deprecated.
This is not guaranteed secure erasure across runtime copies, allocator pages,
swap, crash dumps, or a privileged/compromised host.
