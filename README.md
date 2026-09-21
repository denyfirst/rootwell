# DenyFirst Rootwell

**Status:** early Workbench implementation

Rootwell is a privacy-first, self-hosted workspace for certificates,
cryptographic keys, and machine identities.

> Your private root of trust.

The first product increment is a local-first Workbench CLI for safe inspection,
matching, verification, and conversion. Server, vault, automation, and access
features are added only after their trust boundaries and failure modes are
tested.

## Project doctrine

- Security is the first requirement, not a later hardening phase.
- A feature is not complete because it works; it is complete when positive,
  negative, malformed-input, and relevant abuse cases are tested.
- Private material is never uploaded to DenyFirst and is never committed.
- Cryptographic primitives are not implemented from scratch.
- Risky operations must be explicit, auditable, recoverable, and fail closed.
- Rootwell and Porch are separate repositories and separate products.

## Plans

- [Product and execution plan](docs/PRODUCT-PLAN-AZ.md)
- [Expanded platform vision](docs/PLATFORM-VISION-AZ.md)
- [Engineering workflow](docs/ENGINEERING.md)
- [Workbench threat model](docs/THREAT-MODEL.md)
- [Security invariants](docs/SECURITY-INVARIANTS.md)
- [v0.1 format matrix](docs/FORMAT-MATRIX.md)

## Implemented commands

Inspect one local X.509 certificate in PEM or DER form:

```text
rootwell inspect certificate.pem
rootwell inspect --json certificate.der
```

The command reads at most 16 MiB, ignores the file extension, rejects multiple
or trailing objects, performs no network access, and prints escaped metadata.
A successful result means only that one certificate parsed successfully; it is
not a trust, signature, chain, hostname, or expiry-policy verdict.

Inspection reports public-key details, key usages, Basic Constraints, key
identifiers, SANs, critical-extension OIDs, and the SHA-256 fingerprint. JSON
uses the documented `rootwell.inspect.x509.v1` compatibility contract and
contains metadata only. See [the JSON contract](docs/INSPECT-JSON.md).

Rootwell also evaluates the certificate's encoded validity interval against the
current UTC instant. It reports `within-validity-window`, `not-yet-valid`,
`expired`, or `invalid-range`, together with explicit relative seconds and whole
days. This time-window observation is not a trust or verification verdict.

Verify a TLS server leaf against explicit local trust material:

```text
rootwell verify server.pem \
  --trust-bundle company-roots.pem \
  --intermediates company-intermediates.pem \
  --hostname portal.company.local
```

`--intermediates` is optional; the trust bundle and hostname are mandatory.
The leaf may be PEM or DER, while CA bundles are strict PEM certificate
bundles. Verification uses no operating-system trust store and makes no network
requests. It checks the chain, signatures, validity, TLS server usage, hostname,
constraints, and Rootwell's initial algorithm policy. It does **not** check
revocation, OCSP, CRLs, Certificate Transparency, or the certificate currently
served by a remote endpoint. See [the TLS verification contract](docs/VERIFY-TLS.md).

Private-key handling and conversion are intentionally not implemented yet.
Their threat boundaries and failure contracts must be established before code
is added.
