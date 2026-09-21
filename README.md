# DenyFirst Rootwell

**Status:** foundation planning

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

No production cryptographic implementation exists yet. Threat boundaries,
format scope, and test contracts are established before private-key handling
code is added.
