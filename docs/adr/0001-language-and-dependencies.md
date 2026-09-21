# ADR 0001: Go and a standard-library-first core

**Status:** accepted

**Date:** 2026-09-21

## Decision

Rootwell's first implementation uses Go 1.26.7. The v0.1 runtime begins with no
third-party dependencies. Standard-library X.509, ASN.1, PEM, hashing, and key
types are preferred where their documented behavior satisfies the format and
security contract.

"No dependencies" is not a permanent marketing constraint. A mature library
may be safer than implementing a container such as PKCS#12 ourselves. Such a
dependency requires a new ADR that records:

- why the standard library is insufficient;
- maintainer and release activity;
- vulnerability and security-review history;
- transitive dependencies and checksums;
- parsing/resource limits and fuzzing posture;
- license and update ownership;
- removal or replacement strategy.

Rootwell will not implement cryptographic primitives, password-based encryption
schemes, or a general ASN.1 stack.

## Consequences

- The initial binary is statically buildable and easy to inspect.
- PKCS#12 support waits for an explicit dependency decision.
- CI-installed analysis tools are pinned but do not enter `go.mod` or the
  shipped binary.
- The declared Go patch version is part of the reproducible-build boundary and
  is upgraded through reviewed changes.
