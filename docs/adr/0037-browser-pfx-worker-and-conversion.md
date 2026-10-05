# ADR 0037: Browser PFX uses a separate bounded one-shot worker

**Status:** accepted for development Workbench; independent release audit pending

**Date:** 2026-10-05

**Update:** ADR 0038 extends browser creation to bounded encrypted PKCS#8
input keys without requiring a plaintext intermediate download. The original
creation boundary below records the initial increment.

## Decision

The Convert screen has separate **Open a PFX** and **Create a PFX** sections.
The browser uses the existing `pfxinspect`, `pfxcreate`, and `pfxkeyexport`
cores through a same-origin Go/WASM bridge in a distinct one-shot worker.
The file-reading UI script has no network or persistent-storage capability.
The asset loader fetches only the same-origin WASM asset and cannot access
selected files. The authenticated gateway serves the worker script with
`connect-src 'none'` and `worker-src 'none'`; the loopback static preview is
unauthenticated and synthetic-only.

Open accepts one PFX at most 1 MiB and a separately entered password. It
supports only the MAC-authenticated Modern2023-shaped envelope and bounded
KDFs of ADR 0031. It displays the one certificate whose public key matches
the private key and any additional public certificates, without calling
them trusted or a verified chain. The password field is cleared after
inspection. Each public-certificate download or matching-key extraction
re-reads and reauthenticates the selected file with a freshly entered PFX
password. Public extraction binds the full displayed fingerprint. Key
extraction binds the matching certificate fingerprint and emits only a
**newly encrypted PKCS#8 PEM** with a fresh 20–128 printable-character
password different from the PFX password. There is no plaintext PFX-key
download or key reveal.

Create accepts one strict non-CA certificate, its matching **unencrypted**
RSA/ECDSA private key, optional nearest-issuer-first PEM intermediates, and a
fresh output password. The Go core checks key match, issuer signatures,
duplicates, profile, and encoded round trip. A self-signed root is excluded
from the chain input. The browser does not accept an encrypted input key for
PFX creation; the existing private-key converter is separate. Output is a
modern password-protected PFX. No bag attributes are preserved, no universal
vendor profile is claimed, and no Inventory/Vault write occurs.

The worker receives only bounded transferred copies after Go/WASM readiness.
It has a 45-second inspection or 90-second output deadline; failure, abort,
stale selection, malformed response, or changed choice requests no download.
The worker terminates after one response. Browser downloads get random
filenames and no Rootwell filesystem-permission or no-overwrite guarantee.
Output buffers and owned password/file buffers are cleared best-effort.

## Threat boundary and residual risks

The PFX preflight bounds visible KDF work, but an authenticated encrypted safe
can conceal an extra inner KDF. The decoder has no cancellation API, so the
one-shot worker/deadline is a responsiveness control, not a cryptographic
proof of resource safety or a process sandbox. JS strings, Go copies, worker
termination, browser/OS memory, extensions, downloads, backups, and a
compromised same-origin script/host remain outside a zeroization guarantee.
PKCS#12 and encrypted PKCS#8 passwords should be generated randomly; length
alone is not entropy. Creation and extraction prove object match and output
equivalence, not certificate trust, hostname, revocation, or deployment.

The development gate includes generated synthetic Go and WASM round trips,
wrong-password/tamper/mismatch/refusal paths, worker timeout/abort/transfer
tests, static capability checks, gateway/CSP tests, and a browser visual
check. A release candidate still requires independent security audit and
real-world interoperability testing. Legacy and vendor-specific PFX profiles
remain unsupported until separately reviewed.
