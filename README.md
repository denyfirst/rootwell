# DenyFirst Rootwell

**Status:** early Workbench and loopback-only access-gate implementation

Rootwell is a privacy-first, self-hosted workspace for certificates,
cryptographic keys, and machine identities.

> Your private root of trust.

The first product increments are a local-first Workbench CLI and browser for
safe public-certificate inspection and verification. An experimental local
access gate protects the browser; vault, automation, and remote access remain
outside this release boundary.

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

## Local Workbench interface

For a local test of the password-gated Workbench on Windows, from the Rootwell
repository in an interactive PowerShell terminal:

```powershell
$dataDir = Join-Path $env:LOCALAPPDATA "Rootwell"
$env:GOOS = "js"
$env:GOARCH = "wasm"
go build -trimpath -o web/workbench/rootwell.wasm ./cmd/rootwell-browser
Copy-Item -Force (Join-Path (go env GOROOT) "lib/wasm/wasm_exec.js") web/workbench/wasm_exec.js
Remove-Item Env:GOOS
Remove-Item Env:GOARCH
go run ./cmd/rootwelld init $dataDir
go run ./cmd/rootwelld serve $dataDir web/workbench
```

Save the one-time setup password when `init` displays it and type `SAVED` to
confirm. Open `http://localhost:4180` in the same host's browser. Signing in
with the setup password permits **only** the mandatory password-change page;
after changing it, sign in again with the replacement. Passwords are never
accepted as command-line arguments or written to daemon logs. An existing
installation's setup password cannot be redisplayed. The gateway listens on
127.0.0.1 only; it is not a remote TLS endpoint or production vault. Secure
cookies over HTTP localhost are not supported by every browser, and the
Windows ACL/backup/recovery boundary is not yet complete. See the
[loopback gate threat model](docs/LOOPBACK-GATE-THREAT-MODEL.md).
Serving `web/workbench` directly with a separate static server remains an
unauthenticated developer preview; it is not protected by `rootwelld`.

The dependency-free browser shell is available at
[`web/workbench/index.html`](web/workbench/index.html). Inspect handles one
public certificate; Explore lists certificates across 1–8 selected public
files (single DER certificates or strict PEM bundles), up to 64 certificates
and 16 MiB combined. Both use the bounded Go core through
WebAssembly and never post selected bytes to a server API. A selected public
certificate can be downloaded separately as PEM or DER from Explore, with a
clearly labeled `.pem`, `.der`, `.crt`, or `.cer` filename extension;
the browser manages the final save location. Verify checks a public server
chain against a separately selected root and hostname without network access.
An optional full SHA-256 root fingerprint pin must come from an independent
trusted source; without it, the root's identity is not independently confirmed.
Build and hosting requirements are
documented in the [browser boundary](web/workbench/README.md).

## Implemented commands

The separately built, explicitly network-capable `rootwell-probe` performs a
read-only TLS spot check of one literal IP and port. The regular `rootwell`
Workbench and browser stay offline. Build with
`go build ./cmd/rootwell-probe`, then run the resulting `rootwell-probe`
(`rootwell-probe.exe` on Windows):

```text
rootwell-probe --hostname portal.company.local --connect-ip 192.0.2.10 --port 443 \
  --trust-bundle company-roots.pem --root-sha256 <independently-verified-root-fingerprint> \
  --expected-leaf intended-server.crt
```

The probe checks the live TLS handshake, hostname, chain, pinned root,
Rootwell certificate policy, and exact served leaf. It does not resolve DNS,
use system roots, fetch revocation data, or check every load-balancer node.
Only probe endpoints you are authorized to contact. Obtain the expected root
fingerprint from an independent trusted source, not the same root file. The
hostname is sent as TLS SNI to the selected IP; do not disclose an internal
name to an untrusted endpoint. See
the [probe threat model](docs/LIVE-PROBE-THREAT-MODEL.md) and
[ADR 0011](docs/adr/0011-separate-explicit-live-tls-probe.md).

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

Explore public certificates in one DER file or a strict PEM bundle:

```text
rootwell explore certificates.crt
```

`explore` lists up to 64 certificates, their subject, issuer, expiry, CA flag,
and SHA-256 fingerprint. It does not select a leaf or trust anchor, verify a
chain, export files, or process PFX/private keys. The filename extension does
not determine the encoding; mixed blocks, junk, and duplicates are rejected.
Browser Explore accepts 1–8 selected public files, rejects duplicates across
them, displays the collection locally, and can download one chosen certificate
as PEM or DER from its original source file.
`.crt` and `.cer` are filename extensions, not additional encodings, and both
can be selected for either PEM or DER bytes.
It does not yet produce a combined bundle or infer chain roles. CLI `explore`
remains one-file and read-only.

Match one certificate to one unencrypted local private key:

```text
rootwell match --cert certificate.pem --key private-key.pem
rootwell match --json --cert certificate.der --key private-key.der
```

Matching accepts strict PEM or DER PKCS#8, PKCS#1 RSA, and SEC1 ECDSA keys;
PKCS#8 supports RSA, ECDSA, and Ed25519. Private-key input is capped at 64 KiB,
never printed, and cleared from Rootwell-owned input buffers on a best-effort
basis. Encrypted keys are deliberately rejected until safe passphrase input is
implemented. A mismatch prints an explicit `false` verdict and exits `1`.
Matching does not establish certificate trust or algorithm safety. See the
[match contract](docs/MATCH.md).

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

Private-key conversion and writing are intentionally not implemented yet.
Their threat boundaries and failure contracts must be established before code
is added.
