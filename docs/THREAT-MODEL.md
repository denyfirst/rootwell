# Rootwell Workbench threat model

**Scope:** local Workbench CLI through v0.1

**Last reviewed:** 2026-09-29

This document covers the process that reads local certificate and key material,
performs an explicitly requested operation, and writes a result to a caller-
selected destination. The separate network-capable live TLS probe has its own
[`LIVE-PROBE-THREAT-MODEL.md`](LIVE-PROBE-THREAT-MODEL.md). The future server,
agent, browser gateway, CA connectors, and vault each require a separate
threat model before implementation.

## Security objective

Rootwell must let an operator inspect and transform cryptographic material
without disclosing it, silently changing it, weakening it, or claiming a trust
decision it did not actually prove.

## Data classification

| Class | Examples | Default handling |
|---|---|---|
| Secret | private keys, passphrases, recovery material, API credentials | never log or print; keep local; write only on explicit request with restrictive permissions |
| Sensitive metadata | file paths, internal hostnames, subject names, SANs, owner and inventory relationships | do not echo in errors by default; include in requested output only |
| Public cryptographic material | certificates, CSRs, public keys, fingerprints | may be displayed when requested; integrity still matters |
| Operational evidence | format verdicts, validation failures, tool version, policy version | safe structured output; must not contain secret input |

Certificate content is not assumed harmless. Internal names, identities, and
organization data can be sensitive even when a certificate is technically
public.

## Trust boundaries

```text
operator
   │ arguments, stdin, environment
   ▼
Rootwell process ───────▶ stdout/stderr
   │                         │
   │ bounded reads           │ secret-free diagnostics
   ▼                         ▼
local filesystem        caller or pipeline
   │
   └── explicit output path, atomic replace rules, restrictive permissions

No network boundary exists in Workbench v0.1: network access is out of scope
and therefore forbidden.
```

The following are untrusted inputs:

- every command-line token, including file names;
- file contents and claimed extensions;
- PEM labels, ASN.1 fields, certificate names, and embedded URLs;
- environment variables and current working directory;
- output directories, symlinks, and pre-existing files;
- data received through stdin;
- fixtures contributed in a pull request.

Go's standard library is trusted only within its documented contract. A parser
returning success is not by itself evidence that the object is appropriate for
the requested operation.

## Threat actors

- an attacker who supplies a malformed or adversarial file;
- a local user racing or replacing a path Rootwell is about to write;
- a malicious repository contributor attempting secret disclosure or supply-
  chain execution;
- an operator making an unsafe but plausible mistake;
- a compromised dependency, build input, release artifact, or signing account;
- a future control plane or agent that has been compromised.

An attacker with administrator/root control of the machine can read Rootwell's
memory and replace the executable. Protecting a fully compromised host is not a
claim of the Workbench. Hardware-backed and remote signing models are separate
future boundaries.

## Abuse cases and required controls

| Abuse case | Required control |
|---|---|
| A secret is placed in a file name or unknown command and reflected in an error | diagnostics describe the rule, not the supplied value; regression and fuzz tests |
| A huge or deeply nested input exhausts memory or CPU | bounded reads, explicit object-count limits, parser fuzzing, and time/resource tests before parser release |
| A file extension lies about its content | classify from bounded content; an extension may suggest but never decide a format |
| Conversion silently drops certificates, attributes, or key protection | post-conversion parse and semantic comparison; unsupported preservation fails closed |
| A private key is printed by JSON or debug output | typed output models exclude private bytes; leak tests search every output channel |
| An existing file is replaced unexpectedly | create-new by default; overwrite requires an explicit mode and safe replacement transaction |
| A symlink redirects secret output | platform-specific path and handle validation; tests cover links and races where the OS permits |
| A passphrase appears in process listings or shell history | never accept passphrases as command-line values or URLs |
| Chain verification trusts the host implicitly | v0.1 requires an explicit trust bundle unless a separately named mode says otherwise |
| Parsing follows AIA, CRL, OCSP, or other embedded URLs | Workbench parsing performs no network access |
| A successful issuance is reported as successful deployment | lifecycle states keep issuance, placement, reload, health, and external verification separate |
| A pull request weakens a guard while keeping tests green | behavior tests, two-direction sabotage, signed commits, required review gates, and invariant citations |

## Fail-safe behavior

- Unknown, ambiguous, encrypted-but-unsupported, truncated, trailing, or mixed
  input fails explicitly.
- Rootwell never guesses a private-key password, trust anchor, intended target,
  or output format.
- Partial output is removed or left in a clearly named staging state; it is not
  presented as success.
- Failure output is one line where practical, secret-free, and stable enough for
  automation without exposing attacker-controlled strings.
- A write, flush, close, permission, validation, or rename failure makes the
  operation fail.

## Implemented inspection boundary

`rootwell inspect <file>` reads at most 16 MiB and accepts exactly one X.509
certificate in DER or a header-free PEM `CERTIFICATE` block. DER must consume
the complete input; PEM may have surrounding whitespace but no second block or
other trailing content. Classification comes from bounded content, never the
file extension. Certificate-derived display text is limited to 1 MiB in total
and repeated metadata fields are limited to 4,096 before output escaping.

The result is metadata only. Successful parsing does **not** mean that the
certificate is trusted, currently valid, correctly signed, suitable for a
hostname, or linked to a valid chain. Embedded AIA, CRL, OCSP, and other URLs
are displayed as escaped data when applicable and are never followed. The
production Workbench packages are tested to reject direct network,
child-process, plugin, and unsafe-code imports.

Human output and the versioned JSON view come from the same typed result, which
cannot contain private-key bytes or the input path. JSON is ASCII-escaped while
preserving decoded string values, including non-ASCII certificate names. Key
usage, Basic Constraints, identifiers, and critical extensions are reported as
observations; reporting them does not mean that Rootwell accepts their policy.

The current UTC instant is compared with the encoded inclusive validity
interval. `within-validity-window` means only `NotBefore <= now <= NotAfter`.
It does not imply a valid signature, trusted chain, suitable hostname or usage,
or non-revoked status. Reversed intervals fail closed as `invalid-range`, and
relative-second calculations saturate rather than wrapping.

## Public certificate collection boundary

`rootwell explore <file>` accepts one DER X.509 certificate or 1–64 adjacent,
header-free PEM `CERTIFICATE` blocks within 16 MiB total. It reuses the bounded
single-certificate inspection parser for each object. Extensions are not
trusted. Duplicate certificates, PEM headers, non-certificate blocks,
malformed certificate data, surrounding non-whitespace content, and mixed
secret-bearing input fail before any partial result is printed. Diagnostics
are fixed and do not reflect the path or supplied bytes.

The command prints only public metadata and makes no chain, root-trust,
hostname, signature-validation, revocation, or live-endpoint claim. Public
certificate contents can still reveal internal names and are kept local.
The parsed DER copies are in process memory only; this increment has no file
export or browser upload. A future browser bundle flow and any secret-bearing
format require their own boundary review before implementation.

## Browser pages boundary

Since 24 November 2026 the browser side is seven pages served by `rootwelld`
after sign-in (see [`web/workbench/README.md`](../web/workbench/README.md)).
Three of them work on files a person chooses and never send them anywhere:

- **Inspect** reads up to eight public certificate files after they are
  dropped or chosen, through the same bounded `publicbundle` parser as the
  CLI. It shows the website certificate, its issuer, its dates and whether the
  chain in the files reaches a self-signed root. A PFX, a private key or a
  request is refused with a message naming the page it belongs on. An optional
  private key is compared with the shown certificate in a one-shot worker.
- **Convert** reads one PFX, certificates with or without their key, or a key
  alone, and writes the format the person picks: PEM files in one ZIP, a single
  certificate as PEM or DER, a new PFX, or a key in PEM, DER or the older RSA
  and EC forms.
- **Request** makes a CSR with a new key or an existing one.

The engine is the Go core compiled to WebAssembly. Public certificates are
parsed in the page; private keys, PFX files, requests and key matching run in
a fresh worker for each operation, with a deadline, cancellation when the page
moves on, and clearing of the bytes it received. Responses are versioned and
exclude paths, input bytes and attacker-controlled diagnostics; the 16 MiB
input limit is checked before Go copies are allocated.

The scripts split capabilities. `wasm-loader.js` fetches only the same-origin
`rootwell.wasm`, follows no redirect, and has no DOM or file access. It sends
the session cookie, because the gate serves the engine only to a signed-in
session; `TestEngineLoaderSendsTheSessionTheGateRequires` keeps the two in
step. The scripts that read chosen files (`inspect.js`, `convert.js`,
`request.js` and the shared `ui.js`) have no fetch, XHR, WebSocket, beacon,
worker, dynamic-code, storage or HTML-writing capability; every
certificate-derived value is written with `textContent`. Worker scripts are
served with their own policy that forbids network connections and further
workers. Every page is served with a strict Content Security Policy that
allows scripts, styles, images, fonts and connections only from this server,
`'wasm-unsafe-eval'` for the engine, and nothing inline.

Inspect forgets the certificate and a typed key password when the page is
hidden or left. Convert and Request forget files, keys and passwords when the
page is left, when other files are chosen and after ten idle minutes. Downloads
are browser-managed: Rootwell does not write to disk directly and cannot
control the save prompt, destination or overwrite policy.

Certificates is different by design: it sends what a person adds to this
Rootwell's own `/api/inventory` and `/api/certificates` endpoints, under the
custody boundary of [`CERTIFICATE-CUSTODY-THREAT-MODEL.md`](CERTIFICATE-CUSTODY-THREAT-MODEL.md).
A PFX is opened in its worker first; the server receives its certificate and
the key encrypted again for the transfer, never the PFX or its password.

The engine still carries the explore, single and bundle export, and
explicit-trust verify functions of ADRs 0004, 0005, 0008, 0009 and 0010.
Since the rebuild no page offers bundle export or browser verification;
`scripts/test-browser-wasm.mjs` keeps those functions bounded until they are
removed or used again.

Browser memory, immutable password strings, extensions, a compromised origin
or host, and browser-owned file and download copies are outside this boundary.
The self-hosted origin is trusted to deliver the reviewed scripts, engine and
matching Go runtime shim. Direct `file://` opening does not provide the
engine.

## Implemented TLS verification boundary

`rootwell verify` verifies one PEM or DER leaf for the TLS server profile. The
caller must provide an ASCII hostname and a PEM bundle of explicit trust
anchors. A separate optional PEM bundle supplies intermediates. Rootwell does
not consult the operating-system trust store, merge the two roles, infer a
hostname, or promote an intermediate to a root.

Every accepted trust anchor is a self-signed CA with certificate-signing usage.
Every accepted intermediate is a non-self-signed CA with certificate-signing
usage. Bundles reject non-certificate blocks, PEM headers, junk, duplicates,
more than 64 certificates, and total input over 16 MiB. The leaf must not be a
CA. Verification checks signatures, the full validity chain, DNS hostname, TLS
server extended usage, path constraints, and the initial Rootwell algorithm
policy. It permits RSA keys of at least 2048 bits with a conventional exponent,
NIST P-256/P-384/P-521 ECDSA keys, and Ed25519; legacy signature algorithms and
unknown key types fail closed.

This operation is offline. It does not fetch AIA issuers, CRLs, or OCSP, and it
does not connect to the named host. Success therefore does not prove revocation
status, Certificate Transparency inclusion, possession of the private key, or
what a live endpoint currently serves. Human output states `revocation:
not-checked` and `network: disabled` so those non-claims are not implicit.

## Implemented certificate/private-key match boundary

`rootwell match --cert <file> --key <file>` compares one strict PEM or DER
X.509 certificate with one unencrypted private key. The key may be PKCS#8,
PKCS#1 RSA, or SEC1 ECDSA in strict PEM or DER form. PKCS#8 supports RSA,
ECDSA, and Ed25519. File extensions do not select a parser. Mixed objects,
headers, trailing bytes or fields, unsupported algorithms, malformed keys, and
encrypted keys fail closed.

Certificate reads retain the 16 MiB public-object limit. Private-key reads are
limited to 64 KiB and accepted RSA arithmetic is capped at 16,384 bits. The
comparison canonicalizes both public keys as SubjectPublicKeyInfo and uses a
constant-time comparison. A mismatch is a completed negative verdict: it is
printed as `match: false` and returns exit code 1. A match proves only that the
two inputs encode the same public key. It does not prove certificate trust,
algorithm acceptability, private-key provenance, uncompromised custody, or
live-server deployment.

Output contains only container and public-key metadata. Paths, private bytes,
passphrases, certificate identity fields, and attacker-controlled parser
errors are excluded. Key input and decoded DER buffers are cleared after use
on a best-effort basis, and parsed private values are zeroed where Go's public
types permit. In particular, parsed ECDSA scalar internals are left to Go's
runtime because direct access to them is deprecated and can invalidate the
key implementation. Go runtime copies, allocator pages, swap, crash dumps,
and a privileged host are outside this erasure claim. The operation performs no
network request and does not accept a passphrase through arguments or the
environment. Encrypted-key support remains disabled until an interactive or
descriptor-based secret-input design has its own review and platform tests.

## Implemented public CLI conversion boundary

`rootwell convert --input <file> --to pem|der --output <new-file>` accepts one
bounded strict public certificate. It reparses the output and compares its
DER bytes with the input. A temporary public file is fully written, synced,
read back, and closed before an exclusive hard link makes the output path
visible; an existing file or symlink is not overwritten. Staging cleanup is
best effort. This does not promise crash durability, safe secret-file output,
trust, chain verification, or key custody. PFX, private keys, bundles, and
encrypted material remain unsupported.

## Implemented Linux offline PFX creation boundary

`rootwell pfx-create` reads one bounded non-CA public X.509 certificate, one
bounded strict unencrypted RSA/ECDSA key, and optionally an ordered public
issuer bundle. It requires the existing TLS algorithm policy and exact
certificate/key public-key match. Each issuer must sign the preceding
certificate; duplicates, unrelated material, and a self-signed root are
rejected. The included issuer list is not a trust decision.

Only a local interactive terminal may supply and confirm a new PFX password.
The password is not taken from argv, an environment variable, or a pipe. The
`Modern2023` PKCS#12 encoder with 100,000 KDF iterations produces the output,
which is decoded and compared before writing. On Linux, an existing
owner-private directory and a new 0600 file are required; staging is read
back, no existing destination is replaced, and post-link sync failure reports
uncertainty. Other platforms refuse secret output. No server, inventory,
browser, or network path is involved. External audit remains before first
real-user release. Weak human-chosen passwords, runtime copies, same-user
malware, backups, and crash dumps remain residual risks. See ADR 0030.

## Supply-chain boundary

- The shipped module starts with no runtime dependencies.
- Adding a dependency requires a committed decision record covering ownership,
  maintenance, vulnerability history, transitive code, license, parser limits,
  and the security benefit over the standard library.
- GitHub workflows use no third-party actions. Tools installed during CI are
  version-pinned and do not become runtime dependencies.
- Commits and tags are signed; releases will have a separate reproducibility
  and checksum-signing procedure before the first release.

## Review triggers

Review and version this model before adding any of the following:

- secret-bearing output or a parser for an object not covered by an implemented boundary above;
- password or interactive terminal input;
- temporary files or overwrite support;
- any network-capable command;
- a third-party runtime dependency;
- the server, database, agent, vault, browser gateway, SSH CA, or PGP support;
- a new supported operating system or filesystem security guarantee.
