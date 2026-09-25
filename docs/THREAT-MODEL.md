# Rootwell Workbench threat model

**Scope:** local Workbench CLI through v0.1

**Last reviewed:** 2026-09-24

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

## Browser inspection boundary

The static Workbench can inspect one public PEM or DER X.509 certificate with a
Go WebAssembly build of the same bounded core used by the CLI. The operator
must explicitly choose a file and press **Inspect certificate** before bytes are
read. No certificate upload or parsing API exists: the selected bytes move from
the browser `File` object into a JavaScript byte array and then into Go linear
memory in the same browser process.

The browser scripts split capabilities. `wasm-loader.js` may fetch the exact
same-origin `rootwell.wasm` application asset but has no DOM, file-selection,
or file-byte access. `app.js` may read explicitly selected files and invoke the already-
loaded Go function, but it has no fetch, XHR, WebSocket, beacon, service-worker,
dynamic-code, or workbench-input storage capability. CSP denies third-party
assets and restricts connections to the self-hosted origin. Certificate-derived
values are rendered with `textContent`, never markup.

The WebAssembly bridge checks the 16 MiB limit before allocating its Go copy.
The parser still requires exactly one complete certificate and applies the same
metadata limits. Responses are versioned and exclude paths, input bytes,
private-key fields, stack traces, and attacker-controlled diagnostics. The JS
and Go entry buffers are cleared after processing on a best-effort basis.
Browser and runtime copies outside those buffers are not guaranteed erased.
This boundary therefore accepts public certificates only; private keys,
passphrases, PFX, and other secret-bearing inputs require a separate review.

The self-hosted origin is trusted to deliver the reviewed Rootwell JavaScript,
WebAssembly, and matching Go runtime shim. A compromised origin, browser,
extension, administrator, or host can replace code or read process memory and
is outside this boundary. Production hosting must provide the documented HTTP
security headers, `application/wasm` media type, authenticated administrative
access, no third-party injection, and matching release checksums. Direct
`file://` opening is only a visual fallback and does not provide the functional
engine.

## Browser public bundle exploration boundary

The Explore tab reads 1–8 explicitly selected files only after **Explore
bundle** is pressed. Each file accepts one complete DER certificate or 1–64
public PEM `CERTIFICATE` blocks through the same `publicbundle` parser as the
CLI. The browser additionally enforces a 16 MiB combined, 64-certificate
combined, and 1 MiB aggregate metadata-text limit. It tracks full SHA-256
fingerprints across files, rejecting duplicates without a partial result.
For a cross-file duplicate, the local UI reports both selected file positions,
display-safe, length-bounded filenames, and the full certificate fingerprint.
For a duplicate within one file, the core reports only a fixed error and the
UI identifies that source file; it cannot identify the individual PEM blocks.
Neither case silently deduplicates or displays a partial certificate list.
Private keys and PFX are not accepted. Filenames and extensions never choose
the parser. Malformed, mixed, excessive, or secret-bearing input produces a
fixed, input-free failure and no partial certificate list. Duplicate errors
are the only contextual diagnostics here; they use selected filenames and a
validated public fingerprint, never certificate subject or raw input bytes.

The versioned bridge response contains only subject, issuer, validity start/end, CA flag,
encoding, and SHA-256 fingerprint for each certificate, with a 4 MiB response
cap. The UI validates the response shape and puts certificate-derived text
into DOM text nodes only, including the user-supplied source filename. Each
source file remains associated with its cards so export re-parses that exact
source; selecting new files invalidates old cards. JS and Go entry buffers
and parsed public DER copies
are cleared on a best-effort basis, without a browser-wide erasure claim.
Selected certificate data can still include sensitive internal identities.

Exploration is not verification. The bridge says `not-performed` and
`not-selected`; the UI never promotes an included CA certificate to a trusted
root or silently classifies a leaf. Chain building, hostname, time-policy,
revocation, live endpoint, and private-key possession are outside this result.
The separate public issuer-candidate analysis re-parses the selected files,
caps signature work, and returns only fingerprint-aligned index links. Raw
issuer/subject names and signatures must match before showing an edge. A
self-signed CA is only a candidate, not a trusted anchor. A changed file,
malformed response, or analysis failure hides the entire Explore result.
The session-only expiry overview uses one browser-clock snapshot and strict
canonical UTC-second dates from the Go parser. It has no persistence, alert,
network, or renewal capability. The 30/90-day groups are triage labels only;
an incorrect local clock, untrusted CA, revoked certificate, or old selected
file can invalidate an operational inference. New selection and failure clear
the overview with the cards.
The same-origin asset, CSP, and no-upload trust boundaries above remain in
force. See ADR 0004, ADR 0006, and ADR 0007 for this extension.

## Browser public certificate export boundary

The user explicitly chooses PEM or DER on one Explore card. Rootwell re-reads
and re-parses the selected public file, identifies the intended certificate
by its full SHA-256 fingerprint rather than bundle order, and rejects missing,
changed, secret-bearing, duplicate, or malformed source content. It encodes
only that public certificate, then re-parses the output and checks the DER
bytes and fingerprint against the selected original. DER output preserves the
certificate's exact DER bytes; PEM output contains one canonical public
`CERTIFICATE` block. No trust verdict is made.

The Go/WebAssembly bridge copies only the selected public output into a
bounded byte array; the browser checks the versioned result, format,
fingerprint, and safe generated filename and re-parses the output before
requesting a Blob download. The filename uses a fixed prefix, fingerprint
fragment, and random suffix, never a subject or source filename. The user may
choose `.crt` or `.cer` for either PEM or DER bytes; `.pem` stays PEM-only and
`.der` stays DER-only. The UI labels the true encoding, and changing the
extension never changes the certificate bytes, parser, or trust result. The
file-reading script still cannot transmit through a network API, persist
workbench input, or directly write to a filesystem. Browser-owned file and
download copies cannot be reliably erased by Rootwell. Rootwell does not
control browser/OS save prompts, destination, or overwrite policy; the
application guarantees no direct disk overwrite, not a browser-wide
no-overwrite guarantee. See ADR 0005.

## Browser selected public bundle export boundary

The user checks specific Explore cards to export one public PEM collection
in displayed order. The Go/WebAssembly export path re-parses every selected
source file and requires the full ordered fingerprint list to match Explore;
the requested subset must be order-preserving and nonempty. Mixed,
secret-bearing, malformed, duplicate, excessive, or changed input produces
no output. The output is re-parsed and its DER bytes and fingerprints are
checked before a bounded browser-managed download. Its randomized filename
contains no certificate or source text. No inferred ordering, trust, private
key, direct disk write, or no-overwrite promise is made. See ADR 0008.

## Implemented TLS verification boundary

The browser Verify panel calls the same `certverify.Verify` core as the CLI.
It requires a user-entered hostname and a separately selected PEM trust
bundle. Simple classifies 1–8 strict public source files but never promotes a
self-signed source root into trust; it requires exactly one non-CA leaf.
Advanced selects the leaf and optional intermediates explicitly. Both use
the same policy and explicit evaluation time. Total input is bounded to
16 MiB before Go copies are allocated. The browser accepts only a versioned
success marked `explicit-file`, validates the hostname and chain shape, and
uses text nodes for all certificate-derived strings. Failure or selection
change hides any earlier Verified result. No private keys, PFX, system roots,
network verification, revocation, or live endpoint claim is made. See ADR
0009.

An optional full SHA-256 root fingerprint pin checks the trust anchor of the
verified path after all chain policy checks. It accepts only complete hex or
colon-separated byte notation. A malformed or mismatched pin fails without a
partial chain. If no pin is supplied, the result explicitly says the root
identity was not independently checked. A matching pin does not authenticate
the expected fingerprint's origin: copying it from the same untrusted file is
not an independent check. Editing the pin hides the old verdict and disables
export. The export's complete path fingerprint re-check still binds the root.
Neither mode connects to the hostname or detects a live MITM; see C26.

## Browser verified public fullchain export boundary

The Verify result holds only ordered public fingerprints, file references,
hostname, mode, and evaluation time. A download click re-reads bounded public
inputs and re-runs the same explicit-trust Go verifier. All displayed path
fingerprints, including the separately trusted root, must match the new
verdict exactly. A mismatch or failure returns no bytes and hides the prior
Verified state. The output contains only the selected verified leaf and
intermediates, in verified order; the trust root and any private key are
excluded. Go and browser code re-parse the PEM before a browser-managed
download; no direct disk write or no-overwrite promise is made. An Advanced
backdated evaluation time remains a historical verdict, not present-tense
deployment evidence. See ADR 0010.

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
