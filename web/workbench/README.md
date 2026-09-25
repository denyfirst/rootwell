# Rootwell local Workbench

This directory contains Rootwell's dependency-free, self-hosted browser UI.
Inspect processes one public PEM or DER X.509 certificate. Explore processes
1–8 selected public files containing strict PEM certificate bundles or single
DER certificates, with at most 64 certificates and 16 MiB combined. Each file
uses the same bounded Go core as the
CLI. Verify uses the same explicit-trust TLS server verifier as the CLI.

## Security boundary

- certificate bytes are never posted to a Rootwell or third-party HTTP API;
- only `wasm-loader.js` may fetch, and it loads the same-origin
  `rootwell.wasm` application asset;
- the loader has no DOM, selected-file, or file-byte access;
- `app.js` reads a file only after **Inspect certificate**, **Explore bundle**,
  **Verify certificate**, or a public download action is pressed and has no network,
  service-worker, dynamic-code, or
  workbench-input storage capability;
- selected values and certificate metadata are rendered through `textContent`;
- the Go core enforces the 16 MiB per-file input limit, strict one-certificate
  Inspect or 1–64 certificate per-file Explore limits, trailing-data and metadata
  limits before returning a versioned, public-only response (Explore is also
  capped at 4 MiB); the browser additionally bounds the selected collection
  and rejects duplicates across files without showing partial results;
- duplicate diagnostics name both local files and the full fingerprint across
  files, or the source file for an in-file duplicate; filenames are bounded and
  rendered as text, and duplicate certificates are never silently removed;
- JavaScript and Go entry buffers are cleared after use on a best-effort basis.

Explore displays subject, issuer, CA flag, validity start/end, encoding, fingerprint, and
possible issuer links backed by issuer/subject names and signature checks.
Its expiry overview sorts the selected public certificates by end date and
groups invalid ranges, expired, not-yet-valid, 0–30 days, 31–90 days, and later
dates using a single snapshot of the browser clock. The 30/90-day windows are
fixed triage hints, not configurable alerts or automatic renewal. The overview
exists only in the current page session, refreshes only after Explore is
pressed again, and is cleared on a new selection or analysis failure. A wrong
browser clock produces wrong time buckets; the displayed UTC evaluation time
helps the operator spot this. CA dates are included without implying trust.
It does not select a leaf, choose a trust anchor, or verify a chain. An
explicitly selected set can be downloaded as a public PEM bundle in displayed
order, without an automatic fullchain claim. A selected public certificate
can also be downloaded as one PEM
`CERTIFICATE` block or exact DER bytes. The source is re-parsed and selected
by fingerprint; the output is re-parsed and byte-checked before download.
The user explicitly chooses both the encoding and filename extension:
`.crt`/`.cer` may contain PEM or DER, whereas `.pem` and `.der` are paired
only with their named encodings. The extension does not alter the certificate.
The filename uses a fixed prefix, fingerprint fragment, and random suffix,
never certificate subject text. Rootwell does not write to disk or silently
overwrite a file; final save behavior belongs to the browser and operating
system and cannot be guaranteed by this web page. A CA flag is not a trust
verdict.

Verify is offline and requires a hostname and separately selected PEM trust
anchor file. Simple classifies 1–8 strict public files and requires exactly
one end-entity certificate; self-signed roots in these files are ignored as
trust sources. Advanced accepts an explicit leaf, optional PEM intermediates,
and optional RFC 3339 evaluation time. Both use the same Go verification
policy. Success does not check revocation, live deployment, or private-key
possession. Do not import private keys or PFX into this public-only UI.
An optional full SHA-256 root certificate fingerprint can be entered as
64 hex digits or colon-separated bytes. Rootwell compares it with the final
anchor of the verified path and refuses a malformed or mismatched pin. Obtain
the expected value through a separately trusted channel; copying it from the
same root file adds no assurance. Without a pin, Rootwell reports that root
identity remains unconfirmed. A pin does not check a live server or MITM.

After success, **Download verified fullchain PEM** re-reads the selected
files, re-verifies with the same separate trust file, hostname and evaluation
time, and requires the complete ordered path to match the displayed one.
Only the verified leaf and intermediates are exported, in path order. The
trust root, unrelated certificates, and private keys are excluded. The output
is capped at 4 MiB, re-parsed in Go and the browser, and downloaded with a
random browser-managed filename. An Advanced historical evaluation time is
not a claim that the chain is valid now. See
[ADR 0010](../../docs/adr/0010-browser-verified-public-fullchain-export.md).

Browser-wide memory erasure is not guaranteed. This boundary is for public
certificates only. Do not select private keys, passphrases, PFX/PKCS#12 files,
or other secrets. See
[`docs/adr/0003-browser-inspection-webassembly.md`](../../docs/adr/0003-browser-inspection-webassembly.md)
and [the Explore decision](../../docs/adr/0004-browser-public-bundle-exploration.md)
and [issuer-candidate decision](../../docs/adr/0007-browser-public-issuer-candidates.md)
and [bundle export decision](../../docs/adr/0008-browser-selected-public-bundle-export.md)
and [Verify decision](../../docs/adr/0009-browser-explicit-trust-verification.md)
for the decision and non-claims.

## Build the local engine

The generated `rootwell.wasm` and `wasm_exec.js` files are intentionally not
committed. They must come from the exact Go version selected by `go.mod`.

PowerShell:

```powershell
$env:GOOS = "js"
$env:GOARCH = "wasm"
go build -trimpath -o web/workbench/rootwell.wasm ./cmd/rootwell-browser
Copy-Item -Force (Join-Path (go env GOROOT) "lib/wasm/wasm_exec.js") web/workbench/wasm_exec.js
```

POSIX shell:

```sh
GOOS=js GOARCH=wasm go build -trimpath \
  -o web/workbench/rootwell.wasm ./cmd/rootwell-browser
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/workbench/wasm_exec.js
```

Serve `web/workbench` from a static server. Direct `file://` opening remains a
visual fallback because browsers do not consistently load local WebAssembly.
The server must send `Content-Type: application/wasm` for `rootwell.wasm`.

For a safe first test, download `rootwell-demo-certificate.pem` from the Inspect
panel and select it in Inspect or Explore. It contains one non-production public
certificate for `.invalid` names and deliberately contains no private key. To
see two cards in Explore, use the public `rootwell-demo-bundle.pem` link there.
Each card lets the user choose PEM or DER content and a compatible extension
before downloading its own public certificate.

To test Verify without production material, download the public
`rootwell-verify-demo-ca-files.pem` and `rootwell-verify-demo-root.pem` links
in the Verify panel. Enter `verify.rootwell.invalid` as hostname. Select the
CA-files PEM in Simple and the root PEM as the separate trust file. For
Advanced, use the separate demo leaf and intermediate links. The demo has
no private key; never install its root into a browser or OS trust store. Its
fixed validity window ends on 2035-01-01, after which historical evaluation
time is required for testing.

## Required production headers

The HTML meta policy is a fallback, not the deployment boundary. The static
server should send at least:

```text
Content-Security-Policy: default-src 'none'; style-src 'self'; script-src 'self' 'wasm-unsafe-eval'; img-src 'self'; connect-src 'self'; font-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; worker-src 'none'; manifest-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: camera=(), display-capture=(), geolocation=(), microphone=(), payment=(), usb=()
```

Use an authenticated administrative origin with no third-party script
injection, publish checksums with the release bundle, and package
`rootwell.wasm` together with the matching Go `wasm_exec.js` runtime.
