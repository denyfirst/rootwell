# Rootwell local Workbench

This directory contains Rootwell's dependency-free, self-hosted browser UI.
Inspect is functional: it processes one public PEM or DER X.509 certificate in
the browser with the same bounded Go core and `rootwell.inspect.x509.v1` report
used by the CLI. Verify is still a clearly labeled interaction preview.

## Security boundary

- certificate bytes are never posted to a Rootwell or third-party HTTP API;
- only `wasm-loader.js` may fetch, and it loads the same-origin
  `rootwell.wasm` application asset;
- the loader has no DOM, selected-file, or file-byte access;
- `app.js` reads a file only after **Inspect certificate** is pressed and has no
  network, service-worker, dynamic-code, or workbench-input storage capability;
- selected values and certificate metadata are rendered through `textContent`;
- the Go core enforces the 16 MiB, one-certificate, trailing-data, and metadata
  limits before returning a versioned, secret-free response;
- JavaScript and Go entry buffers are cleared after use on a best-effort basis.

Browser-wide memory erasure is not guaranteed. This boundary is for public
certificates only. Do not select private keys, passphrases, PFX/PKCS#12 files,
or other secrets. See
[`docs/adr/0003-browser-inspection-webassembly.md`](../../docs/adr/0003-browser-inspection-webassembly.md)
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
panel and select it again. It contains one non-production public certificate
for `.invalid` names and deliberately contains no private key.

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
