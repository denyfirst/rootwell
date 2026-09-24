# ADR 0003: Browser inspection uses the Go core through WebAssembly

**Status:** accepted

**Date:** 2026-09-24

## Context

The local Workbench UI must inspect certificates without uploading them to a
Rootwell API or introducing a second X.509 parser. A loopback HTTP API would
move input bytes across a new request boundary and require defenses for CSRF,
DNS rebinding, origin validation, request logging, and local port discovery. A
JavaScript parser would duplicate the security-critical Go implementation. A
desktop shell would add a large runtime and dependency-review boundary before
it provides a necessary benefit.

Browser code must load its WebAssembly program from somewhere. Therefore
"network disabled" is not an honest description for a self-hosted web build:
the browser fetches same-origin application assets. The security claim is that
certificate bytes are never submitted to an HTTP API and no third-party asset,
telemetry, or connector request exists.

## Decision

The first functional browser operation is inspection of one public PEM or DER
X.509 certificate. It compiles the existing Go `certinspect` package and the
shared `rootwell.inspect.x509.v1` report into a `js/wasm` module.

The browser boundary has these rules:

- a dedicated loader may fetch only the same-origin `rootwell.wasm` asset;
- the loader has no DOM, file-selection, or file-byte capability;
- the application script may read the explicitly selected file but has no
  `fetch`, XHR, WebSocket, beacon, service-worker, or storage capability;
- parsing starts only after the operator presses **Inspect certificate**;
- the JS and Go entry buffers are cleared after processing on a best-effort
  basis;
- the Go core enforces the same 16 MiB, one-complete-certificate, metadata, and
  trailing-data limits as the CLI;
- the response has a versioned success/failure envelope, fixed error messages,
  and no raw input, path, stack trace, or private-key field;
- all certificate-derived values enter the DOM through `textContent`;
- the Workbench has no certificate upload endpoint.

The CSP includes `'wasm-unsafe-eval'`, which permits WebAssembly compilation
without permitting JavaScript `eval` or inline scripts. Ordinary
`'unsafe-eval'` and `'unsafe-inline'` remain forbidden and are guarded by the UI
contract tests.

The self-hosted origin and the exact Rootwell build assets are trusted. A
compromised origin can replace JavaScript or WebAssembly and is outside the
claim of an uncompromised Rootwell build. Operators must serve the build over
an authenticated administrative origin with the documented HTTP security
headers and the correct `application/wasm` media type.

This boundary is for public certificates only. Clearing visible input buffers
does not prove that a browser, Go runtime, garbage collector, extension, crash
reporter, or compromised host retained no copy. Private keys, passphrases, PFX
files, and other secrets require a separate decision and are not accepted by
this browser bridge.

## Build and packaging

`rootwell.wasm` and the matching Go `wasm_exec.js` runtime are generated from
the exact Go version declared in `go.mod`; generated artifacts are not source-
controlled. CI compiles the WebAssembly module, caps the artifact at 16 MiB,
checks the JavaScript syntax, and verifies the runtime shim exists. A release
bundle must package the matching pair and its checksums together.

Direct `file://` opening remains a visual fallback only. Functional inspection
requires a static server because browsers do not consistently permit local
WebAssembly loading and because the deployment must send HTTP security headers.

## Rejected alternatives

- **Loopback parsing API:** unnecessary request and local-network boundary for
  an operation that can run in-browser.
- **Independent JavaScript X.509 parser:** duplicates validation logic and adds
  a dependency/supply-chain surface.
- **Desktop shell now:** materially larger runtime before it is justified.
- **Online conversion service:** violates Rootwell's local-first product
  boundary.

## Consequences

The browser and CLI now share one inspection model and parser policy. The
WebAssembly artifact is several megabytes and requires correct static hosting.
Same-origin asset loading is allowed by CSP, so code review and capability-
separation tests must continue to ensure the file-reading script cannot use
network APIs. Verify, conversion, key matching, and secret-bearing operations
remain outside this browser increment until each boundary is separately
reviewed.
