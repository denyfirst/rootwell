# ADR 0036: One-shot browser worker for private-key conversion

**Status:** accepted for development Workbench; independent release audit pending

**Date:** 2026-10-05

ADR 0035's bounded encrypted PKCS#8 import previously ran on the browser UI
thread. The private Convert UI now sends each inspection or export to a fresh,
one-shot dedicated worker. The already loaded, same-origin WebAssembly module
is structured-cloned to that worker. Its script imports only the matching
same-origin Go runtime; it does not fetch the module or make an HTTP request.
No key or password is sent until the worker reports that its Go entrypoints
are ready. Input and password buffers are bounded before cloning, transferred
to the worker, and cleared best-effort there. The caller-owned buffers are
cleared independently. Output bytes transfer back only on export and are
cleared by the UI after the browser-managed download request.

The client terminates the worker after one response, on file-selection abort,
on malformed/failed worker messages, or after a deadline measured from worker
creation: 30 seconds for inspection and 60 seconds for export. Timeout or
worker failure gives no download; a late result cannot update a newer file
selection or a changed output/password choice. There is no synchronous
main-thread fallback. The authenticated
`rootwelld` route serves the worker script with `connect-src 'none'` and
`worker-src 'none'`; the parent allows only same-origin workers. The static
preview remains unauthenticated and does not itself supply response headers.

This is a responsiveness and bounded-work control, **not** a proof of memory
erasure or a process sandbox. Worker termination does not guarantee that JS,
Go, browser, or OS copies disappeared. The main Workbench still contains the
general Go/WASM module, although the private Convert UI no longer invokes its
private functions on the UI thread. Malicious same-origin code, extensions,
and a compromised host remain outside the boundary. PFX and key reveal remain
unsupported in the browser. This change does not authenticate CBC ciphertext
or remove the need for independent release audit.

The repeatable synthetic browser smoke page generates a key in memory and
checks inspection, encrypted export, and encrypted re-import through the real
worker and Go/WASM bridge without a download. Node tests separately exercise
deadline, abort, transfer, malformed messages, and one-shot refusal. The
smoke page is available only from the loopback development preview, not from
the authenticated production asset map.
