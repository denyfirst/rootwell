# Rootwell Workbench UI foundation

This directory is a dependency-free, static interface preview for the future
local Workbench. It establishes Rootwell's visual language and the Inspect and
Verify interaction model without widening the current CLI trust boundary.

## Current boundary

- no remote fonts, scripts, styles, images, analytics, or telemetry;
- Content Security Policy denies every connection;
- selected file names and sizes are displayed with `textContent` only;
- file bytes are not read, parsed, uploaded, cached, or stored;
- the only browser storage is the explicit light/dark theme choice;
- all certificate results are fixed sample data and visibly labeled as such.

This preview is not the production browser processing engine. Connecting it to
the existing Go certificate core requires a separate decision: a reviewed
loopback service, WebAssembly, or a desktop shell. That decision must cover
origin checks, request limits, memory clearing, CSP delivery, CSRF and DNS
rebinding where applicable, packaging, and platform behavior before user files
are processed.

Open `index.html` directly or serve this directory with a development-only
static file server. A preview server is not part of the Rootwell product.
