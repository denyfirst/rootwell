# ADR 0027 — Explicit public inventory metadata export

**Status:** superseded for the Inventory UI, 2026-09-28. The metadata export was removed from that page after user testing found it confusing with certificate export. Certificate download belongs in the Workbench Explore/Verify flows; encrypted inventory backup remains a separate offline operation.

## Decision

The authenticated Inventory page exports only a caller-selected subset of
the already-loaded, structurally validated public metadata response. It uses
an exact field allowlist and a versioned JSON schema with an explicit
`verification: not-performed` boundary. The operator must first preview the
complete JSON and then separately request a browser-managed download. Any
selection, view, or inventory refresh change invalidates the preview. An
export is capped at 4 MiB. No DER, PFX, private key, or unrecognized API
field is copied into the report. No export terms or bytes are sent to a new
server endpoint or retained in browser storage.

Certificate subjects, SANs, owner names, and manually entered location
labels can expose internal topology. Rootwell encrypts its own stored image,
not downloaded files. The browser and operator choose the file destination;
this is not a secure backup format or a verified chain report.

## Visual development fixture

A separate `--fixture-only` script serves the current UI with generated fake
records on `127.0.0.1`. It disables file Save and metadata buttons, and its
server refuses all writes. It exists so unsupported Windows hosts can review
the UI without implying that durable inventory is enabled or authenticated.
It must not be used as a production service.
