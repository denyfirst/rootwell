# ADR 0023: One certificate, bounded operator-declared locations

**Status:** accepted for the Linux public-inventory development boundary.

## Decision

The certificate fingerprint remains the unique inventory identity. A record
may have up to 32 exact, nonempty, bounded location labels entered by the
operator. The first location remains in the legacy `location` field; later
ones are an optional encrypted `additional_locations` payload field. Existing
images without that field open unchanged. There is no separate certificate
copy and no deployment or endpoint verification implied by a location.

An association is an explicit same-origin, authenticated POST referencing an
existing fingerprint and the generation last displayed in the browser. The
writer lock checks that generation, authenticates the whole image, rejects a
missing certificate, duplicate/invalid/excess location, then reseals only the
selected record under a fresh image generation and atomically replaces the
complete image. An optional encrypted `import_generation` preserves the
original import provenance when the record is resealed; older payloads use
their record generation. The original `imported_at` value is preserved. The
response contains no DER or private material and remains `not-performed` for
verification.

## Why

The same public certificate can be deployed at multiple places, but uploading
it repeatedly would create misleading duplicates. A bounded extension of the
existing authenticated image avoids a new database and keeps complete
snapshot/restore semantics. Optimistic generation checking prevents a stale
tab from silently applying a note to a changed image.

## Limits and consequences

Location labels are exact text, not canonical host identities. Two spellings
may name the same machine, and one label may be reused for different
certificates during rotation. There is no automatic discovery, live probe,
proof of deployment, per-location owner, history, editing, deletion, alert,
or anti-rollback anchor. Every successful association changes the inventory
and therefore needs a new full backup; the old backup omits it. External
audit and Windows native storage remain separate gates.
