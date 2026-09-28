# ADR 0024: Explicit correction of an unverified owner note

**Status:** accepted for the Linux public-inventory development boundary.

## Decision

An existing public certificate can have its operator-declared owner label
replaced or explicitly cleared to unknown. The certificate fingerprint is the
identity; the caller supplies the image generation last displayed. A ready
session, same-origin POST, custom request header, bounded strict JSON, and
private writer lock are required. A no-op, stale generation, malformed label,
missing certificate, invalid session, or unsafe image cannot write.

The complete image is authenticated before lookup. Only the selected record
is resealed under the next image generation; DER, locations, original import
generation, and original save timestamp remain unchanged. The response omits
DER and keeps `verification: not-performed`. The UI calls this a manual note,
not verified ownership.

## Consequences

The current encrypted inventory holds the latest owner note, not a
tamper-evident edit history. An older full snapshot can still contain the old
owner and can restore it; after any correction the operator needs a fresh
full snapshot. Clearing an owner does not delete the certificate, remove any
location, or erase older backups. No private key or new network capability is
introduced. Native Windows durable inventory and independent release audit
remain separate gates.
