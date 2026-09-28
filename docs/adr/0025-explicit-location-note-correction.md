# ADR 0025: Correct or remove exact manual location notes

**Status:** accepted for the Linux public-inventory development boundary.

## Decision

An operator can rename or remove one exact location label on a selected public
certificate. The request carries its fingerprint and displayed inventory
generation. Rename requires a new, nonempty, valid, unused label. Remove must
omit the replacement field. A ready session, same-origin POST, custom request
header, bounded strict JSON, whole-image authentication, and the private
writer lock are required. Duplicate, missing, unchanged, malformed, stale,
unauthorized, and unsafe operations cannot write.

The selected record is resealed under the next image generation and the
complete image is atomically replaced. The certificate fingerprint, DER,
owner, original import generation/time, and all other records are preserved.
If the first label is removed, the next label becomes the legacy `location`.
If the last is removed, `location` is empty and `locations` is empty; the
certificate remains in inventory. The UI requires an explicit checkbox before
removing a note and never calls a named host.

## Consequences

This is manual metadata correction, not certificate undeployment, revocation,
or verified discovery. An older full snapshot can restore the old label; a
new full snapshot is needed after each successful change. There is no edit
history or external rollback anchor. Certificate-record deletion is a
separate retention decision. No private key or network capability is added.
