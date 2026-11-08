# ADR 0087: Import one PFX in Certificates

## Status

Development, 2026-11-08. Independent release audit remains pending. Builds on
the bounded PKCS#12 profile of ADR 0031 and the library boundary of ADR 0047.

## Decision

The existing Add a certificate form accepts one `.pfx` or `.p12`, case
insensitively. The extension selects the UI path; the existing authenticated
PFX parser decides whether the content is supported. Mixed PFX/public/key
selections refuse. The separate key picker is hidden, the current PFX password
is requested, and optional Check / direct Save and service notes stay in the
same form. Clear selection cancels and clears the form. Public-only bulk and
the separate Workbench converters keep their existing refusal boundaries.

No new server PFX decoder, API field, storage image format or dependency is
introduced. A dedicated one-shot worker receives a compiled fixed same-origin
WASM asset first, then bounded file/password copies only after readiness. Its
CSP denies connections and child workers. It uses the existing modern-profile
MAC authentication, single matching non-CA RSA/EC key and complete public bag
enumeration. Existing certificatepair policy rejects unrelated/ambiguous
collections; every supplied public certificate must be preserved. Included
roots remain material, never trust anchors. Legacy, empty-password, multiple
matching leaves/keys, CA-key, unsupported, malformed and tampered PFX refuse.

The worker generates 32 bytes through crypto/rand and uses the existing
PBKDF2-HMAC-SHA256/600000/AES256 encrypted PKCS#8 exporter and round-trip check.
Only public PEM, encrypted PKCS#8, its temporary 43-character password and the
full matching certificate fingerprint leave the worker. The temporary password
must differ from the PFX password. No plaintext key output/reveal/download is
added. The PFX container/password never enter the normal server request.

The trusted UI passes these prepared inputs to the existing same-origin
certificate Check/Save API. The temporary password accompanies the encrypted
key so the server can independently decrypt, recompute key match and repeat
validation in the locked atomic writer. This is not end-to-end encryption or
protection against a compromised UI/host. The original PFX password is kept
separate from server custody. Server ready-session, exact generation,
duplicate/no-overwrite, no-store, encrypted image, backup/restore and export
fresh-auth controls are unchanged; redirects are explicitly refused.
Publication is revalidated after the atomic Save as well: loss of session or
cancellation after a durable commit returns an uncertain outcome, never a
false success or a definitive no-write refusal. Restore must retain that pair.

Each Check/Save rereads and reauthenticates the source. Pending preview binds
the original PFX byte digest and file identity, not randomized encrypted output.
The full server fingerprint and matched verdict must equal preparation; a
PFX mismatch cannot use the separate-attachment acknowledgement. No private
bytes or temporary password are retained in pending preview state. The current
password field remains available for the explicit Check/Save sequence, then
clears on success, error, source/generation change, Clear selection, timeout,
hidden or page exit. No cache/storage/URL or background job is introduced.

## Limits and evidence

One PFX <=1 MiB, password 1–128 non-space printable ASCII bytes, at most 16
related public certificates subject to existing bundle/DER budgets, encrypted
key <=64 KiB. Worker deadline 90 seconds; whole PFX preparation/API operation
150 seconds. Source/password/generation changes, timeout, hidden/pagehide and
late results cannot start or publish a stale request. A sent Save with lost
confirmation stays uncertain; refresh is required before retry. Backup stays
manual. The original container, bag attributes and file name are not stored.

Visible KDF work is bounded by the existing preflight. The decoder may conceal
inner work inside an encrypted safe and has no cancellation API. A worker is
a responsiveness boundary, not a proof of resource safety or a host sandbox.
Owned buffers are cleared best-effort; JS strings, Go/dependency/OS copies,
network tooling and old backups cannot be guaranteed erased. Existing stored
key/image limits and authenticated CPU costs remain release-review items.

Generated native and actual Go WASM/UI tests, independent Node/OpenSSL key
validation, worker protocol/cancellation/transfer tests, Linux atomic save and
full restore, exact API/asset/CSP refusal tests and a scheduled wrapper fuzzer
cover this increment. Full final-head CI/race, deliberate sabotage and a
separately recorded maintainer self-review are required before merge. These
are development evidence, not independent audit or real-user custody approval.
The Windows browser fixture remains synthetic/read-only. No Porch change,
live CA/DNS operation, automatic renewal, deployment or release is included.
