# ADR 0051 — Prepare one encrypted staging account key locally

Date: 2026-10-08. Status: development implementation; not production approval.

## Boundary

The next ACME increment prepares and saves one newly generated ECDSA P-256
account key on the operator's Linux daemon. It is **not** a certificate key or
a registered CA account. No provider request, email/domain submission, terms
acceptance, account URL, order, DNS change, issuance or renewal is introduced.
The existing directory-only connector remains unchanged. Production/custom
providers, key import/export/reveal/reset and EAB are outside this increment.

Automation offers an explicit status refresh and an explicit local preparation
with fresh Rootwell password and one-use confirmation. No automatic request or
preparation on page load. Status contains only fixed capability flags, public
SPKI fingerprint, prepared UTC time and complete-image generation. Native
Windows/macOS refuses custody; no emulated persistence or fake success.

## Storage and authorization

A separate `acme_accounts` manifest field has at most one staging entry. Its
canonical payload binds provider, prepared-only state, time and canonical
PKCS#8 P-256 key. A distinct HKDF-SHA256 purpose key plus existing AES-GCM codec
binds installation, fixed staging record identity and generation. Every image
open validates this entry before returning certificates/history. It never
appears as a certificate attachment or gains a signer/export API here. Old
binaries refuse the unknown field; older images remain readable unchanged.

Preparation holds the existing private writer lock, compares exact access
revision and displayed image generation, refuses an existing account key and
checks live session/cancellation after crypto preparation immediately before
atomic replacement. No queue: the shared KDF/crypto slot and five-per-minute
authentication attempt budget apply. File permissions, rename, directory sync,
readback and post-rename uncertainty reuse the existing Linux writer.
Cancellation/logout after the commit boundary cannot undo a write: refresh
status after signing in, never blindly replace the key. All results are fixed,
secret-free, no-store. Status needs ready same-origin authority too.

One encrypted history event (`acme-key-prepared`, public key fingerprint) is
committed with the account in the same image. Certificates UI labels this as
account-key activity, not an added certificate. Existing certificate mutations
preserve the account; full snapshot/restore/recovery carries the same key.
Backup is manual and must be repeated after preparation. Access-only backups
do not contain it. Older complete backups can restore a different/absent key;
there is no external anti-rollback anchor or reliable runtime zeroization.

## Next capability gates

Registration will reuse this same durable signer, require fresh authentication
and an explicit current terms decision, bound all nonce/JWS/account URLs and
responses, and persist uncertain outcomes for same-key reconciliation. An
offline preparation never counts as that decision. Manual DNS-01 issuance and
certificate-key custody remain subsequent separately tested increments.

Protocol references checked 2026-10-08: [RFC 8555 account management and key
selection](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3), and
[Let's Encrypt's separate staging accounts](https://letsencrypt.org/docs/staging-environment/).

## Required evidence

Generated key round trip; stale, duplicate, corrupt/cross-context/purpose,
noncanonical/wrong curve/algorithm/provider/state/time refusal; unchanged image
on failure; metadata secret exclusion; certificate mutation preservation;
Linux permission/lock/revision/session refusal; full password/code restore and
lost-password recovery; container restart/restore; ready/setup/origin/strict
JSON/KDF budget and cancellation boundaries; UI bounded/no-storage/late-result
refusal; positive and negative deliberate sabotage. Maintainer self-review and
all required CI gates precede merge; independent audit precedes real-user release.

## Deliberate sabotage evidence

Removing the exact-generation mismatch refusal failed
`TestStagingAccountPreparationIsEncryptedAtomicAndPreserved` with "stale
preparation was accepted"; always refusing failed "valid preparation refused".
Removing the UI consent guard failed `scripts/test-acme-account.mjs` at
"password alone must not generate a key"; always refusing preparation failed
the approved-success request assertion. All four mutations were restored and
the success/refusal tests rerun. These checks detect those specific defects,
not every possible security issue. VM/DOM assertions are not visual browser QA.

Adversarial self-review added an explicit import/HTTP-selector capability guard
to the local account API, rather than relying only on its lack of provider calls.
This complements the existing architecture and no-network API fixtures; it is
a regression check, not a runtime sandbox or an independent audit.
The same self-review tightened browser fetch to refuse redirects explicitly,
clear its owned serialized request body before awaiting a response, and require
exact JSON media type and the same prepared-date policy as storage. Redirect
policy/media/date refusal is covered by the UI regression harness. Already
copied browser/runtime strings still cannot be reliably erased.
