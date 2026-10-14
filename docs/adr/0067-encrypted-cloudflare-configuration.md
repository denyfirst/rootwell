# ADR 0067 — Local encrypted Cloudflare configuration before DNS execution

Date: 2026-10-14. Development, single operator, Linux/loopback only.

## Decision and scope

The user chose Cloudflare and explicitly requested storing its token encrypted
only in the user's own Rootwell. ADR 0066 / PR #97 has passed all 13 checks and
merged. This independent increment adds one optional local configuration in
the same Automation certificate-request card: check saved settings, save or
explicitly replace, and explicitly remove. No separate Vault/Inventory choice.

Saving does NOT call Cloudflare, verify token permissions, authorize DNS writes,
validate domain ownership or enable automatic renewal. Manual DNS is unchanged.
The unexported TXT protocol and retry policy remain unwired. No real credential,
CA or DNS operation was used; Porch is excluded.

## Secret and persistence boundary

One separately typed `cloudflare_configs` field enters the complete authenticated
image. Its payload is the exact canonical zone ID/name, bounded token bytes and
UTC save time. HKDF-SHA256 uses a new fixed purpose, installation identity and
the existing AES-256-GCM context of installation/record/generation. No custom
crypto, new dependency, external service or browser storage.

The complete manifest MAC authenticates before every field opens; every public
certificate/history/account/order read also validates the credential. Duplicate,
orphan, malformed/case-folded, wrong-purpose/context, tampered, unknown and
noncanonical fields refuse with no partial result. Previous images remain
readable. Previous binaries refuse the new field, rather than dropping it.

Token syntax is deliberately narrow: 40–256 ASCII alphanumeric, hyphen or
underscore bytes (including the current prefixed token style). Zone IDs are
exactly 32 lowercase hex characters; zone names are canonical ASCII public DNS
names, not wildcards, URLs or local names. This is not token validity, entropy,
credential-type or least-privilege proof. Guidance requires specific-zone DNS
Edit and Zone Read, not Global API Key or all-zones credentials. No runtime token
inspection, discovery or permission escalation is performed.

Public V1 status contains only schema/provider/generation/state/zone name/save
time/change availability and three fixed false capability flags. Neither token,
token digest nor zone ID is returned. Fixed history actions bind only a
purpose-prefixed public zone-name hash, never credential-derived data. There is
no token reveal/download/borrower API; an architecture test forbids borrowing
before separately reviewed order-bound DNS custody and lease integration.

All changes require fresh Rootwell password, explicit local confirmation, ready
session, exact host/origin/header/fetch metadata, no query, strict duplicate-free
bounded POST JSON, shared authentication/crypto budgets, exact displayed image
generation and access revision. Linux private writer lock covers full validation
and atomic replacement; live permission repeats before commit and output. A lost
response or post-rename directory-sync failure is uncertain, never automatic
retry or assumed rollback. Status reread reconciles the current image.

Initial save can accompany an existing manual request, but any rotation/removal
requires that the saved request has first been explicitly closed. Completion or
expiry alone does not relax this restriction. This conservative boundary avoids
losing future cleanup credentials; unknown orders can still need manual recovery.
Generic history/generation/issuance-byte reservations remain in force, and
certificate/material/account/order bytes are preserved. No new DNS job reservation
is claimed: job custody is still separate required work.

Complete password/recovery-code backups preserve the actual ciphertext/token,
not just public metadata; offline password recovery preserves the complete image.
Access-only backups do not include it. Removal affects only the current store,
not old snapshots or Cloudflare validity. Provider-side revocation and old-backup
retention remain the operator's responsibility. Native Windows/macOS refuse
credential storage before filesystem/permission borrowing.

## User interface and evidence

Optional expandable settings within the existing certificate request keep the
default manual workflow simple. No initial fetch or automatic provider call.
Saved status must be checked before a change; replacement/removal has distinct
confirmation text. Fields clear after requests, hidden/pagehide/changed active
source, and all errors. Redirects, late or clock-reversed replies, oversized/
wrong-schema/extra-field or invented capability responses cannot grant authority.
The total local UI limit is 15 seconds / 4 KiB; no provider error reflection.

Tests cover success/rotation/removal, secret-free image/status/history, public
and private pair preservation, active-request and pending-completion capacity,
tamper/context/purpose/malformed/stale refusal. Linux tests cover exact revisions,
permission loss at both checks, concurrent lock, 0600 storage, disk-full and
uncertain post-rename outcomes, and both full-backup unlock paths plus offline
password recovery with exact token-bearing image equality. API tests cover
fresh-auth/shared limits/logout/cancellation/origin/setup/native refusal. VM tests
cover controls, no browser storage, hidden/source/late/clock/schema refusal.

Actual compiling two-way sabotage, restored:

- Removing generation equality made
  `TestCloudflareConfigMalformedTamperPurposeAndStaleRefuseBeforeOutput` fail:
  stale configuration changed.
- Reversing the valid-configuration predicate made
  `TestCloudflareConfigEncryptedAtomicRotationRemovalAndPreservation` fail:
  legitimate encrypted credential refused.

Both then passed with the guards restored.
UI two-way sabotage also failed as intended: allowing an absent snapshot made
the no-displayed-generation/no-save assertion fail; forcing the submit button
disabled made the legitimate save-control assertion fail. Both were restored
and the full UI suite passed again. Actual public Go 1.26.9 WASM lifecycle and
bridge tests also passed, including both DNS history labels without a false
certificate or provider-revocation label.

Native fuzz samples: payload 467
executions; request 19,111 executions, each 3 seconds / 2 workers. These are
bounded samples, not exhaustive proof. Full native shuffled Go tests, module
tidy/verify, formatting/vet/build, pinned staticcheck/actionlint, native+Linux
gosec and targeted UI/demo suites ran. Actual Linux storage/API/full recovery/
race execution remains an exact-head CI gate; cross-vet is not execution.

Windows browser preview uses the actual UI with an explicitly fake/read-only
server: inputs/save disabled, no token saved and no real DNS. It is visual QA,
not positive Linux custody, Cloudflare interoperability or independent audit.
Every required exact-head check and separately recorded adversarial maintainer
self-review is required before merge. No bypass, release or deployment.

## Remaining work and risks

Next: CA-derived order-bound TXT ownership and persistent attempts, opaque
exact-image lease, intent-before-I/O/checkpoint/result commits, uncertain read-only
reconciliation, cleanup capacity and closure policy, then explicit DNS operation
UI. Retry policy is not yet persisted/scheduled; unattended unlock/ARI and
production audit remain separate. Provider zone-level permissions exceed the
local TXT policy; successful reads cannot prove limited grants. ADR 0066's
concurrent external-edit/GET-to-DELETE and narrow provider profile residuals remain.

Host/admin/browser/runtime compromise can access decrypted data; this is not
end-to-end encryption, HSM isolation, multiuser RBAC or reliable heap erasure.
Owned byte buffers are cleared where practical, but decoder/JS strings and
runtime/OS copies remain. Complete old-image rollback, old snapshots and clock
rollback are not prevented. Refresh after uncertain local saves; renew the full
backup after mutations. No production-user secrets before independent audit.

Primary references checked 2026-10-14:
[Cloudflare token scoping](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/),
[DNS creation permissions](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/).
