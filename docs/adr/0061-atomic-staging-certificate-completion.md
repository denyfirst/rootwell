# ADR 0061 — Atomic staging pair completion and honest saved-state UI

Date: 2026-10-12. Internal custody completion and public status increment.

Supersede ADR 0060's pending-only custody state with one atomic acceptance
transaction. This does NOT export/wire ADR 0059's network connector or enable
an issuance button, production enrollment, renewal or can_issue. Porch and
offline Workbench are unchanged. Full live issuance integration remains next.

FinishStagingIssuance accepts only bounded public DER from a trusted internal
same-order receipt path, never a supplied key, trust bundle, result or override.
Production repeats the real ADR 0058 independent pinned-staging Check against
the exact encrypted prepared key/CSR/names. No root/system-trust fallback.
Unexported checker/time seams exist only for isolated synthetic custody tests;
architecture freezes their production callers. Certificate bytes alone do not
prove an order relationship; future live transport must still bind the receipt
to the exact saved order/account/lease and retain all ADR 0059 guards.

Require authenticated pending intent, current expected generation, canonical
clock and earliest saved unexpired order. Check result must retain test-only,
exact leaf/key/CSR/names/evaluation time and ordered chain identities. No duplicate
record/overwrite, partial pair or provider-text error. The public production
wrapper checks expiry/backward clock again before publication; Linux repeats
order expiry/live permission before the atomic replacement under the private
writer/revision lock. This standalone writer is not called from a live route.
Future fetch-and-complete integration must use the same lock/intent boundary,
not recursively acquire this lock from the older pending-only runner.

One new complete image contains exactly one leaf record, matched encrypted
material with the supplied ordered public chain and SAME private key, public
CSR/scope transfer tombstone, sealed completion provenance and fixed history.
Private bytes move out of the prepared request; they are not duplicated there.
Account/order ciphertext is unchanged. Other records/notes remain untouched.
Commit once, advance generation once. The reserved final history/generation/
record slot is usable by completion and reservations release ONLY with the
completed state. Tests exercise the actual last history/generation slot.
Response ceiling is the connector's five certificates; existing per-material
128 KiB plaintext and image limits still apply. A larger otherwise valid chain
may refuse storage; intent remains and no saved success is claimed. Headroom
is not a guarantee that every protocol-sized response can be stored.

Every image decode authenticates completion before ANY public records/history.
Link exact leaf/material/prepared CSR/key/account/order/names/time/generation/
chain fingerprints; reject orphan/mismatch/duplicate/tamper/manufactured flags.
Provenance is immutable authenticated historical acceptance, not a new current
trust decision. It does not rerun issuer trust at list/restore time: expiry or
future trust-set updates must not lock users out of their saved keys. Key/CSR
and material match/signature structural checks still repeat. Ordinary import
cannot manufacture origin. Consumers must not treat it as current trust,
revocation, CT, production validity or deployment proof. Old binaries refuse
new payload fields; legacy images without completion remain compatible.

Metadata edits preserve origin; key export follows the existing fresh-password,
separate output-password and matched-pair gates. Delete atomically removes the
current certificate/material/key/public CSR and retains only the sealed public
no-replay completion tombstone. It cannot recreate a key/order or regain a
first/read-only network lease. Old backups retain the key; deletion is not
cryptographic erasure. Global full-history/generation limits remain: an image
at the ultimate write ceiling cannot be mutated without future retention policy.

The v4 existing manual-DNS status reads order/key/issuance from one authenticated
writer-locked snapshot. Existing DNS/key actions refuse started/saved/deleted
issuance BEFORE authentication/provider work. No new mutation/network route.
can_issue remains false. Strict UI states clear old authority, explain incomplete
or closed requests and link saved results to Certificates; no false "not issued"
message on a completed image. Unknown/forged fields/observations refuse without
partial UI. Certificates mark test-only/not for production and show historical
acceptance under Details, never private key/CSR/account/order URLs.

Evidence: exact-key atomic move, unchanged account/order, pairing/export/notes,
whole-image scope/provenance/orphan/tamper refusal, duplicate/non-success/stale/
clock/expiry/check-result refusal, final-slot completion, deletion/no-replay,
native refusal and Linux revision/permission/writer checks. Linux full restore
and password recovery use a dynamically generated synthetic completed image,
created in an isolated child Go test via the unexported custody seam; its key
and encrypted image enter only a private temporary file, NOT stdout/source/CI
artifacts. No production trust configuration is changed. The real production
entry explicitly rejects this synthetic issuer. This demonstrates custody and
restore, not positive live staging interoperability. Existing real receipt
checker tests independently cover issuer acceptance/refusal policy.

Public UI/history real Go WASM VM, strict v4 closed-state VM and read-only demo
tests passed. Actual in-app browser displayed the fake saved test-certificate
card and expanded Details on 127.0.0.1:4181/certificates; explicit DEMO/status-only
labels, key actions disabled, no real key/receipt. This is visual QA of that
read-only fixture, not the real Linux authenticated issuance flow. Parser fuzz
ran 20 seconds/two workers: 11836 executions; target is scheduled.

Actual compiling two-direction sabotage, restored: removing accepted.TestOnly
refusal failed TestCompletionRefusalsAndReservedFinalGenerationHistorySlot with
"forged check result manufactured custody"; refusing every nonempty response
failed TestCompletionAtomicMoveProvenanceNotesExportDeleteAndNoReplay with
"valid checked pair completion refused". Restored tests passed. A missing test
import was a compilation correction, not sabotage evidence. Gosec's G117
serialization flag is narrowly documented: PrivateKey is explicitly nil before
public CSR/scope serialization and immediate AES-GCM sealing. No blanket bypass.

Residuals: trusted callback/host/runtime copies, old authenticated complete-image
rollback, best-effort rather than heap/scalar erasure, manual backup, duplicate/
oversize receipt recovery, expired/new-order/reset/retention policy and current
clock dependence. Live transport/lease/receipt/commit integration, fresh password/
one-use consent/provider budgets and interactive issuance UI remain next.
Renewal/DNS adapters and independent production audit remain later work. Full
local/pinned and exact-head Linux race/restore/platform/container/signature/
vulnerability gates plus separate maintainer self-review precede merge.

Local final-source evidence: full shuffled Windows suite, formatting/tidy/module
checksums, vet/build, Linux/macOS cross-vet, pinned staticcheck/actionlint and
native/Linux-target gosec passed. Live govulncheck passed with zero reachable or
imported-package vulnerabilities; its unused/architecture-forbidden OpenPGP
module-only finding is unchanged. Strict v4/library/demo and real-WASM history
VM tests passed. Actual Linux completion/restore/API and race execution is still
required from exact-head CI; cross-vet is not that execution.
