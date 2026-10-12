# ADR 0060 — Durable staging issuance intent and opaque single-use lease

Date: 2026-10-12. Internal custody increment of the approved issuance wave.

Add an authenticated, HKDF-purpose-separated AES-GCM issuance field to the
existing complete inventory image. No route, live network call, issuance UI
button, receipt acceptance, pair transfer, production enrollment or can_issue
authority is added. ADR 0059's certificate connector remains unexported and
unwired. The full issuance wave is unfinished. Porch is excluded.

Intent binds the exact registered account, saved unexpired/domain-verified
order, canonical names, existing prepared certificate public-key fingerprint
and exact CSR hash. The private key/CSR remain in their original sealed request;
intent does not generate, duplicate or replace them. Every image decode checks
the entire issuance field before public inventory/history can escape. Wrong
purpose, installation, generation, scope, time, ciphertext, duplicate field,
malformed/noncanonical JSON and fabricated issued observations refuse wholly.
Public status contains only state and observation times, never keys/CSRs/URLs.
Older binaries refuse the new manifest field; images without it remain unchanged.

The pure image layer mints an opaque process-local attempt bound to the exact
new image hash/generation. Copies share one atomic consumed state. Only the first
new intent can mint finalize authority. Serialization yields no transferable
authority; zero, stale, altered-image and already-used attempts refuse before
the trusted callback. Reopened/restored intent can mint only same-order read
leases, never another finalize, including when the CA still reports ready.

The pure layer cannot prove that a caller committed an image. The Linux private
writer is the required commit boundary: private writer lock, current access
revision/generation and live permission, atomic intent installation BEFORE
borrowing the signer/exact key/CSR to the callback, then separately atomic
non-issued observation/history. The lock spans the entire operation. Failure,
revocation or uncertain post-rename result retains intent and returns no partial
status. Callback errors become a fixed uncertainty error, not provider text.
First-attempt success can store only a processing observation; received/valid
certificate claims cannot be stored as observations or create a pair. Native
Windows/macOS refuses before file access, permission evaluation or callback.
Fresh password, one-use consent and provider budgets are future live caller
obligations, not implemented by this internal callback seam.

Read-only reconciliation intentionally does NOT write another intent or discard
historical non-issued observations. The already durable irreversible intent
covers these reads and no observation grants issuance, deployment or trust.
CheckedAt is historical evidence, not a current CA verdict or success. This
allows same-order read authority even at the last history/generation completion
slot; a later observation write may still refuse capacity and must not claim it
was saved. Future UI must make stale/failed refresh explicit. This differs from
domain validation, whose prior success could otherwise authorize issuance.
Domain-validation mutation is blocked while issuance intent exists.

Before irreversible intent, reserve one final generation, one history event,
one certificate record and conservative 1 MiB image headroom. Ordinary import,
metadata and non-issued observation writes preserve these reservations. Full
images validate the reservations on decode too. This prevents unrelated writes
from consuming the completion slot; it is NOT an atomic-pair implementation.
Receipt acceptance under the same writer lock, exact prepared-key transfer,
immutable test-only provenance and release of these reservations require a
separate reviewed completion transaction. No completed/issued state exists here.

Full password/recovery snapshots preserve this field without special copies.
Linux tests exercise actual full restore and password recovery, verify unchanged
account/private key/CSR, refuse a second first attempt, and permit read-only
reconciliation after recovery. Restored inventory remains private mode 0600.
Human-readable history recognizes the two non-success events and labels their
identity as a certificate key, not an account key. Unknown events still refuse
the entire activity response. No additional UI authority is implied.

Residual risks: a trusted callback can retain/misuse borrowed keys; this is not
a sandbox/HSM. Owned byte slices are cleared best-effort, not reliable heap or
ECDSA scalar erasure. Old complete authenticated pre-intent images can roll
back intent; host compromise and malicious rollback are outside this guarantee.
No automatic retry, new/expired-order policy, cleanup/reset or renewal is added.
Manual full backups, immutable provenance/pair completion, fresh-auth/consent
live integration and independent production audit remain required. No public
CA/DNS operation or browser visual QA is claimed.

Evidence: successful exact-scope borrowing, copied/concurrent lease refusal,
encrypted/public-output boundaries, strict whole-image tamper/purpose/time/scope
refusal, stale/clock/expiry/image binding, history/generation/record/byte reserves,
commit-before-callback, writer lock/revision/permission checks, native refusal,
full restore/recovery, unknown/success-like event refusal and no live wiring.
The real Go WASM lifecycle VM and five existing ACME VM scripts passed; these
are fixture HTTP/DOM tests, not visual QA. The optimized 20-second/two-worker
issuance payload fuzz run passed 17635 executions (the initial fixture-per-input
run achieved only 11). Fuzzing is not exhaustive proof. This target is scheduled.

Actual two-direction compiling sabotage, then restored: removing the atomic
consume condition failed TestIssuanceIntentExactScopeEncryptionAndSingleUseReadOnlyRecovery
with "copied handle replayed finalize"; rejecting absence of intent failed the
same test with "valid issuance intent refused". Restored issuance tests passed.
A discarded giant-whitespace fixture was rejected by existing canonical JSON
validation; it is not byte-budget evidence. The final byte-budget test exercises
the exact capacity predicate without a 96 MiB allocation. No sabotage remains.

Full local/pinned and exact-final-head Linux race/recovery/container/platform/
signature/vulnerability CI gates and separate maintainer self-review precede
merge. These are development gates, not independent production audit.

Local evidence: complete shuffled Windows suite, fmt/tidy/module verification,
vet/build, Linux/macOS cross-vet, pinned staticcheck/actionlint, native and Linux
target gosec passed. Live govulncheck passed with zero reachable/imported-package
vulnerabilities. Its module-only GO-2026-5932 finding concerns the unused and
architecture-forbidden x/crypto/openpgp package; Rootwell does not import it.
The lease-serialization regression intentionally marshals an opaque empty
object; a narrowly documented test-only SA9005 suppression retains that check.
Actual Linux full-recovery and race execution is required in exact-head CI,
not inferred from Windows tests or cross-vet.
