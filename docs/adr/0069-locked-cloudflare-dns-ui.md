# ADR 0069 — Locked Cloudflare TXT transaction and explicit UI

Date: 2026-10-20. Development, single operator, Linux/loopback only. Porch is
excluded. No customer token, live DNS/CA test, production release or scheduler.

## Decision

Connect ADR 0066/0067/0068 through ONE writer lock: authenticate the complete
image and exact revision/generation, prepare the CA-derived plan if needed,
commit the attempt and irreversible intent, consume its exact-image lease once,
borrow only that plan's credential, invoke the fixed bounded Cloudflare protocol,
validate the state transition, then atomically save the observation/wait. Check
permission before each commit, network boundary and final publication. No API
can supply TXT, owner marker, zone ID, record ID, network target or verdict.

Each explicit click operates on one displayed domain. First add can POST once;
reopened creating is read-only even if the process died before sending. Created
records retain the exact provider ID. Cleanup first persists deleting, then the
protocol rechecks ID/type/name/value/marker before one DELETE. Reopened deleting
is GET-only and cannot repeat DELETE. Existing records are borrowed, never
owned/deleted. Provider observations are not DNS propagation or CA verification;
the existing separate CA-check step and manual alternative remain.

## Budgets, expiry and recovery policy

Provisioning/reconciliation and cleanup have SEPARATE persisted six-attempt
budgets. Every invocation consumes its attempt before I/O, preserves exponential
jitter and longer provider Retry-After, and refuses early/backwards clocks.
Capacity reserves cover all remaining attempt/result transitions in both phases,
in addition to independent CA/issuance and byte reserves. Invalid/overlong hints
block only that phase; no reset, automatic retry or abandoned ownership.

DNS byte reservation is 64 KiB payload/closure slack PLUS 2 KiB per remaining
transition (including a permanent unresolved-recovery slot), independently added
to pending issuance. It decreases when an intent/outcome consumes its reserved
slot; the previous fixed 64 KiB reserve could not fund writes at its own boundary.
Capacity tests measure actual serialized intent/result growth against released
bytes, exercise every cleanup attempt at the nonce boundary, and ensure ordinary
writes cannot spend remaining reservations. The encrypted DNS payload cap is
16 KiB for eight long names with separate cleanup counters. Outcome timestamps
prevent backwards-clock authority even when the minimum wait already elapsed.

First creation requires an unexpired pending CA TXT request. Reconciliation and
cleanup must remain possible after CA expiry/completion, but cannot create new
records, validate domains, reissue or reopen a request. Any unresolved creating,
created or deleting row blocks local closure and token rotation/removal. Only
new, borrowed and deleted rows can archive without active authority.

If creation remains uncertain or a deletion may not have happened, the operator
must inspect Cloudflare, leave foreign records alone and use remaining explicit
read-only checks. Exhausted/blocked phases fail closed and keep encrypted scope;
they cannot be reset or declared cleaned by user input. Provider/host failures
may therefore require a separately reviewed maintenance recovery increment;
this release does NOT promise unlimited recovery or automatic cleanup. Keep a
new full backup after changes. Complete old-image rollback/host compromise and
late provider processing are not solved. No blind fallback POST/DELETE.

## Concurrency, UI and authority

Cloudflare does not supply a documented atomic content/marker compare-and-delete
in the reviewed delete contract. Explicit cleanup consent MUST disclose and
confirm exclusive editing of these Rootwell-owned records during the operation.
Exact ID is not atomic unchanged-content protection against external writers.
The protocol never widens to PATCH/PUT or deletes borrowed records. Sources:
[create](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/),
[list](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/),
[delete](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/delete/)
(reviewed 2026-10-20). Fake TLS tests do not establish live interoperability.

Automation gains an optional Cloudflare section in the existing request card,
not another product page. Read saved DNS status first; choose one domain, then
add/check/cleanup with fresh Rootwell password and explicit action-specific
consent. Shared auth/KDF/provider budgets, strict bounded POST JSON, ready
session, exact host/origin/header and no-store apply. No automatic CA check or
background credential unlock. Browser clears password/authority on hidden,
source change, timeout, error and cancellation and rejects late/mixed results.
Native Windows/macOS refuse before secret borrowing; any browser preview is
synthetic/read-only, not a claimed successful provider operation.

## Acceptance

Success/refusal/malformed/stale/foreign/replay/expiry/wait/budget tests; actual
Linux writer/permission/fault/full-recovery/race; TLS protocol request assertions;
UI model and browser QA; deliberate two-way sabotage; pinned full local checks;
signed PR, every required CI, separate adversarial maintainer self-review and
merge commit. Independent production audit remains a separate release gate.

## Recorded local evidence

Real compiling sabotage and restoration: removing the checkpoint requirement
failed the no-intent malformed-result test; reversing created acceptance failed
the legitimate owned workflow. Removing deleting from read-only direction failed
the unknown-cleanup budget test; reversing direction failed legitimate first
write acceptance. All guards restored, targeted tests pass. Lease validation is
also a second barrier: the direction sabotage was refused before a repeated
DELETE, not evidence of a transmitted deletion.

Native shuffled full Go/module/format/vet/build, pinned staticcheck/actionlint,
native/Linux gosec and Linux/Darwin cross-vet pass. Govulncheck: no reachable or
imported-package finding; one required-module-only unused residual. UI VM tests
exercise add/read/cleanup, separate exclusive consent, source/phase/counters,
wait/exhaustion and malformed/hidden/late/error/clock refusal. Actual rebuilt
WASM/history checks, fuzz samples, Linux CI execution and separate final review
are recorded with the signed PR. A Windows in-app browser shows the real same-
card UI against four fake read-only DNS statuses, not an actual provider call;
mutation/password controls and fixture endpoints refuse operations. Early
visible-tab attachment failed; background browser attachment succeeded and the
actual rendered form/statuses were inspected and captured.

Three-second/two-worker local fuzz samples: request parser 50,190 executions;
sealed DNS payload 440 executions (before adding explicit owned/cleanup state
seeds). These are short development samples, not exhaustive parser assurance.

## 2026-10-23 dependency security gate

The resumed scan found reachable standard-library GO-2026-6809 in Go 1.26.9,
through certverify.Verify to crypto/x509.Certificate.Verify. The Go advisory
reports the compromised-intermediate distrust fix in Go 1.26.10. Raise only the
module patch minimum and official Docker build image to 1.26.10; pin the latter
to the digest returned by Docker Hub's authenticated library/golang registry
manifest endpoint. Do not suppress the finding, change system roots or modify
the host-global Go install. Repeat full gates and actual rebuilt WASM on the
patched toolchain. Prior 1.26.9 scan success is historical, not current evidence.
Sources: [Go advisory](https://pkg.go.dev/vuln/GO-2026-6809),
[Go release history](https://go.dev/doc/devel/release#go1.26.10).

Patched native Go 1.26.10 full shuffled suite, vet/build/module checks, pinned
staticcheck/actionlint, native/Linux gosec and Linux/Darwin cross-vet pass.
The patched govulncheck reports zero reachable/imported-package findings; only
the inherited unused module-level residual remains. Public WASM was rebuilt
with 1.26.10 and its real history/lifecycle suite passed. These are local and
cross-vet results, not actual Linux execution; that remains the exact-head CI gate.
