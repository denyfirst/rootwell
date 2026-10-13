# ADR 0065 — Public manual-renewal result, without replacement authority

Date: 2026-10-13. Development only; Porch excluded.

## Decision and boundary

The existing Automation card shows a compact old/new result after the active
Rootwell staging renewal has actually completed with both pairs still saved.
Read-only public metadata is derived from the authenticated complete image:
original/new fingerprints, their exact NotAfter UTC timestamps, and a boolean
computed by the existing publicinventory.Compare core. No fixed validity,
assumed extension, time remaining, fresh issuer trust, revocation or server
deployment verdict. Shorter/equal expiry is explicitly not extra time.

ReadStagingRenewalResult authenticates every current and closed-scope binding
before selecting the two public DER records from decode's detached output.
It never opens material for private output, accepts a caller-selected candidate,
copies notes, writes history/storage, mints a lease or performs CA/DNS I/O.
The authenticated renewal_source and active issuance completion select exact
identities; same certificate/key or different names refuses without partial
output. This comparison does not replace the existing pinned issuance check.

Linux reads under the existing private writer/revision lock and exact expected
generation. The existing API's final lifecycle and new-request snapshots must
match that generation; session/revision/context is checked again before output.
Native platforms refuse before file I/O. No new endpoint, request capability,
dependency, persisted field or backup format. V8 adds one renewal_result field
to the strict manual-DNS public contract. Result is null for ordinary issuance,
incomplete, deleted or locally closed active scopes. Archived result browsing
is not added; the certificates and authenticated history remain in their own
library after local closure. Explicit deletion and old-backup risks are unchanged.

## UI and refusal

One existing card, clear Original / New expiry blocks, no SHA by default; exact
public identities are under an optional disclosure. Matching separate keys and
preserved original notes follow authenticated completion, not browser claims.
No key bytes, URI, password, source filenames or notes are exposed. textContent
only, no browser storage or external requests. Explicit saved-status read only;
no automatic poll, renewal, replacement, export or server deployment.

Strict five-field result validates identities, distinctness, canonical UTC dates
and the derived expiry flag; only a saved renewal can carry it, and a saved
renewal cannot omit it. The section clears before every request and on hidden,
pagehide, selection/provider change, timeout and failure, discarding late output.
Full response retains the existing 8 KiB / 30-second bound.

## Evidence

- Model: complete independent pairs, exact core-derived dates, shorter and longer
  lifetimes, no mutation/secret output, stale/zero generation, invalid image/key,
  pending/ordinary/closed/deleted absence. Existing full graph tamper tests remain.
- Linux integration: actual private encrypted files, revision/generation refusal,
  immutable reads and both full-backup restore credentials; real ready HTTP session
  V8 public result with no CA callback, no cache/partial output on corrupt image.
- UI VM: shorter/equal/later dates, exact field/source identity, malformed date,
  absent result, extra secret field, inconsistent flag, pending/deleted/ordinary
  fake success refusal; hidden/pagehide/provider/clear, late and failed rereads.
- Actual compiling sabotage: removing expected-generation equality makes
  TestRenewalResultRefusesStaleTamperedAndIncompleteWithoutPartialOutput fail
  (stale selection exposed partial result). Rejecting ExpiryExtended results
  makes TestRenewalResultReportsShorterLifetimeWithoutAssumingExtension fail
  (completed renewal comparison unavailable). Both changes restored.
- Local Go shuffled suite, module verify/tidy, gofmt/vet/build, pinned staticcheck,
  native/Linux gosec, govulncheck, actionlint and Linux/Darwin cross-vet pass.
  govulncheck reports zero reachable/imported-package findings and one unused
  module-only residual; no dependency changes. Actual Linux race/storage execution
  requires exact-head CI, not Windows cross-vet.
- Real WASM comparison/bridge, inventory and ACME/access UI suites and read-only
  demo checks; visual browser QA uses explicitly simulated result/dates/keys,
  not real CA issuance or private custody. All demo writes remain refused.
- The reused FuzzPublicComparison parser passed a three-second two-worker local
  run (180 executions); the existing scheduled target remains unchanged.

## Residual and next gates

Existing host/runtime copies, old complete-image rollback, clocks and manual
backups, bounded history/archive retention, live pinned-staging interop and
independent production audit remain. The extra complete-image read adds bounded
CPU under the existing crypto slot; no KDF/secret capability increase. The summary
does not remain available for the active request after explicit local closure.
ARI/rate/backoff policy, scoped DNS adapters, unattended unlock and deployment
still need separately reviewed implementation and tests. No live CA or real
credentials were used. Signed PR, all exact-head checks and a separate maintainer
self-review remain mandatory; this is not an independent audit or release.
