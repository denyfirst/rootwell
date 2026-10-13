# ADR 0064 — Explicit manual staging renewal from Certificates

Date: 2026-10-13. Development only; no real CA/DNS operation or Porch change.

Certificates offers Renew test certificate only for an authenticated Rootwell
staging completion with a saved matching pair. An exact-generation same-tab
POST navigation carries only fingerprint/generation, never keys, notes or URL
state. The server derives the exact names from authenticated completion. It
renders an inert bounded public selection, not network authority. Imported
certificates cannot claim this capability; generic CA/EAB support remains later.

The existing request must first be explicitly closed under ADR 0063. Renewal
requires its own fresh password, consent and generation. It creates a separate
durable order intent linked to the earlier closed completion, then reuses the
same bounded DNS/validation/new-key/receipt/pair path. Lost creation stays
uncertain, never auto-replayed. No key reuse, automatic retry/poll, ARI request,
scheduler, validity-extension, replacement, deletion, revocation or deployment.
This is operator-driven new issuance, not a claim of CA renewal-rate exemption.

The optional encrypted order renewal_source is an exact public fingerprint.
Whole-image validation walks closed scopes in chronological order: source must
be an earlier completed scope, with identical names/account and a different new
key. Forward/self/orphan/deleted-before-closure references refuse. Active source
deletion refuses until that request closes; later source deletion keeps the
authenticated historical tombstone, not a live pair claim. No extra DER/secret
copy or recursive historical authority. Notes and both saved pairs remain; the
new certificate is not automatically applied to services or declared healthier.
Full backup/recovery preserves linkage. Old binaries refuse the new order field.

V7 exposes only renewal_source plus inherited public state. The same Automation
card shows selected certificate/domains, explicit close and then a new renewal
consent. Source/generation changes, hidden/pagehide, late/malformed/error states
clear authority. Reloaded saved status identifies the renewal independently of
the navigation hint. Windows preview is clearly fake/read-only with all CA and
secret mutations disabled. No production/live-CA/audit claim.

Acceptance: model success/refusal/tamper/source deletion/key independence,
atomic intent before callback, real fresh-auth HTTP/navigation, full recovery,
strict V7 UI/cancellation, two-way compiling sabotage, fuzz/architecture guards,
pinned local gates and all exact-head CI; separate maintainer self-review before
signed merge-only delivery. Retention limits, authenticated rollback, host/key
compromise, live staging QA, ARI/backoff/DNS/production and external audit remain.

Sources rechecked 2026-10-13: [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html)
and [Let's Encrypt integration guide](https://letsencrypt.org/docs/integration-guide/).

## Development evidence

Actual compiling sabotage, subsequently fully restored: bypassing renewal graph
binding caused `TestManualRenewalRefusesStaleOrphanActiveDeletedNamesAndTamperedLinks`
to fail with “tampered renewal exposed partial source”; blocking every nonempty
renewal source caused the legitimate completion test to fail with “legitimate
renewal refused”. Both named tests then passed ten repetitions. The positive
full-image test also reseals a mathematically valid original-key/CSR into the new
request and confirms same-key refusal before output. Synthetic checked completion
keeps both independently keyed pairs, then historical deletion stays valid.

`FuzzRenewalOrderBinding` ran 20 seconds/two workers, 20,866 executions, PASS;
scheduled target inventory and inherited strict HTTP fuzz cover the new field.
V7 VM tests cover source handoff → explicit closure → fresh renewal consent,
strict exact names/fingerprint/generation, malformed/stale/other-source/error
and hidden/pagehide/late cancellation. Linux real writer/fresh-auth/navigation,
intent-before-I/O/lost-response reconciliation and both full recovery methods
are tested by exact-head CI; native runs/type checking do not substitute them.

Pinned local Go 1.26.9 module tidy/verify, format/vet/build, shuffled full Windows
suite, staticcheck 0.7.0, actionlint 1.7.12, gosec 2.28.0 (native/Linux) and
Linux/Darwin vet passed. Govulncheck 1.6.0 found zero reachable/imported-package
findings and one existing unused module-only OpenPGP residual; no dependency
changed. Final review moved Linux-only navigation test helpers behind the Linux
build tag rather than suppressing the native staticcheck unused warning.
Valid-MAC historical forward/self links also refuse before any partial pair.
Real WASM history, all ACME V7 UI, certificate-card navigation/no unsupported
renewal, disabled demo mutations and container config checks passed.

Real browser Certificates card → public fake renewal navigation → local fake
saved-status read shows fixed names and fresh consent/password with disabled
Get renewal DNS records. Preview is fake/read-only (no authentication, CA, key or
durable user-data operation), not a Linux or live-CA browser interoperability test.
Separate final-head adversarial maintainer self-review and all 13 exact-head CI
checks precede merge; audit/release remain separate. No Porch changes.

Final review tightened historical deletion proof to the authenticated nested
issuance generation, not a later outer archive reseal generation. At equal
second-resolution times, deletion must still be strictly after the dependent
closure generation. Prior/at-closure deletion refuses; later deletion remains
valid. This does not grant runtime historical authority.
