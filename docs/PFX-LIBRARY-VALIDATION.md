# PFX library preparation — development evidence

2026-11-08, ADR 0087 / C106. No independent audit, production secret, live
CA/DNS/target, release or Porch modification is claimed.

## Local evidence

- Full native shuffled package suite passed. Native publication/API/asset tests
  passed after adding the post-commit publication guard. Linux vet/build,
  native vet/staticcheck/gosec, actionlint and module verification passed.
- Native and browser-WASM govulncheck each report zero reachable findings,
  with one uncalled required-module finding. No dependency is added.
- RSA/EC PFX preparation produces only encrypted PKCS#8 and an independent
  random password. The existing server material parser independently decrypts,
  recomputes match and retains the entire public collection. Wrong password,
  tamper, legacy profile, CA key, no matching key, multiple matching leaves,
  unrelated certificates/CAs, malformed and oversized inputs return no partial
  material. Caller-owned input remains unchanged; owned outputs clear.
- Actual Go WASM through the library UI produces two fresh encrypted outputs
  for Check/Save; an independent Node/OpenSSL parser verifies each key/cert.
  The original container/password never enter the observed certificate-material
  contract. Original file digest/identity survives randomized output and
  rejects same-size source replacement. Public/secret ambiguity cannot become
  an acknowledged PFX mismatch. No decoded private bytes or passwords are
  retained in pending preview state.
- The complete browser/WASM/UI CI step was also run locally and passed,
  including existing public/private/PFX/CSR, library, auth and automation tests.
- Worker tests assert module-only initialization, ready-first secret transfer,
  strict bounded one-shot output, timeout/abort, late-result refusal, no
  network/storage/download and owned-buffer clearing. Gateway and demo tests
  assert authentication/no-store and network/child-worker-denying CSP.
- The wrapper fuzzer ran for 10 seconds, two workers, 305437 executions without
  failure; it is included in the scheduled fuzz matrix. Existing PKCS#12 parser
  preflight fuzz coverage remains in place.

## Deliberate sabotage, restored after every case

Eight executable cases caused the intended assertion failures, not build or
syntax failures: plaintext instead of encrypted prepared key; refusing all
valid preparation; ignoring related-collection policy; a constant source
digest; refusing every valid PFX match; sending secrets before worker readiness;
accepting every post-commit publication context; and refusing every valid
publication context. Each source restoration is in `finally`; restored native,
architecture, worker and UI tests pass.

## Required final gates

The extended actual Linux integration verifies unchanged-image Check/refusal,
independent encrypted-key validation, durable-but-unconfirmed Save when the
session expires precisely after commit, duplicate/no-overwrite and full restore
of the matching PFX key/bundle alongside older material. It runs in the new
early smoke and full shuffled Linux race CI; this Windows host's native tests
are not Linux custody evidence. Final-head CI, reproducible artifacts and
separately recorded adversarial maintainer self-review are required before
ordinary signed-workflow merge. Green tests do not replace the release audit.
