# Expected certificate comparison — development evidence

2026-11-06, ADR 0085 / C104. No live target, CA/DNS operation, release or
independent audit is claimed. Porch is unchanged.

## Scope and evidence

- Full native shuffled `go test -shuffle=on -timeout=40m ./...` passed.
- Native vet/staticcheck, Linux cross-vet/build, actionlint and gosec passed;
  gosec reports zero issues. No dependency was added; module verification and
  tidiness passed. govulncheck reports zero reachable findings, with one
  required-module finding outside the called code.
- Actual Go WASM public parsing and issuer graph, executed by
  `scripts/test-website-expected.mjs`, confirms PEM/DER identity, different DER
  with the same public key, identical-name/different-key certificates, exact
  wrong/missing intermediate positions, normal root omission, ambiguous leaf
  selection, unrelated extra CA visibility and malformed/duplicate/private
  input refusal. Supplying complete correct CA material cannot change either
  failed server observation. Observation objects remain unchanged.
- `TestIssuerChecksLocateExactBrokenSignatureAtEachDepth` binds the exact
  child and rejected server candidate by fingerprint at both leaf->issuer
  and issuer->root depth. Correct edges remain verified, not rejected.
- UI VM assertions check separate certificate/chain results, the actual
  server-sent candidate position, malformed issuer-edge metadata refusal,
  unchanged exact `{target,confirm}` network body, no filenames/bytes/hashes
  in requests, preflight secret refusal, explicit ambiguous selection and
  canceled/hidden/late file reads never starting an observation.
- The existing API still rejects any certificate/key/fingerprint/trust input.
  Preview file/consent inputs and live POSTs remain disabled; the dedicated
  example uses generated public bytes and clearly synthetic server data.

## Actual sabotage, restored after every run

1. Force every expected certificate identity to match: actual WASM test fails.
2. Force every expected identity to differ: actual WASM test fails.
3. Accept every same-name server issuer candidate: the per-depth Go assertion
   fails on the wrong key.
4. Reject every server issuer candidate: the per-depth Go assertion fails on
   the correct signature.

These are executable assertion failures, not syntax/compiler failures.
Source restoration is in `finally`; actual WASM and Go package tests pass
afterward. Final-head CI/full Linux race and separately recorded adversarial
maintainer self-review are still required before ordinary signed-workflow
merge. Self-review does not replace the user's later independent release audit.
