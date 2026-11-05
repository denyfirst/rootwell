# Website check development validation — ADR 0084

2026-11-05, Go 1.26.10, native Windows development host. Independent audit,
release, live public-site tests and real CA/DNS operations are not claimed.

## Local evidence

- Full `go test -shuffle=on -timeout=40m ./...` passed. Changed website
  packages and API tests also passed after the final local changes.
- `go vet ./...`, Linux/Darwin cross-vet and Linux cross-build passed;
  `staticcheck ./...`, formatting, module verification/tidiness and actionlint
  passed. Full gosec reported zero issues (diagnostic capture's intentional
  TLS skip-verification is explicitly documented and separately verified).
- govulncheck: zero reachable vulnerabilities; one required-module finding
  outside the called package/symbol graph. No dependency was added.
- Native fuzz, two workers / twenty seconds each: 371,103 analyzer executions,
  245,816 target parser executions, 20,606 consent parser executions; all passed.
  Scheduled fuzz matrix includes all three targets.
- Real synthetic TLS over local injected sockets checks exact original SNI,
  one DNS lookup, one numeric-address dial, valid versus untrusted root pools,
  and zero application data. No public site is contacted by these tests.
- Missing issuer, wrong issuer with identical names and independent keys,
  expiry, hostname mismatch, untrusted peer root, order differences, malformed
  input, address-policy refusals, byte limits, cancellation/revocation,
  ready/setup/origin/consent/throttle and late-session publication are tested.
- `node scripts/test-website-check.mjs` and
  `node scripts/test-inventory-demo.mjs` passed: bounded contract, raw-error
  refusal, single-use consent, late results, timeout, hidden/pageexit reset,
  generated-only examples and preview live-POST refusal.
- In-app browser showed both actual example renders (healthy and wrong issuer)
  in the existing Rootwell shell. Screenshots are local development artifacts,
  not a claim of a live TLS observation or independent audit.

## Actual compiling sabotage, restored after each run

1. Force valid paths untrusted: `TestTrustedPathDoesNotNeedServerSentRoot`
   failed.
2. Replace signature eligibility with issuer-name equality:
   `TestSameIssuerNameCannotForgeSignatureLinkOrTrust` failed.
3. Permit every valid address: `TestSpecialUseAndMappedAddressesAreRefused`
   failed on unsafe addresses.
4. Refuse every address: the same test failed on public addresses.

Each was an assertion failure in the intended test, not a compiler failure.
Source was restored in a `finally` block and both packages passed afterward.
No weakened implementation is committed. Final-head CI, actual Linux race
checks and the separately recorded maintainer self-review remain merge gates;
this local record does not substitute for them.
