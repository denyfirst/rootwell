# ADR 0049 — Network-free ACME staging setup check

Date: 2026-10-08. Status: development increment; not account integration,
issuance, production enrollment or independent audit.

## Decision

Begin ACME with a small, honest Automation section in the existing Rootwell
shell. The operator checks 1–32 unique ASCII DNS names and a planned manual
DNS-01/HTTP-01 proof for a fixed Let's Encrypt staging profile. Reuse CSR DNS
normalization without generating a CSR/key or resolving a name. Reject unknown,
production/custom providers, malformed/reserved/internal names, IP/URL inputs,
normalized duplicates and HTTP-01 wildcards. This narrow syntax policy is not
CA eligibility, domain ownership, CAA, public-suffix or IDNA validation.

`POST /api/acme/plan` is ready-session, exact-origin/custom-header protected,
strict bounded JSON (16 KiB), no-store, and rechecks the session before output.
Only provider/challenge/domains exist in the request. No account key, email,
password, DNS credential, terms acceptance or custom directory is accepted.
There is no CA traffic, persistence, key generation or challenge token. Response
capabilities are all false. It works on Windows too because it has no custody
write; Windows encrypted library custody remains read-only.

The UI labels this setup-only state, binds the exact response to current inputs,
rejects execution capabilities and clears on source change, hidden/pagehide,
timeout and Clear. The directory is display text, never a fetched endpoint.
There are no fake account/issuance buttons or invented DNS instructions.

## Evidence and limits

`TestACMEPlanChecksSyntaxWithoutGrantingCapabilities`,
`TestACMEPlanJSONIsBoundedStrictAndSecretFree`,
`TestACMEPlanGateHasNoCAOrPersistenceCapability`,
`TestACMESetupHasNoOutboundOrPersistenceImports`,
`FuzzACMEPlanRequestJSON` and `scripts/test-acme-setup.mjs` cover positive,
refusal, malformed, local/session/origin, no-write/no-CA and late UI boundaries.
The import/selector guard is regression evidence, not a runtime sandbox.
Two-way deliberate sabotage outcomes and local/CI gates are recorded in the PR.
Local sabotage: removing the HTTP wildcard refusal failed the negative core
test; refusing the fixed valid provider failed its positive case. Removing
same-origin refusal failed the gate negative test; reversing it failed the
local valid request. Allowing `can_issue:true` failed the UI refusal test;
hiding a valid summary failed its positive test. All six mutations were
restored, then the intended suites passed.
DOM/VM tests are not a claim of visual browser QA. Host compromise and runtime
string retention remain outside guarantees.

## Next gates

Follow [ACME threat model](../ACME-THREAT-MODEL.md): reviewed mature client,
bounded staging transport and isolated fake-CA tests; encrypted recoverable
account; manual DNS order/issuance; manual renewal before a scheduler. Real CA
requests need separate explicit enrollment/domain authority. Default CI does
not contact external CAs. Production and deployment remain separately gated.
Porch is outside this increment.
