# ADR 0057 — Prepare a durable certificate key and exact-name CSR

Date: 2026-10-12. First custody increment of issuance, not issuance itself.
Linux single-operator development. Porch and offline Workbench unchanged.

After a saved unexpired ready/all-valid CA observation, explicit consent and
fresh Rootwell password prepare ONE P-256 certificate key and signed exact-SAN
CSR locally. No connection, account key reuse, finalize, certificate fetch,
DNS write, key export, reset/replacement or automatic preparation. The same
Automation card shows preparation separately from account/DNS verification;
can_issue stays false. Preparation is not a new certificate in Certificates.

A separate acme_certificate_requests manifest field, HKDF purpose key and
existing AES-GCM codec bind key/CSR to installation, fixed request identity,
generation, exact account fingerprint, saved order and canonical names.
Canonical PKCS#8, P-256, strict existing CSR parser/signature/policy, matching
SPKI, empty subject and exact SANs are revalidated on every complete-image open.
One request, <=512-byte key, <=4096-byte CSR, <=8192-byte sealed payload.
Only public prepared time and key fingerprint reach UI/history. Old binaries
refuse the new field. Existing account, order and certificate custody remain.

The private writer lock rechecks access revision, generation and live permission
before atomic replacement. Late cancellation cannot undo committed storage;
refresh reconciles the same key, never regenerates it. Preparation needs its own
history slot; future irreversible issuance must reserve completion capacity
separately before any CA request. Full password/recovery backup and offline
password recovery preserve the identical key AND CSR. Backup remains manual.
No external rollback anchor, cryptographic erasure or reliable heap erasure.
Generated/parsed signers use the existing best-effort ClearParsedKey helper;
owned PKCS#8 and serialized plaintext buffers are cleared. Runtime/private
scalar internals and copies are explicitly outside this guarantee.
An unused request cannot yet be reset/deleted/exported; cleanup and expiry/new
order policies are separate reviewed release work, not silently promised here.

Protocol review found pinned x/crypto CreateOrderCert internally polls an order.
The next network increment must constrain finalize to this durable CSR and
reconcile the same order without blindly re-finalizing. Returned non-CA leaf,
exact public key/SANs, time/usage/algorithm and issuer path need independent
staging-only trust. Never trust roots supplied by the issuance response or add
staging roots to system/browser trust. CA submission/pair storage, manual renewal
and DNS adapters are NOT implemented by this preparation increment.

Required evidence: success and stale/duplicate/expiry/unverified refusal;
strict key/CSR/account/order/context/purpose/tamper refusal; no private output;
unchanged existing records; Linux revision/lock/revocation/permission and full
password/recovery restore; native refusal; API fresh authentication/no network;
bounded hidden/late/malformed UI; actual two-direction sabotage and required CI.
VM tests are not visual QA; fake fixtures are not public CA interoperability.
Independent production audit remains a separate gate.

Local evidence 2026-10-12: shuffled full Windows tests, fmt/tidy/module verify,
vet/build/staticcheck/gosec, Linux/macOS cross-vet and actionlint passed. ACME
setup/directory/account/registration/order VM tests and actual Go WASM lifecycle
history passed. Three 20-second two-worker fuzz runs passed: request binding
256587 executions, sealed request payload 3669, manual DNS API parser 8134.
Live vuln.go.dev scanning was attempted twice and unavailable (DNS lookup
failure); required CI vulnerability, Linux custody/full restore and race gates
must pass before merge. No skipped/bypassed check is claimed successful.

Actual two-direction sabotage, then restored: omitting key/CSR SPKI equality
(with compilation preserved) made TestCertificateRequestExactNamesSeparateKeyAndStrictRefusal
fail "unsafe/partial request accepted"; rejecting every checked request made it
fail "valid request refused". Restored focused tests passed. No sabotage retained.
An initial mutation did not compile because its unused variable remained; that
compiler failure was not counted as behavior evidence. The corrected mutation
above exercised the intended refusal. Existing certificate/private material is
also preserved through preparation in the C75 regression test.

Sources checked 2026-10-11: [RFC 8555 section 7.4](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4),
[Let's Encrypt staging](https://letsencrypt.org/docs/staging-environment/), and
local pinned golang.org/x/crypto v0.57.0 acme/rfc8555.go CreateOrderCert.
