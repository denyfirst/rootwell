# ADR 0058 — Offline acceptance gate for a staging-issued certificate

Date: 2026-10-12. Issuance wave, receipt-validation increment only.

Before enabling finalize or pair storage, add an independently testable offline
gate for the exact prepared P-256 key/CSR and ordered DER certificate response.
This increment adds no route, signer lease, CA request, write, browser control,
issuance authority, renewal or deployment. Existing can_issue remains false.
The full issuance wave is not complete. Porch is excluded.

The production entry point (development code, not a production-ready product)
selects ONLY four reviewed Let's Encrypt staging self-signed roots embedded in
this package. Neither a response root nor system roots can supply trust. The
unexported test seam uses independently generated synthetic roots; it is not a
runtime configuration option. No AIA/OCSP/CRL/Link fetching or dynamic root update.
Staging trust is test-only, never installed in host/browser trust stores. Root
rotation requires source/fingerprint review, signed changes and required CI.
Intermediates are not pinned: the supplied ordered chain must link to a pinned
root, and every supplied certificate must participate in that exact path.

Limits: 1–8 DER certificates, each <=48 KiB, total <=256 KiB; independent roots
<=32 KiB, <=4 certificates; inherited bounded key/CSR and canonical name policy.
RSA public keys on response/path members have an explicit 8192-bit ceiling,
checked before any response signature/path arithmetic. The inherited algorithm
policy provides a floor, not an upper work-factor bound; small DER alone cannot
bound RSA arithmetic. Public-only synthetic huge-modulus fixtures isolate this
ceiling without generating costly oversized private keys, alongside a real
RSA-issuer/P-256-leaf success case. Existing policy is not weakened.
Recheck key/CSR signature and exact SAN/SPKI binding, non-CA leaf, explicit
UTC evaluation year 2000–9999, current time,
explicit digital-signature and TLS-server usage, no signing/unknown usages,
no extra/duplicate DNS or non-DNS SAN, supported algorithms and critical
extensions on the entire path. Standard crypto/x509 verifies signatures,
constraints and path at an explicit time, with no system roots. Exact SAN set
comparison includes wildcard identifiers, without inventing a probe hostname.
Standard encoding/asn1 RawValue inspection rejects otherwise ignored SAN types;
no custom ASN.1 encoder or cryptographic primitive is introduced.

Duplicates, reordered, unrelated, unused, missing-intermediate, untrusted or
tampered response members refuse. A supplied terminal root is accepted only
when byte-identical to an independently configured root; omission is valid.
Cross-signed intermediates are permitted if the complete supplied path verifies.
Self-issued is not assumed self-signed: cross-signatures with equal issuer and
subject names remain untrusted intermediates unless independently anchored.
Time is checked on every selected path member, including its root; an unused
older anchor's expiry does not invalidate another current anchored path.
Only fixed errors and public fingerprints/times/names escape. No partial result
on failure; caller input bytes remain unchanged. Owned parsed private-key copies
are best-effort cleared by existing request validation, not reliably erased.

Limits do not make compromised host/runtime or hostile authenticated operators
safe. Offline acceptance proves neither CA order ownership/status nor revocation,
live interoperability, deployment, general browser trust or production readiness.
The network/custody increment must reserve capacity, commit intent before CA
I/O, use the same CSR, prevent blind finalize replay/client polling, revalidate
receipt under the writer lock, atomically transfer the pair and mark test-only
provenance. UI and full recovery integration are still required there.

Sources reviewed 2026-10-12: [RFC 8555 sections 7.4/7.4.2](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4),
[Let's Encrypt staging](https://letsencrypt.org/docs/staging-environment/).
Root bytes fetched from its linked official HTTPS PEM resources without
redirects; exact DER SHA-256 hashes and source URLs are recorded beside assets.
HTTPS/source review is not an independent out-of-band root ceremony.

Local evidence 2026-10-12: full shuffled Windows tests, fmt/tidy/module verify,
vet/build/staticcheck/gosec, Linux/macOS cross-vet, Linux-target gosec and
actionlint passed. Focused receipt tests report 94.9% statement coverage (not a
security guarantee). Twenty-second, two-worker receipt fuzzing passed with
95468 executions. ACME setup/directory/account/registration/order UI VM
regression scripts passed, not visual QA. govulncheck reported no affected
symbols/imported packages and one unused required-module advisory; it is not a
claim of zero module advisories. Required CI platform/race/container/signature
and vulnerability gates must pass before merge. No real CA enrollment, DNS
operation, browser preview, deployment, production release or external audit.

Actual two-direction sabotage, then restored: bypassing exactDNS (with code
still compiling) made TestStagingReceiptRejectsAlteredNamesKeysUsageTimeAndSAN's
extra-name case fail "unsafe receipt or partial evidence accepted". Rejecting
valid evaluation years made all normal/apex/wildcard success cases in
TestStagingReceiptExactBindingIndependentTrustAndNoInputMutation fail "valid
exact-name receipt refused or incorrectly summarized". Restored focused tests
and full gates passed. No sabotage retained. Initial fixture failures exposed
that CreateCertificate truncates unknown KU bits, so the negative fixture now
uses a standard ASN.1 BIT STRING extension and the checker inspects those bits.
The not-CA issuer fixture also clears CA-only path-length settings; a fixture
construction failure is not counted as security refusal evidence.

Final diff review found the missing explicit RSA work ceiling; a follow-up
adds it before signature verification, with the new boundary test. Additional
actual two-direction sabotage, restored: replacing the RSA ceiling with >0
made TestStagingReceiptCapsRSAIssuerWorkBeforeSignatureVerification fail "RSA
work ceiling failed before path verification"; accepting only zero-size RSA
made its real normal RSA-issuer success case fail "normal RSA issuer refused".
After restoration, all local full/pinned gates were repeated and passed,
including Linux/macOS cross-vet and Linux-target gosec. Final receipt coverage
is 95.0%; a fresh twenty-second/two-worker fuzz run passed 205887 executions.
govulncheck repeated the same no-affected-code/one-unused-module result. Manual
DNS UI VM regression was repeated, not visual QA. The final head requires fresh
CI gates and a superseding self-review; earlier-head checks cannot authorize it.
