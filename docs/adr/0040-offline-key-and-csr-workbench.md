# ADR 0040 — Offline key + CSR wizard and returned-certificate comparison

Status: accepted for implementation; development tests and release audit required.

## Boundary

A separate Request certificate tool generates RSA 2048/3072/4096 or ECDSA
P-256/P-384/P-521 using Go crypto/rand, or signs with an existing strict supported
private key. New keys leave the worker only encrypted as modern PKCS#8; a ZIP
contains that encrypted key and its public CSR so an operator does not save the
CSR while accidentally losing the key. Passwords are never included in the ZIP.
Extraction tools control actual file permissions. Existing keys are not copied
into the download. No CA issuance, key custody, network, inventory, renewal,
deployment, SSH or PGP capability is added.

The wizard requests DNS/IP names and optional bounded subject fields. DNS names
are ASCII (international names need punycode), wildcards are leftmost `*.`, and
duplicates/URLs/ports/CIDRs/zones/control characters are refused. Generation
requires at least one SAN and a common name from those names. Subject data is
requested information, not proof of identity. At most 32 DNS and 8 IP names.

CSRs use standard crypto/x509 creation and parsing. Signature, allowed modern
algorithm/key policy, canonical public key, names and subject are checked after
creation. Imported PEM/DER consumes one complete request, at most 64 KiB.
The bounded initial profile accepts DNS/IP SAN only and no attributes except
one extensionRequest containing at most the SAN extension. Standard ASN.1
decoding preflights attributes and general names that x509 can silently ignore;
no custom ASN.1 encoder or signing primitive is implemented. Challenge passwords,
unknown attributes/extensions and email/URI/otherName profiles are refused, not
silently lost. Empty-SAN existing requests may be inspected, not generated.

Public CSR export binds the displayed full request fingerprint. Returned public
certificates are compared with a re-parsed, signature-checked CSR and its expected
fingerprint. Canonical public keys are compared; missing/additional literal SANs,
subject changes and CA status are separate results. Wildcards are not expanded.
**Same key does not verify the issuer signature, chain, hostname coverage, time,
purpose, revocation or deployment.** A malicious party can copy a public key
into a fake certificate; Verify with independent trust remains required.

## Browser and residual risks

One-shot workers own bounded transferred copies, with finite deadlines and
generation/abort guards for stale choices, navigation and hidden documents.
Both message directions require the dedicated-worker MessagePort event shape
(empty origin, null source), rejecting foreign/missing event metadata before
initialization or secret transfer. This is not a Window.postMessage origin
allowlist or protection against compromised same-origin code. The private
worker handle, validated one-shot protocol and CSP are the actual channel
boundary; do not reuse this handler as a window/shared-worker receiver.
Passwords and owned buffers are cleared best-effort. Only public CSR bytes may
remain in the page for the explicit matching step. File-reading UI has no network,
storage, clipboard or markup-injection capability; worker CSP denies connections.
This uses a narrowly scoped network-free net/netip address parser, not DNS or
sockets. Random download filenames contain no user names. Browser/OS downloads,
runtime copies, extensions, weak chosen passwords, screen capture and compromised
hosts remain residual risks. ZIP encryption is not claimed: its key entry is
encrypted, while the CSR contains public names and subject information.

## Evidence required

RSA/ECDSA generation, encrypted-key round trip and exact key/CSR match; supported
existing plaintext/encrypted keys; CSR PEM/DER export; signature tamper, weak
algorithm, missing/wrong password, name/subject validation, unknown attribute/
extension, duplicate/mixed/trailing/oversized input and stale-fingerprint refusal.
Returned-certificate same/different key, name differences, expiry/CA/non-trust
semantics; independent OpenSSL CSR verification and Node private-key parsing;
WASM/worker/UI cancellation and no-secret-storage tests; fuzz target inventory;
two-direction sabotage; normal signed PR/CI/self-review gates and synthetic UI demo.

Standards: [PKCS#10 RFC 2986](https://www.rfc-editor.org/rfc/rfc2986) and
[X.509 RFC 5280](https://www.rfc-editor.org/rfc/rfc5280).
Worker protocol: [WHATWG dedicated workers](https://html.spec.whatwg.org/multipage/workers.html#dom-worker-postmessage)
and [MessagePort event initialization](https://html.spec.whatwg.org/multipage/web-messaging.html#message-ports).
