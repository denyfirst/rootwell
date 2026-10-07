# Secret-bearing conversion: pre-implementation threat model

**Status:** Linux offline PFX creation/extraction, bounded browser private-key conversion, and narrow modern browser PFX work implemented for development; production audit remains required. Optional matched-key library custody has a separate boundary in ADR 0046.

**Date:** 2026-09-29

## Assets and boundaries

ADR 0047 adds a distinct optional Inspect certificate/key comparator. Public
Inspect/Verify pickers remain public-only; the new secret picker sends bounded
copies only to the existing one-shot worker, using the same strict decoder and
key-match core. It returns public fingerprints/status only, not private bytes,
and has no upload/save/export capability. Source/tool/hidden/closed/deadline
boundaries discard results and clear owned buffers; worker termination bounds
parsed-key lifetime. Match is mathematical identity, not trusted issuance.
Wrong password/malformed input is not mismatch. Runtime/OS/extension copies
remain residual risks and independent release audit is still required.

Private keys, PFX passwords, extracted keys, and unencrypted working buffers
are secret. Public certificates may still reveal internal identities. The
operator supplies local files and a destination to an offline CLI process;
file contents, filenames, directories, terminal state, and the chosen output
path are untrusted. Those CLI operations cross no network, browser, server,
inventory, telemetry, or Porch boundary. A separate browser Convert picker
accepts strict unencrypted keys and bounded encrypted PKCS#8; a distinct PFX picker uses the modern profile of ADR 0037. Public Inspect/Verify
and the public Inventory importer must keep rejecting secret-bearing imports.
The explicitly chosen certificate-library picker is a separate own-daemon
upload/custody capability; see [custody threat model](CERTIFICATE-CUSTODY-THREAT-MODEL.md).

The attacker may supply a malicious container, swap a path before use, race a
write, watch process arguments or logs, trick the operator into using a weak
output profile, or provide a valid but unrelated certificate/key pair. A local
administrator or compromised host is outside the confidentiality claim.

## Required controls before each capability is exposed

| Risk | Required evidence |
|---|---|
| Huge, malformed, nested, duplicated, mixed, or unauthenticated PFX | Byte/object/key-count and work limits before expensive decode; parser fuzzing; wrong-password, bad-MAC, trailing-data, ambiguity, and rejection tests with no partial output. |
| Wrong certificate or misleading chain | Public-key match, signature/relationship checks where claimed, duplicate and unrelated-certificate refusal, post-conversion semantic comparison; trust remains a separate Verify decision. |
| Loss of unknown bags or attributes | Enumerate what the selected library exposes; refuse round-trip when semantics cannot be preserved or explicitly documented as intentionally discarded. Never label a lossy transformation lossless. |
| Password disclosure | Terminal-only local input with echo disabled and prompt confirmation where output protection is created; no argv/env/URL/stdout/stderr/log/JSON password path. Refuse non-TTY before reading any key. Error strings never reflect attacker input. |
| Private-key disclosure through output | CLI uses a separate named action and private-file output. Browser conversion has a separate private picker; encrypted PKCS#8 is default, while plaintext requires explicit target and confirmation. Browser/OS file permissions and copies cannot be guaranteed. |
| Unsafe file write | Explicit destination, no overwrite, reject symlink/unsafe parent, create with private permissions, validate/sync before reporting success; failure cleanup and uncertain post-commit results are tested per platform. |
| Stale or substituted input | Keep handles bound to inspected bytes or recheck a content digest before commit; test path replacement and key/certificate mismatch. |
| Secret remnants | Clear owned byte buffers where possible, use bounded lifetimes, keep secrets out of errors and crash artifacts; document that runtime/OS copies cannot be reliably erased. |
| Dependency compromise or vulnerable profile | ADR 0001 review, pinned versions, license/transitive inventory, `govulncheck`, advisory regression cases, release-update owner, and independent review before release. |

The library candidate `software.sslmate.com/src/go-pkcs12` supports encoding
and chain decoding, while `golang.org/x/crypto/pkcs12` is read-only/frozen for
this purpose. This is **not** an approval to add either dependency. The former
had a password-authentication bypass affecting 0.6.0, 0.7.0, and 0.7.1;
upstream lists 0.7.2 as patched. The implementation review must verify the
then-current advisory state and add a wrong-password regression fixture.

Primary sources (checked 2026-09-29):

- [SSLMate package documentation](https://pkg.go.dev/software.sslmate.com/src/go-pkcs12)
- [SSLMate upstream repository and license](https://github.com/SSLMate/go-pkcs12)
- [Upstream security advisory GHSA-mpwr-8vm7-h73f](https://github.com/SSLMate/go-pkcs12/security/advisories/GHSA-mpwr-8vm7-h73f)
- [Go x/crypto PKCS#12 documentation](https://pkg.go.dev/golang.org/x/crypto/pkcs12)

## Release gates

For each enabled operation, demonstrate successful round trip against generated
non-production fixtures and an independent OpenSSL parser; mismatch, wrong
password, unsupported algorithm/container, malformed input, output failures,
path races, and secret-in-diagnostics refusal. Sabotage both the validation
path and the leak/write guards and show the relevant tests fail. Run formatting,
unit, fuzz, race, vet, static, vulnerability, and supported-platform checks.
Record exact versions and residual risks in the PR. Do not claim production
secret custody or audited safety before external review.

Browser private-key conversion is scoped by
[`ADR 0034`](adr/0034-browser-encrypted-private-key-conversion.md).
Browser PFX work follows ADR 0037 and has an additional development gate: specific
origin/CSP, extension and download threat analysis, memory-retention tests,
and no hidden upload evidence. The release candidate still requires an
independent audit before real-user deployment. The public Convert picker,
Inspect, Verify, and Inventory continue to refuse PFX and private keys;
the separate private Convert picker refuses PFX and legacy encrypted PEM; its
bounded encrypted-PKCS#8 import and plaintext targets follow ADR 0035.

ADR 0038 additionally permits a bounded encrypted PKCS#8 key directly in
browser PFX creation. Its current password is transferred only to the one-shot
worker, independently from the output password; no plaintext intermediate
download is needed. Input/output password reuse is refused. Windows imports
test output with an ephemeral key store, and the WASM path also consumes an
independently encoded Node/OpenSSL encrypted input.

ADR 0039 adds explicit, transient private-key display. Encrypted files require
fresh file-password authentication and inspected identity; plaintext files
require renewed screen-exposure consent. Future saved keys need separate
instance reauthentication. Text is cleared after 30 seconds and on page/tool/
source changes, manual hide or closing PFX key tools. Pending operations are
cancelled at page boundaries. No clipboard, download, logging, URL or storage
path is added. Screen capture, extensions, same-origin compromise, assistive
technology and runtime strings remain residual risks, not erasure guarantees.

ADR 0040 adds a separate offline key + DNS/IP CSR wizard, not a CA or vault.
Only encrypted new keys leave the worker; a ZIP groups the encrypted PKCS#8
and public signed CSR, but is not itself encrypted. Existing keys are not
exported. Strict signed-request parsing, modern key policy, full-fingerprint
export binding, one-shot deadlines and stale-choice cancellation apply.
Returned certificates are compared by canonical public key and literal names;
copying a public key into a fake certificate is possible, so independent trust
verification remains mandatory before relying on it. Browser/OS copies and
download permissions are not controlled by this workbench.
