# Secret-bearing conversion: pre-implementation threat model

**Status:** Linux offline PFX creation and narrow public CLI inspection implemented; extraction and browser/server secret handling remain planned

**Date:** 2026-09-29

## Assets and boundaries

Private keys, PFX passwords, extracted keys, and unencrypted working buffers
are secret. Public certificates may still reveal internal identities. The
operator supplies local files and a destination to an offline CLI process;
file contents, filenames, directories, terminal state, and the chosen output
path are untrusted. No network, browser, server, inventory, telemetry, or
Porch boundary is crossed. The existing public Workbench and inventory must
keep rejecting secret-bearing imports.

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
| Private-key disclosure through output | Separate named action, private file only, no stdout or browser download in the first increments. Default key export must be encrypted PKCS#8; plaintext export, if ever allowed, needs a separate decision. |
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

Browser/server PFX work has an additional development gate: specific
origin/CSP, extension and download threat analysis, memory-retention tests,
and no hidden upload evidence. The release candidate still requires an
independent audit before real-user deployment. Until the browser boundary is
implemented and internally tested, the public Convert UI must continue to
refuse PFX and private keys.
