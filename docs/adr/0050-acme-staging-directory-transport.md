# ADR 0050 — Opt-in staging directory reachability, not enrollment

Date: 2026-10-08. Development boundary; independent release audit outstanding.
Porch is excluded.

## Decision

Keep ADR 0049's setup check network-free. A separate ready-session, same-origin
POST accepts exactly the fixed staging provider and explicit boolean consent.
The Automation page presents a separate optional action and explains server IP
and DNS resolver visibility. One confirmation permits one directory GET only.
No domains, email, keys, certificate material or arbitrary URL is accepted.
No account, terms acceptance, nonce/JWS request, order, challenge, issuance,
storage, renewal or deployment capability is introduced.

Use `golang.org/x/crypto/acme` at the existing reviewed module pin v0.57.0,
calling only `Client.Discover` with no signer. Do not implement ACME cryptography.
Explicitly override production-directory, default HTTP client and retry defaults.
The client receives a one-use guarded transport and no cookie jar or proxy.

## Dependency review

The Go team's ACME package implements RFC 8555, is maintained in x/crypto,
and uses a BSD-3-Clause license (module LICENSE inspected). This change promotes
the already pinned module to direct usage, without changing its version.
The ACME package's imported dependency closure uses standard-library packages;
the module's unrelated openpgp package is not imported. GO-2026-5932 affects that
unmaintained package, not a justification to waive the required vulnerability
scan. Actual imported/reachable findings must still pass govulncheck.

Upstream Discover accepts broad directory JSON, caches URLs, and its normal
client can follow redirects/retry with no timeout unless a caller supplies
limits. Therefore preflight the document before giving it to Discover: 32 KiB,
valid UTF-8, one root object, no duplicate keys anywhere, depth 8, token budget
2048, exact-case known fields, required RFC directory endpoints. All known
operation URLs (including optional newAuthz/renewalInfo) must be canonical HTTPS
URLs on the fixed host with conservative `/acme/` paths, no credentials,
query, fragment, custom port, escape or dot segments. Bounded unknown extensions
are ignored, not fetched. ToS/website metadata may legitimately name another
origin; neither is linked, fetched, accepted, or returned by this action.

## Transport and authority

One dedicated transport per check, no environment proxies/ambient credentials,
system TLS trust and original hostname/SNI, TLS >=1.2. Resolve only the fixed
host; reject empty, >16, mixed-public/private or special-use answers. Numeric
dialing pins one approved IP; no second DNS resolution or retry/fallback. The
conservative special-use policy may refuse otherwise usable special addresses
or a working secondary address; refusal is preferable to authority expansion.
TLS authorization is rechecked after the handshake before HTTP gets the socket.

Live connections are Linux/Docker-only. Separate self-review found that Go's
native Windows verifier calls CertGetCertificateChain without cache-only/AIA
retrieval-disable flags; platform chain building can cause additional ambient
network access outside this transport. Windows/macOS live connection is refused
before DNS/cooldown; UI and API say native preview stays offline. Synthetic tests
use explicit non-system root pools and therefore do not exercise native verifier
network access. Native platform support requires its own reviewed trust boundary,
not InsecureSkipVerify, ad-hoc verification, or a hidden environment bypass.

Total deadline 8 seconds; dial 3, TLS and headers 4, headers 8 KiB, body 32 KiB.
No compression, redirect, non-200 response or retry. Recheck live session/context
before resolver/dial/TLS completion/response/result. A request already sent
before logout cannot be recalled; no guarantee of instantaneous revocation or
erasure of OS/runtime buffers. One global in-flight check and 30-second cooldown
are RAM-only and reset at process restart, not a durable CA quota mechanism.

Return only a fixed nine-field reachability summary; raw response/error/metadata
is not reflected or logged. No filesystem write. Offline CLI/Workbench and
setup API cannot import this connector or the ACME client. Fake DNS/numeric
dial/root injection exists only in unexported test dependencies; no live URL,
environment, command-line or insecure test override is exposed.

## Evidence and residual work

Isolated synthetic TLS CA tests cover SNI/hostname verification, pinned numeric
dialing, exactly one secret-free GET, ignored proxy, unsafe/mixed DNS, TLS refusal,
redirect/no-retry, parser limits, cancellation and authorization revocation.
Daemon tests cover strict consent, setup/login/origin/method/query boundaries,
late session/context, cooldown/in-flight refusal and unchanged access bytes.
VM UI tests cover single-use consent, bounded strict summary, errors and stale/
hidden/clear/deadline results. These are not visual browser QA or live public-CA
interoperability. No test makes a real external CA request.

Two-way sabotage: forcing the IP policy to allow every address caused
`TestDirectoryRefusesPrivateMixedDNSAndRevokedConsentBeforeDial` to fail on
private/mixed dialing. Refusing every nonempty directory caused
`TestDirectoryStrictBoundedParser` to fail on its valid fixture. Both changes
were restored and the complete connector test suite passed again. Concurrency
and in-flight logout are exercised with a blocked connector and real gate calls,
not just simulated status flags. Chunked overflow, header overflow, wrong TLS
hostname and stalled body/parent deadline are also refused.
UI sabotage also failed in both directions: removing the consent guard sent an
unconfirmed request; hard-denying the action prevented its approved success.
The same UI test passed after restoration. Short local fuzz runs exercise both
new parsers; longer scheduled fuzzing remains in the mandatory fuzz inventory.

Account custody/uncertain registration reconciliation and manual DNS issuance
are the next separate capabilities. Production/custom CA/EAB/ARI, unattended
renewal and independent release audit remain outstanding.

Sources checked 2026-10-08: [pinned ACME API](https://pkg.go.dev/golang.org/x/crypto@v0.57.0/acme),
[RFC 8555 directory](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1),
[staging](https://letsencrypt.org/docs/staging-environment/),
[IPv4 special registry](https://www.iana.org/assignments/iana-ipv4-special-registry/),
[IPv6 special registry](https://www.iana.org/assignments/iana-ipv6-special-registry/),
[unimported openpgp advisory](https://pkg.go.dev/vuln/GO-2026-5932).
Also inspected Go 1.26.7 x509 root_windows.go/root_unix.go/verify.go and
[Windows chain retrieval flags](https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatechain).
