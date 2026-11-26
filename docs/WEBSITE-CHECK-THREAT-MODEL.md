# Website certificate check threat model — ADRs 0084 and 0090

Development only, 2026-11-05; internal servers since 2026-11-26 (ADR 0090).
Separate from the offline Workbench and the strict expected-leaf CLI probe.
No independent security audit is claimed.

The signed-in owner asks for one check of a website or internal server. The site's name is sent to the configured DNS resolver and
as TLS SNI; the peer sees the Rootwell server's connection address. Neither
private keys nor certificate files enter the API. ADR 0085 adds an optional
public file comparison entirely within the browser; only the original target
and consent JSON are sent. The page does not save the target, file or results,
use browser storage for them, or add a server history record. The
operator's network, resolver, peer and local host may retain their own records.

## Untrusted input and SSRF

Both the target and every peer certificate are untrusted. A target is an
ASCII DNS name (punycode for other scripts) or an IP address, with an optional
port and an optional `https://`. Paths, credentials, fragments, queries,
`localhost`, numbers that resolvers read as addresses, zoned IPv6 and IPv4
written inside IPv6 are rejected. All returned addresses (maximum 16) must be
allowed, including IPv4-mapped IPv6, or the whole check is refused.

Allowed addresses are public and private networks, so internal servers can be
checked (ADR 0090). Never allowed: loopback, unspecified, link-local (cloud
metadata), multicast, broadcast, reserved and documentation ranges, the
metadata addresses 100.100.100.200 and fd00:ec2::254, and IPv6 transition
ranges that embed an IPv4 address. A check makes at most three TCP connections,
each to a validated numeric address: the first IPv4 answer, the first IPv6
answer only when the IPv4 one did not answer, and one classic-key-exchange
retry when a server dropped the first greeting. DNS cannot change the
connected destination after validation. No HTTP client, proxy, redirect, TLS
application data, embedded AIA/CRL/OCSP URL or child process is involved.

Reaching private networks makes the check a probe of the owner's network:
it learns whether a port answers and which certificates it sends, nothing
more. Only the signed-in owner can start one, one at a time and at most one
every 5 seconds. Network egress rules on the Rootwell host remain the
operator's boundary; resolver compromise and operator routing remain risks.

## Authentication, bounds and cancellation

The API accepts only exact-key bounded JSON POST with explicit confirmation,
same-origin header protection, expected Host and a ready session. Setup-only
and anonymous callers have no connector authority. A global in-memory busy bit
and a 5-second interval bound concurrent/repeated requests; there is no queue
or unbounded per-target state. Revalidation occurs before DNS/dial/handshake
and result publication. Logout, revision changes, expiry, cancellation or
server shutdown revoke publication; already transmitted bytes cannot be recalled.

The total operation is bounded to 15 seconds, each TCP dial to three seconds
and each handshake to five.
Socket input is capped at 256 KiB and output at 64 KiB. The standard Go TLS
parser still sees hostile handshake data within that input bound. At most ten
certificates / 128 KiB of raw certificate data reach the analyzer. A certificate
sent twice is analyzed once and named; a malformed observation produces no
partial report.
Peer subject/issuer text is bounded, controls/bidi formatting removed, and
rendered only as text. Fixed errors do not echo peer diagnostics; they name
only the canonical target and the address Rootwell dialed.
The browser independently bounds response bytes, fields, dates and arrays;
malformed, timed-out, late, hidden or mismatched-target results cannot show
success. New input clears the previous result. Example data is labeled synthetic.

## Trust and result meaning

ADR 0086 adds a separate native POST navigation from Certificates. It reads
one exact-generation public snapshot with strict Origin/navigation metadata,
ready-session and post-read revalidation; it cannot select a target or start
the connector. Only one public DER record enters inert HTML, then the existing
browser parser/fingerprint check. Private keys and service notes are absent.
This snapshot may later differ from the library; it is not a live library link.
It never fills the server's issuer pool, changes trust or bypasses consent.

TLS intentionally observes invalid certificates with InsecureSkipVerify; this
is a diagnostic capture boundary, never an authentication success. No
credentials or application data follow. A separate pure x509 verifier checks
the chain with server-auth usage at the observation time, using the explicit
Rootwell host root pool and only intermediates from this handshake. The DNS
name is checked separately. Only Linux enables the live production connector,
avoiding ambient Windows/macOS AIA retrieval by platform verifiers. Native
preview refuses before DNS and the read-only fixture server refuses all live
check POSTs. Synthetic TLS tests use injected local sockets, not real websites.

Peer-provided roots are candidates, never added to the trust pool. A trusted
root need not be sent by the server. When the chain does not reach the host's
roots, the check tries the self-signed certificate authorities the owner saved
in Certificates (at most 64) and says so by name; nothing a check observes is
saved. Every displayed path link is established cryptographically; matching
names alone cannot link an issuer. On failure, only unambiguous supplied
signature links are shown, and the issuer that the last link names is called
missing, with both fixes: send it, or save the company root. Multiple valid
cross-signed paths may exist; the displayed path is the shortest
verifier-selected path, not a unique universal chain. Every other sent
certificate is classified by signature: an older chain (another issuer's copy
of a path certificate, or an issuer of such a copy, which servers send for old
devices; emanat.az and example.com do), a root, or unrelated. Only an
unrelated or out-of-date extra certificate is reported as needing a fix.

ADR 0085 also publishes per-child verified/rejected issuer candidate
fingerprints, bounded to ten children / nine other sent candidates each.
Matching names cannot make a verified link. The optional local expected chain
uses the existing WASM signature graph, identifies exact missing/wrong
intermediate positions, and leaves root omission informational. Comparison
never supplies the verifier with uploaded issuers/roots or changes its verdict.

A verified result means this hostname and current server-auth path passed this
observation under this host's trust roots. It says nothing about every browser,
every load-balancer address, old TLS profiles, future responses, revocation or
Certificate Transparency. A compromised host, browser extension, same-origin
script, root store or network environment is outside this guarantee.
