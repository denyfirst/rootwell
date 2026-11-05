# Website certificate check threat model — ADR 0084

Development only, 2026-11-05. Separate from the offline Workbench and the
strict expected-leaf CLI probe. No independent security audit is claimed.

The operator authorizes one public website origin from a ready, revision-bound
Rootwell session. The site's name is sent to the configured DNS resolver and
as TLS SNI; the peer sees the Rootwell server's connection address. Neither
private keys nor certificate files are requested. The page does not save the
target or results, use browser storage, or add a server history record. The
operator's network, resolver, peer and local host may retain their own records.

## Untrusted input and SSRF

Both the target and every peer certificate are untrusted. Only ASCII DNS names
(including valid ASCII punycode labels) and HTTPS origins on port 443 are
accepted. Paths, credentials, fragments, queries, IP literals and custom ports
are rejected. Local/special-use suffixes are refused before DNS. All returned
addresses (maximum 16) must pass public-address checks, including IPv4-mapped
IPv6. Mixed public/private answers refuse the entire observation. The first
validated numeric address is dialed once; DNS cannot change the connected
destination after validation. No HTTP client, proxy, redirect, TLS application
data, embedded AIA/CRL/OCSP URL or child process is involved.

This is a conservative address policy, not a substitute for network egress
controls: operator-controlled routing/NAT, resolver compromise and changes in
special-use address assignments remain risks. No private-network override is
offered. Supporting an enterprise internal endpoint requires a separate design.

## Authentication, bounds and cancellation

The API accepts only exact-key bounded JSON POST with explicit confirmation,
same-origin header protection, expected Host and a ready session. Setup-only
and anonymous callers have no connector authority. A global in-memory busy bit
and 30-second interval bound concurrent/repeated requests; there is no queue
or unbounded per-target state. Revalidation occurs before DNS/dial/handshake
and result publication. Logout, revision changes, expiry, cancellation or
server shutdown revoke publication; already transmitted bytes cannot be recalled.

The total operation is bounded to eight seconds; TCP dialing to three seconds.
Socket input is capped at 256 KiB and output at 64 KiB. The standard Go TLS
parser still sees hostile handshake data within that input bound. At most ten
certificates / 128 KiB of raw certificate data reach the analyzer. Certificates
with duplicate DER or malformed observation shape produce no partial report.
Peer subject/issuer text is bounded, controls/bidi formatting removed, and
rendered only as text. Fixed errors do not echo peer diagnostics or user input.
The browser independently bounds response bytes, fields, dates and arrays;
malformed, timed-out, late, hidden or mismatched-target results cannot show
success. New input clears the previous result. Example data is labeled synthetic.

## Trust and result meaning

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
root need not be sent by the server. Every displayed path link is established
cryptographically; matching names alone cannot link an issuer. On failure,
only unambiguous supplied signature links are shown. Unknown trust is not
automatically diagnosed as a missing intermediate or attack. Multiple valid
cross-signed paths may exist; the displayed path is one verifier-selected path,
not an assertion of a unique universal chain.

A verified result means this hostname and current server-auth path passed this
observation under this host's trust roots. It says nothing about every browser,
every load-balancer address, old TLS profiles, future responses, revocation or
Certificate Transparency. A compromised host, browser extension, same-origin
script, root store or network environment is outside this guarantee.
