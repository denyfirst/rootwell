# ADR 0084: Explicit website certificate diagnosis

## Status

Development, 2026-11-05. Not independently audited or released.

## Product decision

The operator deferred further automatic-renewal development. Existing merged
automation remains unchanged; unfinished production registration stays in its
own worktree. Rootwell now prioritizes readable website chain diagnosis. Porch
is not modified or copied. This feature is not a general vulnerability scan.

## Boundary

A signed-in ready operator explicitly consents to one public DNS-name:443
TLS observation from their own Rootwell server. Input accepts a DNS name or
an HTTPS origin, not credentials, paths, query strings, IP literals, custom
ports, or arbitrary protocols. DNS answers are bounded and all must pass a
conservative public-address policy. The connector resolves once and dials one
numeric address with the original SNI. It sends no HTTP/application request,
cookies, keys, proxy traffic, redirects, or AIA/OCSP/CRL fetches. One concurrent
check per installation, a 30-second global interval and an eight-second total
deadline bound the operation. Revocation of the original session prevents
later stages and publication; already sent DNS/TLS bytes cannot be recalled.

Only Linux enables the production connector: its explicitly loaded system root
pool uses Go's local path builder without platform AIA retrieval. Native
Windows/macOS refuse before DNS. Synthetic TLS tests inject local fixtures;
preview examples never invoke this connector. Offline Workbench remains offline.

TLS intentionally collects untrusted certificates for diagnosis, completing
only a bounded TLS 1.2/1.3 handshake. This does not authenticate the peer.
The separate pure analyzer verifies signatures, server usage, hostname, dates
and paths against the supplied root pool. Peer-provided roots never become
trusted. A matched issuer name is insufficient: every displayed signature link
uses CheckSignatureFrom. Failed verification is a failed result, not a network
error or a successful trust claim. Raw peer errors are not reflected.

## Presentation

One Website check page within the existing Rootwell shell. Text, icons and
color convey verified / attention / failed; color is never the only cue.
Display a verified path when one exists; otherwise show only unambiguous
signature links and explain that missing issuer and unknown trust cannot
always be distinguished. Include server-sent order, unused certificates,
fingerprints, observation time, connected address and trust-store context in
expandable details. An absent server-sent root is normal. Misordering is a
compatibility warning, not automatic proof of invalid trust. No private key,
file upload, export, stored history or conversion duplicate is added.

## Limits

One endpoint, one vantage, one instant, one offered TLS profile. This is not a
test of every load-balancer address, browser root store, legacy TLS support,
revocation, Certificate Transparency or universal MITM absence. System roots
depend on the operator's installation. Private networks/custom enterprise
trust require a future explicit target/trust authorization design; no private
address bypass is introduced here. Ordinary public services routed by an
operator-controlled network remain dependent on that network's egress policy.
