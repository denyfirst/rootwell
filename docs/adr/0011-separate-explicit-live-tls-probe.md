# ADR 0011: Separate, explicitly invoked live TLS probe

## Status

Accepted for development; not an independent security audit.

## Decision

The existing `rootwell` Workbench CLI and browser remain network-free. A
separate executable, `rootwell-probe`, is the only production package allowed
to import networking. It performs one operator-requested TCP/TLS probe to an
explicit literal IP and port. The hostname is separately supplied for SNI and
certificate verification; the probe does not resolve DNS, make HTTP requests,
follow redirects or AIA/OCSP/CRL URLs, send application data, use system roots,
or execute a child process. Its five-second deadline covers the connection and
handshake. The operator must be authorized to contact the target.

The command requires a strict PEM trust bundle, the full SHA-256 fingerprint
of the intended root obtained independently, and a local public certificate
for the expected leaf. It validates and selects the pinned root before any
network action. Go's TLS client verifies the handshake using only that root
and the explicit hostname. Before a successful handshake is reported, the
connection callback compares the served leaf's exact DER fingerprint with
the expected leaf and re-runs Rootwell's TLS-server verification policy using
only the intermediates presented by the peer and the pinned root. Thus a
locally available but missing server intermediate cannot mask deployment
failure. A missing, malformed, or mismatched input yields no network action or
no success result as appropriate. Diagnostics never echo paths or peer text.

The process is local and read-only. It does not install, renew, revoke, or
export certificates. An explicit IP avoids surprise DNS resolution and makes
the observation's network vantage concrete. This is an operational spot
check, not the independent Porch integration planned for deployment evidence.

## Non-claims and limits

One TLS handshake observes one endpoint from one vantage at one instant. It
does not prove every load-balancer node, another observer's path, future
behavior, revocation, Certificate Transparency, or the provenance of the
operator's expected leaf and root fingerprint. A compromised host, binary,
trust input, or expected fingerprint is outside this guarantee. TLS itself
authenticates the handshake with the server certificate's key; Rootwell does
not claim that this proves the server's physical identity independently of
the configured trust and network context.

No browser button or server-side request proxy is added. If a future UI or
control plane exposes this capability, it requires its own authorization,
target allowlist, DNS/SSRF, rate-limit, and audit review rather than calling
this executable on arbitrary user input.
