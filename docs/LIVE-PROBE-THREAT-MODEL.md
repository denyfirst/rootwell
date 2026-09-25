# Explicit live TLS probe threat model

**Scope:** development-only `rootwell-probe` executable. This is not the
offline Workbench, browser UI, self-hosted server, agent, or Porch integration.

## Assets and trust

The probe reads public certificate files that can reveal internal identities,
but never reads private keys or passphrases. The operator provides a DNS
hostname for SNI and verification, a literal IP and port to contact, a strict
PEM trust bundle, a full expected root fingerprint obtained through an
independent trusted channel, and the intended public leaf certificate.
Rootwell cannot authenticate the provenance of those expectations. Input
paths, certificate text, peer errors, and network addresses are untrusted.
The supplied hostname is sent as SNI in the TLS ClientHello and may be visible
to the selected peer and on-path observers. Do not send a sensitive internal
name to an untrusted IP.

## Network boundary

The separate executable can initiate only one direct TCP/TLS connection to
the literal operator-selected IP and port per invocation. There is no DNS
lookup by this command, HTTP request, redirect, proxy, embedded URL fetch,
telemetry, child process, or browser API. A five-second timeout covers the
connection and handshake. No TLS application data is sent. No system root or
locally available intermediate may complete the peer's chain. The offline
`rootwell` CLI and browser continue to have no network imports or path to
this executable. Do not wrap this probe in a web API without a new SSRF,
authorization, allowlist, rate-limit, and audit design.

Before connecting, local files are bounded to 16 MiB, the strict root parser
rejects malformed/duplicate/non-self-signed trust entries, the requested
root fingerprint must identify a root in that bundle, and the expected leaf
must be one strict public certificate. Go TLS checks hostname, chain,
validity, usage, and handshake against only the pinned root. The callback
also checks exact served leaf DER identity, caps the observed chain, and
re-runs Rootwell's algorithm/chain policy on intermediates actually supplied
by the peer. If any check fails, no success output is printed. All errors are
fixed strings without reflecting user paths, certificate subjects, or peer
diagnostics.

## Remaining threats and non-claims

- A compromised local host or binary can change the probe or its output.
- A false expected root fingerprint or leaf from a compromised source can
  mislead the operator; Rootwell cannot create an independent trust channel.
- One IP:port handshake sees one endpoint from this machine now. Another
  load-balancer node, geographic vantage, DNS answer, or future connection
  can differ. Successful probing does not assert universal MITM absence.
- Revocation, CT inclusion, OCSP stapling policy, private-key custody, and
  automatic deployment are not checked. The TLS handshake authenticates
  possession for this connection under the configured trust, not ownership
  of the physical host.
- The probe is read-only and does not overwrite any local file; its output
  writer can fail, in which case the command exits unsuccessfully.
