# ADR 0090: Website check reaches internal servers and names what is wrong

## Status

Accepted on 26 November 2026. It changes ADR 0084 (website chain
diagnostics): the public-only address policy, the port 443 limit, the
30-second interval and the unnamed findings.

## Context

A test with real certificates on 25 November 2026 showed two problems.

1. Website check accepted only public DNS names on port 443. Rootwell is
   self-hosted and keeps a company's internal certificates too: intranet
   sites, NAS boxes, printers, mail and VPN gateways on private addresses and
   other ports. "Check website" on such a certificate could never work.
2. The result was hard to act on. emanat.az sends its chain, then a chain to
   an older root for old devices, then that older root. The old analysis
   called the older chain "a certificate the server does not need", without
   naming it, while the chain drawing stayed green. A missing intermediate
   and a self-signed certificate got general wording.

The owner decided on 26 November 2026 that internal servers must be
checkable.

## Decision

**Targets.** A target is a DNS name (one label or more) or an IP address,
with an optional port (1–65535) and an optional `https://` in front. Paths,
user names, queries and fragments are still refused, as are `localhost`,
numbers that resolvers read as addresses (`10.1`, `3232235777`), zoned IPv6
and IPv4 written inside IPv6. A name in another script is sent by the page in
its `xn--` form.

**Addresses.** Every DNS answer (at most 16) must be allowed, or the whole
check is refused. Allowed: public and private networks, including 10/8,
172.16/12, 192.168/16, 100.64/10 and fc00::/7. Never allowed: loopback,
unspecified, link-local (where cloud metadata lives), multicast, broadcast and
reserved ranges, documentation ranges, the known metadata addresses outside
link-local (100.100.100.200, fd00:ec2::254), and IPv6 transition ranges that
embed an IPv4 address (2002::/16, 2001::/23, 64:ff9b::/96, 64:ff9b:1::/48).

**Connections.** A check makes at most three TCP connections to checked
numeric addresses: the first IPv4 answer, then the first IPv6 answer only when
nothing answered or the connection timed out, and one more attempt to the same
address without post-quantum key exchange when the server dropped the first
greeting. Only a TLS handshake happens; no application data is sent. The SNI
is the name, or absent for an address. A check takes at most 15 seconds; each
connection 3 and each handshake 5.

**Rate.** One check at a time, and at least 5 seconds between checks, for the
whole server. Checks remain for the signed-in owner only.

**Failures in words.** Name not found, DNS silent, nothing listening, no
answer in time, not TLS, handshake refused: each has its own sentence naming
the target and the address Rootwell dialed. Peer and resolver text is never
shown.

**Saved roots.** When the chain does not reach a public root, the check tries
again with the self-signed certificate authorities found among the
certificates the person saved in Certificates (at most 64). A success says
"trusted through your root X" and that only devices with that root trust the
site. Roots a server sends are still never trusted, and nothing from a check
is ever saved.

**Findings name certificates.** Every finding carries the fingerprints of the
certificates it is about, and its text names them. Each sent certificate gets
a use: the chain visitors get, an older chain (a sent certificate that links
into the chain by signature or is another issuer's copy of a chain
certificate), a root, or unrelated. Only an unrelated or out-of-date extra
certificate needs a fix; an older chain and a sent root are notes. A missing
issuer, a sent root that is not public, a self-signed website certificate, an
expired certificate, a wrong issuer with the same name, a SHA-1 signature and
a certificate that is not a CA each get their own words and fix. A
certificate sent twice is analyzed once and named. The page marks the
certificates a finding names, draws a missing issuer as a dashed link, and
lists everything else the server sends under "Also sent by the server".

## Consequences

- Rootwell can now reach any non-refused address its host can reach,
  including internal services. Only the signed-in owner can start a check;
  the rate bounds port probing to one target every 5 seconds; a check learns
  only whether a port answers and which certificates it sends. Network egress
  rules on the Rootwell host remain the operator's boundary.
- Revocation is still not checked; the page says so once.
- `docs/WEBSITE-CHECK-THREAT-MODEL.md` and C103 in
  `docs/SECURITY-INVARIANTS.md` describe the new boundary.
