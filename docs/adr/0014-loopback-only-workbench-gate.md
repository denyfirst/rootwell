# ADR 0014: Separate loopback-only Workbench access gate

Status: accepted for development, not production secret custody.

Rootwell keeps the offline CLI and static public-certificate Workbench free of
server and authentication dependencies. A separately built `rootwelld` serves
the Workbench behind one local installation password on 127.0.0.1:4180. It
cannot bind a remote interface by option. The operator explicitly initializes
an access file on an interactive terminal; the daemon never logs or displays
the password. The initial credential creates a 15-minute setup-only session,
not Workbench access. Password rotation revokes all sessions and requires
fresh sign-in. A ready session expires after 12 hours.

All Workbench routes and assets are denied before a ready session. Mutations
require bounded JSON, an exact same-origin `Origin`, and a custom header; Host
is fixed to `localhost:4180`. Sessions use random opaque values in Secure,
HttpOnly, SameSite=Strict, host-only cookies. The gateway refuses startup if
essential WebAssembly or script assets are absent. The original static server
remains an unauthenticated developer preview and must not be represented as
password-protected.

We reject daemon-log bootstrap passwords because Docker and service logs may
retain them. We reject a remote HTTP listener, even with a password, because
it would disclose credentials and session traffic. SSH tunneling to loopback
is the only documented remote test path until a separate TLS/reverse-proxy
design is reviewed. Secure cookies over HTTP localhost do not work in every
browser; we do not weaken cookie flags to hide that limitation.

The [loopback threat model](../LOOPBACK-GATE-THREAT-MODEL.md) records the
remaining Windows ACL, concurrency, backup/recovery, and browser-compromise
limits. No inventory, private-key storage, or production authorization claim
is introduced here.
