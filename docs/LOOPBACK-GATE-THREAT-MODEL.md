# Loopback setup gate threat model

**Scope:** single-operator, self-hosted development gateway for the existing
public-only Workbench. It binds only to 127.0.0.1. No vault, inventory,
private-key upload, remote listener, TLS termination, or recovery is provided.

The local operator runs `rootwelld init` interactively on the host. Only that
command displays a per-installation initial password on a terminal. The server
never prints a password, accepts one in a CLI argument, or recreates an
existing access file. If init output is lost, it cannot be redisplayed.

The server checks a password using the key envelope from ADR 0013. A correct
initial password receives a 15-minute setup-only session. It can reach only
the password-change page and session endpoints; static Workbench assets and
every future API are behind a ready-only gate. Successful change rewraps the
same data key, revokes every session, and requires fresh sign-in. Closing the
browser before change leaves the installation in setup mode.

Authentication requests are bounded JSON POSTs with exact same-origin Origin
checks, a custom request header, a global attempt limit, and one active KDF
operation. The session is a random opaque token in a Secure, HttpOnly,
SameSite=Strict, host-only cookie. No password or token is placed in URLs,
browser storage, or logs. Cache-Control: no-store is applied to protected
responses. The server validates Host to reject DNS rebinding. It serves only
an explicit list of static filenames from an operator-controlled directory.
The server refuses startup when a required browser engine or script is missing;
directly serving the same static source directory elsewhere bypasses this gate
and is only a developer preview.

Each issued session is bound to a SHA-256 revision of the bounded, privately
opened encrypted access file. Sign-in refuses an access-file change observed
between password verification and session issuance. On later requests, a
missing, reader-rejected, or different access file invalidates that session, including
when another process changes the password. This is fail-closed detection at
request boundaries, not a cross-process lock or a monotonic anti-rollback
record: a same-byte rollback between requests or a change during one request
is not proven impossible. The reader still does not validate Windows ACLs.

**Residual boundaries:** HTTP over host loopback is not a remote transport
security claim. Remote access requires an SSH tunnel to the host loopback or
future reviewed TLS deployment. Some browsers do not support Secure cookies
on plain HTTP localhost; those browsers must not silently fall back to an
insecure cookie. The access file's Windows ACL and directory ownership,
concurrent process instances, durable backups/recovery, and lost-password
flow require further review before production secret custody. A compromised
host, browser extension, or same-origin script can act as the user. The
Workbench remains public-certificate-only and stores no user history.
