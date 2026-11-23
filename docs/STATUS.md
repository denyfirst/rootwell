# Rootwell — current status

23 November 2026. Rootwell is in development and has not been released: use
only test material. The plan is
[`PRODUCT-PLAN.md`](PRODUCT-PLAN.md); the review behind it is
[`AUDIT-2026-11-22.md`](AUDIT-2026-11-22.md).

## What exists

**Pages**
- Six pages in the menu, in the graphite design, light and dark:
  Certificates (the home page), Website check, Inspect, Convert, Request and
  Account. Sign-in and setup wear the same design.
- No demo files, demo links or sample websites ship with the pages; the tests
  generate their own material.

**Tools (offline)**
- They run in the browser through the Go core compiled to WebAssembly, and as
  the `rootwell` command.
- Selected files stay in the browser; the command makes no network requests.
- What they do:
  - **Inspect** a certificate or a chain: who it is for, who issued it, how
    long it lasts, whether the chain is complete, and whether a private key
    belongs to it.
  - **Convert** a certificate, key or PFX into PEM files, a single
    certificate, a new PFX, or a key in PEM, DER or the older RSA and EC forms.
  - **Request** a CSR with a new key or an existing one.
  - **Verify** a server chain against a chosen root and hostname, with the
    `rootwell verify` command.
- `rootwell-probe` is a separate command that checks the TLS certificate one
  IP and port serve, against a pinned root.

**Certificates (Linux only)**
- `rootwelld` stores certificates, bundles and private keys, encrypted with a
  key that opens from the sign-in password.
- What a user can do:
  - add certificates, a bundle, a key or a PFX, several files at once;
  - add a key later to a certificate saved without one;
  - note where it is used and who is responsible;
  - see how long each one has left;
  - download the certificate, the full chain, or the certificate and key;
  - download the key locked with a password, after the sign-in password.
- Durable storage is turned off on Windows.

**Website check (Linux only)**
- Connects once to a public HTTPS site and explains its chain: missing or
  wrong intermediates, dates, and names.

**ACME automation (Let's Encrypt staging only)**
- What works:
  - a test account;
  - a manual DNS or Cloudflare DNS-01 order;
  - issuance;
  - manual renewal;
  - a renewal job that runs while its session lives (12 hours at most).
- A local production account key can be prepared, but nothing talks to the
  production CA.

**Access**
- One account: password sign-in on `http://localhost:4180`, loopback only.
- An offline recovery code, and terminal ceremonies for full snapshots and
  restore ([`RECOVERY.md`](RECOVERY.md)).
- A Docker Compose development profile
  ([`CONTAINER-RECOVERY.md`](CONTAINER-RECOVERY.md)).

**Engineering**
- Every page was tested end to end on a fresh Linux machine installed from
  [`CONTAINER-RECOVERY.md`](CONTAINER-RECOVERY.md), in a real browser.
- Signed commits only, checked against the base branch's signer list.
- Thirteen CI checks:
  - Linux race tests;
  - vet on Linux, macOS and Windows;
  - pinned staticcheck, gosec and govulncheck;
  - fuzzing;
  - a reproducible-build check;
  - container restore and upgrade drills.

## What does not exist yet

- A certificate a browser trusts.
- Renewal with nobody signed in.
- Delivery to servers.
- HTTPS, MFA, more than one account, or remote access without an SSH tunnel.
- Backups from the web.
- An install script and releases.

Each one has a phase in the plan.
