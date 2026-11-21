# Rootwell — current status

22 November 2026, at `main` `b8bfa5f`. Rootwell is in development and has not
been released: use only test material. The plan is
[`PRODUCT-PLAN.md`](PRODUCT-PLAN.md); the review behind it is
[`AUDIT-2026-11-22.md`](AUDIT-2026-11-22.md).

## What exists

**Tools (offline)**
- They run in the browser through the Go core compiled to WebAssembly, and as
  the `rootwell` command.
- Selected files stay in the browser; the command makes no network requests.
- What they do:
  - **Inspect** certificates and bundles.
  - **Convert** PEM to DER and back.
  - **Private keys:** convert them, with encrypted PKCS#8 output by default.
  - **PFX:** open it, extract a certificate or an encrypted key, or create one.
  - **Requests:** create a key and CSR, or sign with an existing key.
  - **Match** a certificate to its key.
  - **Verify** a server chain against a chosen root and hostname.
- `rootwell-probe` is a separate command that checks the TLS certificate one
  IP and port serve, against a pinned root.

**Certificates (Linux only)**
- `rootwelld` stores certificates, bundles and private keys, encrypted with a
  key that opens from the sign-in password.
- What a user can do:
  - add a certificate, a bundle or a PFX;
  - add a key later to a certificate saved without one;
  - add notes;
  - see expiry reminders;
  - download the public certificate;
  - download the key encrypted, after the password.
- Durable storage is turned off on Windows.

**Website check (Linux only)**
- Connects once to a public HTTPS site and explains its chain: missing or
  wrong intermediates, dates, and names.
- Can compare the result with a certificate the user holds.

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
