# Rootwell — current status

23 November 2026. Rootwell is in development and has not been released: use
only test material. The plan is
[`PRODUCT-PLAN.md`](PRODUCT-PLAN.md); the review behind it is
[`AUDIT-2026-11-22.md`](AUDIT-2026-11-22.md).

The plan is in Phase 3a. Its first two parts are done: the vault and the
instance key, with the Certificates page moved onto them. Accounts with TOTP,
sessions and HTTPS are next.

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
- `rootwelld` keeps certificates, bundles and private keys in a vault,
  `rootwell.db` in the data directory. Each record is sealed under its own
  key, and record names do not show the domains.
- An **instance key**, in its own file outside the data directory, opens the
  vault. `rootwelld init` shows its recovery code once. The sign-in password
  only signs in; it unlocks no data.
- A private key is opened only for a download; listing never opens one.
- The list holds up to 500 certificates, with no limit on how often it
  changes.
- What a user can do:
  - add certificates, a bundle, a key or a PFX, several files at once;
  - add a key later to a certificate saved without one;
  - note where it is used and who is responsible;
  - see how long each one has left;
  - download the certificate, the full chain, or the certificate and key;
  - download the key locked with a password, after the sign-in password.
- On Windows the pages open as a preview: no key file or vault is made, and
  saving is turned off.

**Website check (Linux only)**
- Connects once to a public HTTPS site and explains its chain: missing or
  wrong intermediates, dates, and names.

**Renewal: removed for now**
- The staging-only ACME automation and its hidden Renewals page were removed
  on 23 November 2026: test accounts, DNS orders, issuance, manual renewal,
  the session renewal job and the production account key.
- Real renewal comes back in Phase 3c, built on the ACME protocol packages
  that stay.

**Access and recovery**
- One account: password sign-in on `http://localhost:4180`, loopback only.
- `rootwelld key-restore` rebuilds a lost instance key file from its recovery
  code.
- Backups are, for now, a copy of the data directory made with the service
  stopped; the key file never goes with it
  ([`RECOVERY.md`](RECOVERY.md)).
- Terminal commands for the sign-in password alone: a password recovery code
  and access-only snapshots.
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
  - a container volume drill: seed, reopen, serve, refusals and restart.

## What does not exist yet

- A certificate a browser trusts.
- Renewal of any kind.
- Delivery to servers.
- HTTPS, MFA, more than one account, or remote access without an SSH tunnel.
- Online backup and restore, from the web or with the service running, and
  instance key rotation.
- An install script and releases.

Each one has a phase in the plan.
