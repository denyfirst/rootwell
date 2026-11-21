# Rootwell — product plan

Written on 22 November 2026, when Rootwell got a new maintainer. This English
plan replaces the Azerbaijani plan, the execution log and the platform vision;
their history stays in Git. What exists today is in `STATUS.md`. The review
behind this plan is `AUDIT-2026-11-22.md`.

## 1. Goal

Rootwell is a self-hosted place where a small team:

- keeps its TLS certificates and their private keys;
- gets them renewed without anyone signing in;
- has them written where its servers read them;
- sees what a website really serves.

It also gives safe offline tools for certificate files, so nobody uploads a
private key to a converter website again.

Rootwell is one of three Denyfirst products:

- **Porch** measures from the outside what a server presents.
- **Keybash** keeps SSH and RDP access.
- **Rootwell** keeps certificates and keys, renews them and delivers them.

They are separate repositories, products and releases.

The order of priorities is fixed: security, then correctness, privacy,
recoverability, comfort, and features last. Comfort is designed together with
security, not after it. A step that adds friction without stopping a real
attack is removed.

## 2. Agreed boundaries

- Self-hosted only. There is no Denyfirst cloud account, relay or central
  store.
- After the install, every task happens on web pages. The command line keeps
  only the server-side decisions:
  - installing;
  - choosing the networks Rootwell listens on;
  - choosing the delivery targets;
  - the break-glass recovery.
- The interface and the repository are in English, in plain words. A limit is
  stated once, where it matters, not as a disclaimer on every line.
- There are no users yet, and nothing has been released. Until the first
  release, old paths are replaced rather than migrated, and there are no
  fallbacks. Data from development builds is not carried forward.
- The design is the Denyfirst family design shared with Porch and Keybash:
  - Schibsted Grotesk, served by Rootwell itself;
  - light and dark schemes;
  - Rootwell's own colour.

  Red, amber and green mean only a verdict, never a control.

## 3. What a user does

The usual path is:

1. Sign in with a password and a code from a phone.
2. **Certificates** lists every certificate, with the days it has left and how
   it renews.
3. Add a certificate from a file or a PFX, or get one from Let's Encrypt.
4. From then on it renews by itself and is written where the server reads it.
5. **Website check** confirms the server serves it.

The pages in the menu:

- **Certificates**
- **Renewals**
- **Website check**
- **Tools** (the offline workbench)
- **Installation**
- **Account**

Users and Activity come later.

## 4. Architecture

- One Go service, `rootwelld`, on Linux with systemd under its own user.
  - It is installed from source with `scripts/install.sh`, with matching
    upgrade and uninstall scripts.
  - Docker Compose stays as a development profile.
- HTTPS only. It listens on loopback by default and can also listen on named
  LAN or VPN networks. For its own certificate it starts with a local test CA
  at install; later it can use one it issues for itself.
- The store is bbolt, as in Keybash, with one record per object. History is a
  rolling log and never blocks a write.
- The browser tools are the Go core compiled to WebAssembly and run in
  dedicated workers, as today. Selected files never leave the browser.
- Network reach is limited to three kinds of destination:
  - the ACME CAs and the DNS provider APIs, at fixed hosts;
  - the websites a user checks, at public addresses only;
  - nothing else.

## 5. Security model

**Protected:**
- private keys and ACME account keys;
- DNS API tokens;
- sign-in passwords, MFA seeds and recovery codes;
- session tokens.

**Trusted:**
- the host administrator;
- `rootwelld`;
- the shipped code;
- the user's browser.

**Untrusted input:**
- answers from CAs and DNS providers;
- the websites that are checked;
- every file a user selects.

| Threat | Control | Remaining boundary |
|---|---|---|
| Stolen database or backup | Each secret is sealed under its own data key; the data keys are under an instance key kept in a separate file; backups are encrypted | If the instance key is taken too, the protection is gone |
| Live host compromise | None beyond the operating system: Rootwell must use keys to renew them | This is not a zero-knowledge design |
| Session theft, CSRF, XSS | HTTPS, a `__Host-` cookie, exact Origin and Fetch Metadata checks, a strict CSP, safe DOM writes | Malicious browser extensions |
| Password guessing | Argon2id, rate limits per name and per source, mandatory TOTP | TOTP can be phished |
| Server-side request forgery | Fixed hosts for CAs and DNS APIs; website checks dial only checked public addresses; no redirects | Public addresses used internally |
| Wrong certificate delivered | Delivery only after the chain, names and key match are verified; atomic replace; the previous files are kept | The served result depends on the server's own reload |
| Hostile files | Bounded parsers, fuzzing, single-use workers | Unknown parser defects |

### Keys and the vault

- Each private key, account key and API token gets:
  - its own random data key;
  - an AEAD seal bound to the record and its version.
- The instance key lives in its own `0600` file. It is never kept in the
  database or a backup. A recovery copy is shown once at install.
- **Rootwell can open keys without a person.** Unattended renewal needs this.
  The old design opened keys only during a signed-in session of at most
  12 hours, which made automatic renewal impossible. This is the deliberate
  change.
- A private key leaves Rootwell in two ways only:
  - to a delivery target set up on the server;
  - as a download after a fresh phone code. The download is encrypted by
    default; plain PEM is an explicit choice.

### Sign-in and sessions

These follow Keybash:

- A one-time bootstrap code for the first account.
- Argon2id passwords of at least 15 characters, checked against a blocklist.
- Mandatory TOTP and one-time recovery codes.
- Sessions end after 15 minutes idle and after 8 hours at most.
- A fresh phone code (from the last ten minutes) is needed only to:
  - show or download a private key;
  - delete a certificate that has a key;
  - save or replace a DNS token;
  - register a CA account;
  - change a delivery.

  Nothing else asks for the password again.

## 6. Renewal and delivery

- **CAs:**
  - Let's Encrypt production and staging, as fixed profiles;
  - later, any ACME CA with external account binding.
- **Challenges:**
  - DNS-01 through Cloudflare first, with a token scoped to the zone;
  - manual DNS for a one-off;
  - HTTP-01 later.
- **When:** in the CA's renewal window (ARI) when it offers one, otherwise at
  two thirds of the lifetime. Failures retry with backoff, and nothing waits
  for a person.
- **Delivery:** root sets up delivery targets on the server: a directory, file
  names, owner, mode and a systemd unit to reload. A page can attach a
  certificate to a target root created. It can never name a path or a
  command. Rootwell writes the files atomically, keeps the previous set and
  reloads the named unit.
- After a delivery, an optional website check confirms the new certificate is
  served.
- Notifications by e-mail or webhook, on a failure or near expiry, come later.

## 7. Phases

| Phase | Result | Exit condition |
|---|---|---|
| 0 — English repository | Plan, status, audit; the Azerbaijani documents replaced | No Azerbaijani text in tracked files, except Unicode test inputs |
| 1 — Security fixes | The audit findings that matter before the rebuild | Each fix has a test that fails on the old code |
| 2 — Design | The Denyfirst design system; a rail and top bar as in Keybash; plain words on Tools, Certificates and Website check | Screenshots in both schemes and at phone width |
| 3a — Accounts | HTTPS, accounts, TOTP, instance key | They replace the password-derived unlock, loopback HTTP and the offline-only ceremonies |
| 3b — Store | bbolt with sealing per secret, rolling history, encrypted backup and restore from the Installation page | Restore to a clean instance is verified |
| 3c — Renewals | Production and staging, an unattended scheduler, Cloudflare DNS-01, a plain Renewals page | A renewal completes with nobody signed in |
| 3d — Delivery | Delivery targets and the check after delivery | Files are replaced atomically and the unit is reloaded |
| 3e — Package | Install, upgrade and uninstall scripts; an Installation page; signed reproducible releases | Install on a clean host is verified |
| 4 — Release readiness | An independent review; a live CA and DNS test on a real domain; documented limits | No open material finding |

**Later:**
- roles and invites;
- an activity log;
- notifications;
- more DNS providers;
- HTTP-01;
- other ACME CAs.

## 8. What stays from today

**Kept, as the audit found them sound:**
- file parsing and checking: `certinspect`, `certverify`, `keymatch`,
  `fileinput`, `publicbundle` and `publicconvert`;
- keys, PFX and requests: `pfxinspect`, `pfxcreate`, `pfxkeyexport`,
  `csrworkbench` and `secretfile`;
- the browser packages;
- website checks: `websiteprobe` and `websitechain`;
- ACME and DNS: the protocol pieces of `acmestaging` (directory,
  registration, order, certificate, Cloudflare and renewal information),
  made general over fixed profiles, and `providerretry`.

**Replaced in Phase 3:**
- the password-derived unlock and its ceremonies (`instanceaccess`);
- the single-image store and its capacity reservations (`inventorystore`,
  `inventoryseal`);
- the loopback HTTP session layer (`cmd/rootwelld/gate.go`);
- the staging-only automation state machine: timing watch, session renewal
  job, closed-request pages, history archives and DNS maintenance.

## 9. Open decisions

- Whether the first release has roles, or a single administrator.
- Whether a plain PEM download stays available, and on what condition.
- Rootwell's colour, decided from the Phase 2 screenshots.
- Whether Docker is supported beyond development.
