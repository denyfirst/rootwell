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
  - one stylesheet with fixed sizes (`web/workbench/rootwell.css`).
- Rootwell's colour is graphite, decided on 22 November 2026. Porch is violet
  and Keybash cyan. Rootwell stays neutral, so the only colours on a page are
  the verdicts: green for good, amber for close to its end, red for expired or
  broken. A control is never drawn in a verdict's colour.
- A person who knows nothing about certificates must understand a page from
  how it looks: status pills, a lifetime bar, a drawn chain. No paragraph
  under a control explains what it does.

## 3. What a user does

The usual path is:

1. Sign in with a name, a password and a code from a phone.
2. **Certificates** lists every certificate with the days it has left, where
   it is used and whether its key is kept. Clicking one opens its details:
   the lifetime bar, the chain, the names it works for, and Download, Check
   website and Delete.
3. Add a certificate by dropping a file, a bundle or a PFX: Rootwell
   recognises what it is. Or add a website to watch, and Rootwell reads its
   certificate. Or get one from Let's Encrypt.
4. It renews by itself, is written where the server reads it, and a message
   arrives if anything needs a person.

The pages in the menu:

| Page | What it is for |
|---|---|
| Certificates | Everything kept, how long each lasts, where it is used; renew one by hand |
| Website check | What a website really sends, what is wrong, how to fix it; watch it |
| Inspect | What is inside a file; does a key match; is the chain complete |
| Convert | A certificate, key or PFX into the format a server needs |
| Request | A CSR for a commercial CA, whose new key Rootwell keeps until the certificate arrives |
| Alerts | Where Rootwell writes when a certificate comes close to its end |
| Account | Password, phone codes, recovery codes |
| Installation | How browsers reach Rootwell; a backup |

**Renewals** comes back to the menu when renewal through ACME works (Phase
3c, after the first release).
Users and Activity come later.

**Removed** on 22 November 2026, as noise for a person:

- the staging-only Renewals page, with its 14 confirmations and 10 password
  fields;
- the separate Verify tool with a hand-picked root. Website check does its
  job, and Inspect keeps a short chain check;
- the 30-second key reveal (download the key instead);
- the history archives, request pages, timing watch and DNS maintenance;
- separate location, owner and note panels. One edit has two fields: where
  it is used, and who is responsible;
- the separate Check button, since Save checks;
- the bulk-import section. The Add dialog takes several files at once;
- every demo file, demo link and sample website on product pages. Sample
  files live in tests only.

On 23 November 2026 the hidden Renewals page and the staging automation behind
it were deleted from the code too, ahead of Phase 3c (section 7).

**Added**, in order of value:

1. **Alerts:** e-mail and Telegram when a certificate has 30, 14 or 7 days
   left or has ended; later also when a renewal fails, or when a watched
   website serves a certificate Rootwell does not expect. E-mail and
   Telegram were done on 27 November 2026 (ADR 0092); webhooks for Teams
   and Slack come later.
2. **Watched websites:** "Watch this site" in Website check. Rootwell checks
   it every six hours, and writes when it serves another certificate or has a
   problem. Done on 27 November 2026 (ADR 0093).
3. **Real renewal** with Let's Encrypt and Cloudflare DNS, nobody signed in
   (Phase 3c, after the first release).
4. **Finishing a request:** the key of a CSR stays in Rootwell, sealed. When
   the CA sends the certificate, Rootwell pairs them and keeps both, and a
   renewal takes the old certificate's place. Done on 27 November 2026
   (ADR 0091).
5. **Download for the server:** one button for nginx and Apache (PEM: full
   chain and key) and one for Windows and IIS (PFX), so nobody has to know
   format names. Done on 27 November 2026; the key stays locked with the
   download password, and the ZIP says how each server reads it.
6. **Delivery** to the server (Phase 3d, after the first release). Later,
   through Keybash, which already reaches the servers.

## 4. Architecture

- One Go service, `rootwelld`, on Linux with systemd under its own user.
  - It is installed from source with `scripts/install.sh`, with matching
    upgrade and uninstall scripts.
  - Docker Compose stays as a development profile.
- HTTPS only. It listens on loopback by default and can also listen on named
  LAN or VPN addresses. For its own certificate it makes a local certificate
  authority at its first start, which a browser trusts once; later it can use
  a public certificate it obtains for itself.
- The store is bbolt, as in Keybash, with one record per object. History is a
  rolling log and never blocks a write.
- The browser tools are the Go core compiled to WebAssembly and run in
  dedicated workers, as today. Selected files never leave the browser.
- Network reach is limited to four kinds of destination:
  - the ACME CAs and the DNS provider APIs, at fixed hosts;
  - the websites a user checks, public or private, never loopback,
    link-local or metadata (ADR 0090);
  - for alerts, the mail server the person names, under the same address
    rule, and Telegram at its fixed host (ADR 0092);
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
| Password guessing | Argon2id, rate limits per name and per source, mandatory TOTP, optional passkeys | TOTP can be phished, even when a passkey is added |
| Server-side request forgery | Fixed hosts for CAs and DNS APIs; website checks are for the signed-in owner only, dial only checked addresses (never loopback, link-local or metadata), one every 5 seconds; no redirects; alerts reach the named mail server under the same address rule, over verified TLS, and Telegram's fixed host only (ADR 0092) | A check, or the mail server setting, can reach the owner's internal network, by design (ADR 0090) |
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
- Optional passkeys, which stand in for the phone code and resist phishing.
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
- Alerts by e-mail or webhook, on a failure or near expiry (section 3).

## 7. Phases

| Phase | Result | Exit condition |
|---|---|---|
| 0 — English repository | Plan, status, audit; the Azerbaijani documents replaced | No Azerbaijani text in tracked files, except Unicode test inputs |
| 1 — Security fixes | The audit findings that matter before the rebuild | Each fix has a test that fails on the old code |
| 2 — Design | The Denyfirst design system and the shared rail | Screenshots in both schemes and at phone width |
| 2b — Pages | Every page rebuilt in the graphite design: Inspect, Convert, Request, Website check, Certificates, Account; demos and removed features gone | A person who knows nothing of certificates can use each page; screenshots in both schemes and at phone width |
| 3a — Accounts | HTTPS, accounts, TOTP, instance key | They replace the password-derived unlock, loopback HTTP and the offline-only ceremonies |
| 3b — Store | Rolling history, online backup and restore from the Installation page, instance key rotation; the bbolt vault with sealing per record itself landed in 3a | Restore to a clean instance is verified |
| 3b+ — Certificate lifecycle | Renewal by hand, with the new key kept in Rootwell and the new certificate taking the old one's place (ADR 0091); alerts by e-mail and Telegram; watched websites; downloads for the server | A renewal made from a sheet finishes with its key and replaces the old certificate; a test alert arrives; a watched site that changes certificate raises one |
| 3e — Package | Install, upgrade and uninstall scripts; signed reproducible releases | Install on a clean host is verified |
| 4 — Release readiness | An independent review; documented limits | No open material finding |
| 3c — Renewals, after the first release | Production and staging, an unattended scheduler, Cloudflare DNS-01, a plain Renewals page; a live CA and DNS test on a real domain | A renewal completes with nobody signed in |
| 3d — Delivery, after the first release | Delivery targets and the check after delivery | Files are replaced atomically and the unit is reloaded |

**Phase 3a, where it stands** (ADR 0088):

1. **Part 1** (PR 122) added the vault, account, QR-code and server-certificate
   packages, not yet wired to the service.
2. **Part 2** moved the Certificates page into the vault, opened by an
   instance key kept in its own file outside the data directory.
   `rootwelld init` shows the key's recovery code once, and
   `rootwelld key-restore` rebuilds a lost key file from it. The sign-in
   password now only signs in. This closes audit findings RW-01, RW-11 and
   RW-12.
3. **Part 3** brought accounts, kept in the vault. `rootwelld init` prints a
   setup code; the setup page makes the account with a name, a password and
   an authenticator app on the phone, and shows ten recovery codes once.
   Sign-in takes the password, then a phone code or a recovery code. Sessions
   live in memory, end after 15 minutes idle and 8 hours at most, and only
   wrong tries count against a name or an address. Downloading a key,
   deleting a certificate with a key, and changing the password, the phone or
   the recovery codes need a phone code from the last ten minutes; nothing
   asks for the password again. `rootwelld setup-code` with an account's name
   is the way back after losing the password, or the phone and the codes. The
   access file, its password-only commands and `instanceaccess` are gone, and
   `rootwelld` runs only on Linux. This closes audit findings RW-07, RW-09,
   RW-10 and RW-14. This release has one account.
4. **HTTPS**, the second half of part 3, replaced plain HTTP on loopback.
   `rootwelld` answers only over HTTPS with TLS 1.3, on port 4180 of the
   loopback addresses and of any LAN or VPN address named with `--listen`.
   Its first start makes Rootwell's own certificate authority in the vault,
   which signs a 90-day server certificate that the running server renews. A
   person trusts the authority once: `/rootwell-ca.pem`, checked against the
   fingerprint `rootwelld` prints. `rootwelld serving-names` adds LAN or VPN
   names, with a new authority. A request needs one of the covered names and
   an exact `https://` Origin, which closes RW-02 except on `localhost`.

Part 2 also removed the old automation early: the hidden Renewals page, the
session-bound ACME automation, the old encrypted store and its offline
commands. ADR 0088 planned to remove them as their replacements land. They
went now because nothing has been released, there are no users, the page was
hidden, and keeping them would have meant moving them to the vault only to
delete them in Phase 3c. Renewal comes back in Phase 3c, built on the ACME
protocol packages that stay (section 8).

**Passkeys** followed Phase 3a, on 24 November 2026 (ADR 0088, invariant
C113). A passkey added on the Account page stands in for the phone code at
sign-in and in the fresh-code dialog, with the device's fingerprint, face or
PIN. It is optional: the phone stays mandatory and is the way back. A passkey
works only on the name it was added on, never on an IP address, and a setup
code that replaces the account's sign-in removes them.

**Phase 3b** followed on 24 November 2026 (ADR 0088, invariant C114). The
**Installation** page shows how browsers reach Rootwell and, after a fresh
code, downloads a backup while it runs: a consistent copy of the whole vault,
sealed, which never holds the instance key and opens only with the key it was
made under. On the server, with the service stopped, `rootwelld restore` puts
a backup into an empty data directory, with the key file or its recovery
code; `rootwelld key-rotate` moves the vault to a new instance key, which
closes RW-04; and `rootwelld key-export` shows the key's recovery code again.
A backup from the page, restored through the container into an empty data
directory on a test machine, brought back its four certificates with their
places, owner and saved key, which meets the exit condition. The rolling
history in the table was not built: the vault keeps no history, so it never
refuses a write (RW-01), and an activity log stays under Later.

A first internal review of Phase 3 followed the same day, and its findings
are fixed:
- Key rotation gives every record a new data key and rewrites the file, and
  a backup copies live records only, so an old key opens nothing current
  (C114).
- Sign-in tries sent together are counted one by one (C110).
- A browser that signed in before is not locked out by others' failures, and
  wrong setup codes count against their source only (C110).
- A fresh code moves the session to a new token (C111).
- The local authority cannot sign for names below its own, and one-word
  names are refused (C112).
- Pages forget phone keys and recovery codes on leaving, and the delete
  dialog acts only on the certificate it named.

One limit stays and is written down (C114): someone who can write the vault
file without the key can put an older sealed record back.

**The first release, decided on 27 November 2026.** The owner moved renewal
through ACME (Phase 3c) and delivery (Phase 3d) after the first release: they
touch DNS tokens and live servers, and get built slowly once Rootwell is in
use. Before it, the certificate work is finished (Phase 3b+), then Phase 3e
and the independent review of Phase 4.

**Phase 3b+, where it stands.** Renewal by hand landed first (ADR 0091). A
sheet's Renew makes a request for the same names with a new key that
Rootwell makes and keeps; the Request page keeps new keys the same way. When
the provider's certificate is added, it finds its key, and a renewal takes
the older certificate's place, keeping where it is used and who looks after
it. Alerts by e-mail and Telegram followed (ADR 0092): 30, 14 and 7 days
before a certificate ends and on the day, once each, from a page beside
Account. Downloads named by the server followed: PEM files for nginx and
Apache, a PFX for Windows and IIS. Last came watched websites (ADR 0093):
checked every six hours, with an alert when one serves another certificate or
has a problem. Phase 3b+ is complete.

**Next:** Phase 3e (install scripts and signed releases) and Phase 4 (an
independent review), then the first release, with the owner's go-ahead.

**Later:**
- roles and invites;
- an activity log;
- more DNS providers;
- HTTP-01;
- other ACME CAs;
- delivery through Keybash;
- certificates from a small internal CA, for printers, NAS and intranet.

## 8. What stays from today

**Kept, as the audit found them sound:**
- file parsing and checking: `certinspect`, `certverify`, `keymatch`,
  `fileinput`, `publicbundle` and `publicconvert`;
- keys, PFX and requests: `pfxinspect`, `pfxcreate`, `pfxkeyexport`,
  `csrworkbench` and `secretfile`;
- the browser packages;
- website checks: `websiteprobe` and `websitechain`;
- ACME and DNS: the protocol pieces of `acmestaging` (directory,
  registration, order, certificate, Cloudflare and renewal information), with
  `acmeplan`, `acmeorder`, `acmeprofile`, `acmecertificate`,
  `acmecertrequest`, `renewalpolicy`, `renewalrecord`, `cloudflareconfig`,
  `dnsrecord` and `providerretry`. They have no caller in the service until
  Phase 3c makes them general over fixed profiles.

**Replaced on 24 November 2026**, in Phase 3a part 3:
- the password-derived unlock and its ceremonies (`instanceaccess`), with the
  access file and its password-only commands;
- the old session layer of `cmd/rootwelld/gate.go`, by accounts and sessions
  (`internal/accountstore`, `cmd/rootwelld/session.go`);
- the loopback HTTP transport, by HTTPS with Rootwell's own certificate
  authority (`internal/servecert`, `internal/servingstore`).

**Removed on 23 November 2026**, in Phase 3a part 2:
- the single-image store and its capacity reservations (`inventorystore`,
  `inventoryseal`), with its offline snapshot commands;
- the staging-only automation state machine: timing watch, session renewal
  job, closed-request pages, history archives, DNS maintenance, the stored
  Cloudflare token and ACME account keys, and the hidden Renewals page.

## 9. Open decisions

- Whether the first release has roles, or a single administrator.
- Whether a plain PEM download stays available, and on what condition.
- Whether Docker is supported beyond development.
