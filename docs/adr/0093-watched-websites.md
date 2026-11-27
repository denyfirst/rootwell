# ADR 0093: Watched websites

## Status

Accepted on 27 November 2026. It is item 2 of PRODUCT-PLAN section 3 and
builds on Website check (ADR 0090) and alerts (ADR 0092). Amended the same
day: a site is checked every six hours, not once a day, so a change is known
the same working day.

## Context

Rootwell knows the certificates a person keeps, not what their servers
serve. After a renewal by hand (ADR 0091) nobody tells the person whether the
new certificate went onto the server, and a server can start failing, or
serve a certificate nobody expected, between two visits to Website check.

## Decision

**Watching.** After a check, Website check offers "Watch this site". The site
is kept in the form Website check writes it: a name or address, with its port
when that is not 443. An address the check could never dial (loopback,
link-local, metadata, reserved) is refused when it is added. At most 50 sites
are watched. Each is one sealed vault record, indexed by an HMAC of its name.
Watching needs a signed-in session, as a check does; stopping a watch
silences it, so it needs a fresh code (C111).

**Checking.** In the hourly loop that sends alerts, before them, each site
not checked in the last six hours is checked, the one waiting longest first,
exactly as a person's check: the same address rule, connection limits and
saved roots, and the same single slot and 5-second gap, which the watched
checks share with people's. Fifty sites make at most 200 checks a day. A check saves only what the page shows: the
verdict, its first problem in one sentence, and the certificate the site
served (fingerprint, name, end).

**Telling.** An alert goes out when a watched site serves another certificate
than at its last check, or has a problem it did not have: a broken or
incomplete chain, a wrong name, an ending certificate, or no answer. Each
change is told once; a site that stays broken says nothing more until it
changes again. The first check after watching tells nothing, since the person
saw that result when they chose to watch. The message names the site, the
certificate it serves now and when the one before ended, and links to
Website check for it.

## Consequences

- The person learns that a renewal reached the server, and when a server
  starts failing, within seven hours: six between checks, and up to one
  more until the hourly loop runs.
- Watched names are kept in the vault; like Website check, a watched site
  can be an internal server (ADR 0090).
- A site that changes certificate often, such as one behind several servers
  with different certificates, tells each change.
- Not built: watching more often than every six hours, and comparing a served
  certificate with the saved ones beyond showing its end.

## Evidence

`TestSitesAreAddedOnceAndUpToTheLimit`, `TestASiteIsDueEverySixHours`,
`TestEachChangeIsToldOnce`, `TestASiteRecordIsReadStrictly`,
`TestLinuxASiteIsWatchedInCheckFormAndStoppingNeedsAFreshCode`,
`TestLinuxWatchedSitesAreCheckedEverySixHoursAsWebsiteCheckDoes`,
`TestAWatchMessageSaysWhatChanged` and `scripts/test-website-check.mjs`.
