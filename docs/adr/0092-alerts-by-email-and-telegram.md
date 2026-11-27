# ADR 0092: Alerts by e-mail and Telegram

## Status

Accepted on 27 November 2026. It is the first part of the alerts in
PRODUCT-PLAN section 3, with the channels the owner chose: e-mail and
Telegram. Webhooks for Teams and Slack are not built.

## Context

Rootwell showed how long each certificate lasts, but only to someone who
opened the page. A certificate that ends unnoticed takes a website down. The
owner asked for alerts before the first release, by Telegram and e-mail.

Alerts are Rootwell's second kind of outgoing connection, after Website
check (ADR 0090). They carry certificate names, where they are used and who
looks after them, to a server the person names, or to Telegram.

## Decision

**When.** An alert goes out 30, 14 and 7 days before a certificate ends, and
on the day it ends. Each step is sent once per certificate. Only the nearest
step is sent: a certificate added with five days left gets the 7-day alert,
not three. A certificate whose end date moves starts again. Replaced
certificates (ADR 0091) get none. Everything due goes in one message, soonest
first, with where each one is used, its owner and a link to its sheet on the
first name Rootwell answers to that is not loopback.

**How often.** `rootwelld serve` looks a minute after it starts and then every
hour. A step counts as sent when at least one channel delivered it; when none
did, the next hour tries again, and the page's log says why each channel
failed. The last 20 sends, tests included, are kept for the page.

**Telegram.** A bot the person makes with @BotFather, and one chat, group or
channel. Rootwell connects only to `api.telegram.org:443`, over TLS verified
against the public roots, with no proxy from the environment, no redirects
and a 30-second limit. The token goes in the URL path, as Telegram's API
wants, so no error, log or page ever repeats the URL or Telegram's own words:
four fixed sentences say what went wrong. Telegram, as a service, sees each
message's text.

**E-mail.** The person's own mail server, always over TLS: TLS from the first
byte (usually port 465) or STARTTLS (usually 587). A server that does not
offer STARTTLS is refused before anything is sent. The server's certificate
must verify for its name against the public roots or a certificate authority
saved in Certificates, as in Website check, so a company mail server with its
own authority works. Signing in uses PLAIN over that TLS only. The server's
name or address must pass the same address rule as Website check
(`internal/netpolicy`, moved out of `websiteprobe` for both): private
networks yes; loopback, link-local and metadata, multicast, documentation and
reserved ranges never, for the name and for every address it resolves to. The
sender and recipients are bare addresses, up to ten; no header can be added
through a setting or a certificate's name, since lines are checked and the
subject is encoded. Mail server text is never shown.

**Settings and secrets.** The settings are one sealed vault record; the mail
password and the bot token are another, opened only to send. The page never
gets a secret back: it shows that one is saved, and keeping it is asked for
by leaving its field empty. Saving a channel or turning one off needs a fresh
code (C111), so a stolen session can neither send alerts elsewhere nor
silence them. Turning a channel off forgets its secret. A test message needs
a signed-in session only, one at a time and at most one every ten seconds.

**The page.** Alerts sits in the menu beside Account and Installation. It
reaches `/api/alerts` only and reads no file.

## Consequences

- A certificate's name, places and owner leave the server in alerts: to the
  mail server named, and through Telegram.
- A live host compromise reveals the mail password and the bot token, as it
  reveals keys (C107). A stolen database or backup does not.
- Alerts are as punctual as the hour: one may come up to an hour after a
  step is reached, and a host that is off sends nothing until it is back.
- Not built: webhooks, alerts about failed renewals (there is no automatic
  renewal yet), and plain SMTP without TLS.

## Evidence

`TestEachStepIsSentOnceAndOnlyTheNearest`,
`TestANewEndDateStartsAgainAndTheRecordStaysSmall`, `TestDueIsSoonestFirst`,
`TestTelegramSendsOneMessageToTheChat`,
`TestTelegramRefusalsAreNamedWithoutTheToken`,
`TestTelegramSettingsAreCheckedBeforeSending`,
`TestTelegramConnectsOnlyToTelegram`, `TestEmailGoesOnlyOverVerifiedTLS`,
`TestEmailRefusesWhatItCannotVerify`, `TestEmailReachesOnlyAllowedAddresses`,
`TestEmailSettingsAreCheckedBeforeConnecting`,
`TestTheSecretsAreKeptApartAndNeverShown`, `TestAlertRecordsAreReadStrictly`,
`TestAlertsGoOutOnceAndRetryWhenNothingArrived`, `TestNoChannelSendsNothing`,
`TestLinuxAlertSettingsNeedAFreshCodeAndNeverShowSecrets`,
`TestLinuxAlertInputIsRefused`,
`TestLinuxATestNeedsAChannelAndWaitsBetweenTries`,
`TestPagesSeparateFileAndNetworkCapabilities`,
`TestWorkbenchHasNoNetworkOrProcessImports` and `scripts/test-alerts.mjs`.
