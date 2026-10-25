# ADR 0072 — Bounded offline ARI and renewal-time policy

Date: 2026-10-26. Development component, no new runtime authority. Porch excluded.

Continue the operator-approved automation wave without introducing a scheduler
before its untrusted time/protocol policy can be tested independently. The
existing ready-session limit remains: no disk password, new host unlock key or
extension beyond twelve hours. No real CA/DNS calls or customer input in tests.

## Policy

`internal/renewalpolicy` has no storage, HTTP, session, signer or credentials.
It parses at most 8 KiB UTF-8 ARI JSON, checks unique keys through depth eight
and a 256-value budget, exact required window fields and strict RFC3339 wire
grammar, normalized UTC instants in 2020–2100 and end strictly after start.
Bounded unknown extension metadata is ignored, never followed/reflected.
Optional explanation URLs are intentionally not surfaced by this component:
no caller should acquire an arbitrary navigation/network destination from it.
This narrower choice sacrifices optional explanatory UX, not renewal timing.

Exactly one valid Retry-After sets a checking interval clamped to one minute
through one day. This is ARI's special read-check policy, **not** the DNS
mutation backoff policy; the latter is unchanged. Missing/invalid ARI hints
refuse trusted information, and a separate error-delay calculation gives six
hours for long-term errors/after six temporary failures. Earlier temporary
failures use capped exponential delays. No retry loop or counter reset exists.
Future callers must persist the count/wait before every authorized provider read.

RFC9773 certificate IDs come from bounded X.509 DER, a non-CA certificate's
AKI keyIdentifier and positive serial. Mature standard-library ASN.1 encoding
retains the INTEGER's required leading zero; no custom ASN.1/crypto encoder.
This proves neither issuer trust nor account/domain ownership.

Renewal time is selected uniformly with crypto/rand within the half-open ARI
window, or a local fallback window ending at two thirds of actual lifetime
(halfway for lifetimes under ten days), spreading work earlier by 1/24 lifetime.
Past selections mean now, but existing CA/provider error backoff always wins.
Expired/not-yet-valid certificates, stale/future/invalid ARI, windows ending
after certificate expiry, backoff beyond expiry and entropy failure refuse
without a partial selection. Subsecond lifetimes refuse. No fixed 90d lifetime.
Future custody must authenticate the exact certificate/source and durably save
one choice before scheduling; never reroll on status reads/restarts/restores.

## Boundary and remaining work

Parsed information is explicitly **untrusted**, not a CA observation. No exported
live connector, API, UI control, encrypted job field, scheduler, terms agreement,
rate-limit exemption, replacement/deployment or production trust is added.
Architecture tests deny runtime imports/extra capabilities until a separate
scoped custody/transport review. Next: pinned staging ARI read, exact certificate
binding and persisted observation/selection/error waits; then ready-session
opt-in worker/pause/visible failure and UI. Existing DNS uncertainty and finite
history remain stop conditions, not reset/abandonment opportunities.

Primary sources checked 2026-10-26:
[RFC 9773](https://www.rfc-editor.org/rfc/rfc9773.html) sections 4.1–4.3,
[Let's Encrypt integration guide](https://letsencrypt.org/docs/integration-guide/#when-to-renew).
The component is not a complete RFC9773 client: directory discovery, HTTP
semantics, authenticated source, durable scheduling and `replaces` are not wired.

## Evidence

Positive offset/fraction/date/serial-padding/random endpoints, long/short
fallback, urgent-past ARI with backoff, stale/expired/oversize/duplicate/nested/
case/grammar/header/entropy refusal and constant errors. Generated synthetic
certificate ID matches the RFC's public example values, including leading zero.
Actual compiling two-way sabotage: omitting backoff application failed the urgent
ARI test; inverting the window comparison failed valid information acceptance.
Guards restored, ten shuffled package repetitions pass. Initial fuzz smoke:
490366 ARI JSON, 1515995 certificate ID and 1874451 renewal-selection executions, 15s each,
no finding; this is not exhaustive or interoperability evidence.
Full pinned local gates, Linux race/all final-head CI and separate maintainer
self-review remain mandatory before merge; independent audit before release.
