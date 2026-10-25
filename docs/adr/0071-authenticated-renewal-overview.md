# ADR 0071 — One-image renewal readiness and honest stop conditions

Date: 2026-10-26. Development, single operator, Linux loopback. Porch excluded.

The operator requested consecutive automation increments and chose the existing
ready-session boundary: logout/lock/expiry/restart stops work, with no new
independent unlock credential or extension of the twelve-hour lifetime.

Before a scheduler can choose work, expose its stop conditions without asking
the operator to infer them from several technical panels. One private writer
lock reads one complete authenticated image and checks access revision before
and after. No stitched generations, outbound call, write, password acquisition,
retention change or retry reset. Existing ready/origin/header/shared crypto
budget and native-platform refusal apply. Recheck live session/cancellation,
backwards time and ten-second age before publication. No partial output on error.

The summary reports unreserved activity/generation/byte headroom, separate
reserved transitions, archive/record slots, pending request/closure state and
DNS unknown/wait/cleanup/terminal maintenance. Headroom is informational, never
an admission promise. Writers retain their existing exact reservations. No
history/ownership abandonment, silent pruning or unlimited recovery claim.
Terminal DNS uncertainty remains saved and blocks progress; this overview does
not make it repairable. A scheduler must stop and surface it, never bypass it.

Only an authenticated saved staging completion with its matched private key
gets a local two-thirds-of-actual-lifetime review reminder. Other certificates
remain manual. Retained originals with a completed successor are superseded,
including when the successor was later deleted. Dates are not CA suggestions,
renewal consent, issuer trust, deployment, replacement or a rate-limit exemption.
Public rows contain only identity/name/expiry/review/state, not notes, DER, key,
TXT, provider ID/owner marker, token or internal URL. No manifest change.

The existing Automation page gains one optional-read overview, plain next-step
guidance and collapsed technical headroom/certificate details. Strict bounded
response, no-store, ten-second total deadline, one-minute invalidation, hidden/
pagehide/source-change cancellation and late-result refusal. No automatic fetch
or polling. The read-only Windows fixture must identify all data as synthetic.

ARI remains a separate protocol/persistence increment. Sources checked for its
design: [RFC 9773](https://www.rfc-editor.org/rfc/rfc9773.html), especially
4.2–4.3: CA windows, randomized choice, Retry-After and error backoff must not be
confused with this local reminder. No ARI-compliance or live interoperability
claim is made here. Production profile/terms/domain actions and independent
release audit remain outstanding.

Acceptance: whole-image/refusal/no-mutation/secret/clock/capacity/lineage tests;
Linux locked revision/full password+code restore/permissions and API origin/
session/shared budget; bounded UI stale/hidden/late/malformed tests; actual
compiling two-way sabotage, pinned local checks, all exact-head CI and separate
maintainer adversarial self-review. Green CI is not an independent audit.

## Local adversarial evidence

Actual compiling two-way sabotage: changing blocked/exhausted DNS maintenance
to “none” failed both the complete recovery/status test and the blocked-clock
table. Inverting the review-time comparison failed the legitimate waiting
certificate test. Guards restored and positive suite repeated. The architecture
gate initially rejected the new handler and historical-scope reader: authorize
only net/http in this loopback handler, keep historical scopes inside renewal's
existing validator, and return only public superseded identities to the summary.
No broad network/historical-scope exception. Pinned gosec found an int-to-uint
conversion without an explicit local range proof; require 0–256 reserved slots
before conversion rather than suppressing the finding. Fuzz smoke ran 907,676
executions/15 seconds with no finding (not exhaustive assurance).
