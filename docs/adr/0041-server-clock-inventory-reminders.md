# ADR 0041 — Server-clock inventory reminders without outbound notifications

**Status:** accepted for development, 2026-10-06. Extends ADR 0026; not an
independent audit or a production deployment claim.

## Decision

Use the existing authenticated Linux `/api/inventory` read boundary. Once the
complete encrypted image and access revision have authenticated, derive all
expiry observations from one UTC, whole-second `gate.now()` instant. Responses
include that instant, `clock_source: server-clock`, a 60-second refresh hint,
and each record's date-only status and rounded-up positive days remaining.
NotAfter equality is expired; an empty/reversed/noncanonical range is invalid.
Unix seconds, not `time.Duration`, avoid saturation on dates up to year 9999.
The observation does not mutate the image, generation, or import provenance.
No browser clock is used to decide certificate expiry. A server clock is not
authenticated time and can also be wrong.

The page gives one quiet, in-app summary and an action sentence on each card.
7/14/30/90-day reminder windows are ephemeral local view choices (default 30).
Expired, invalid and not-yet-valid records always need attention. There is no
mute/acknowledgment that can silently hide these records. Search, thresholds
and filters do not leave the browser or change saved records. Technical fields
and destructive controls remain inside collapsed details; Inventory still
offers no certificate/metadata download.

While visible, the page checks its own installation at most once a minute
after a successful load, using the existing ready, revision-bound session;
this does not extend the fixed session lifetime. No automatic refresh
interrupts expanded record details, a correction/deletion panel or a pending write. Unchecking the
option pauses periodic reads. Results aged 120 seconds show an explicit stale
warning, including when editing or periodic refresh is disabled. The UI uses
both elapsed monotonic time and device-clock movement to detect stale views;
backwards time is stale, not renewed freshness. Server/device differences over
five minutes are called out, not resolved by changing either clock.

GET is abortable and has a 10-second deadline and a streaming 4 MiB UTF-8 JSON
response cap. Every record and its expiry observation must agree with the
single server instant before anything is displayed. The page refuses missing,
inconsistent, oversized or malformed responses as a whole, and never echoes
malformed JSON. Read errors clear cards and pause automatic retry until a
manual refresh or visible-page return. Hidden/pagehide/BFCache views clear
metadata, abort the read, discard late results and stop the timer; returning
re-reads through authentication. A submitted write can still finish after the
page is hidden; its outcome must be reloaded, never inferred as cancelled.

There is no new background daemon scheduler, durable alert state, OS
notification permission, email, webhook, DNS request, endpoint scan, renewal,
revocation or private-key custody. A closed page does not deliver reminders.
One reminder may cover several declared locations; these remain manual notes,
not proof of live deployment. Offline Workbench capability is unchanged and
Porch is untouched. Public metadata can expose internal names, so ready-session,
same-origin/header, no-store, encryption and text-node rendering gates remain.
The read-only Windows visual fixture is not authenticated Linux storage.

## Limitations and evidence

Host/browser compromise, false server time and replay of an older complete
encrypted snapshot remain outside this boundary. The 4 MiB page cap can refuse
an otherwise valid but unusually large metadata catalog; no partial results
are shown. Persisted reminder preferences, offline notifications and
Workbench handoff are separate increments, not implicitly implemented here.

Evidence: `TestObserveExpiryExactBoundariesAndNoTrust`,
`TestObserveExpiryRejectsMalformedAndHandlesLongDates`,
`TestInventoryMonitoringBindsOneServerClockAndNeverMutates`, the Linux
authenticated API test (unchanged image across repeated monitoring reads),
`scripts/test-rootwelld-inventory.mjs` (threshold boundaries, wrong clocks,
timers, stale/failure/visibility/BFCache, exact response cap, late results),
and `scripts/test-inventory-demo.mjs`. Both positive and refusal assertions are
deliberately sabotaged and restored before merge. Existing cross-platform,
race, linter, CodeQL and signature gates still apply.
