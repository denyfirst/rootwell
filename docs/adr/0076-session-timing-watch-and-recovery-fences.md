# ADR 0076 — Session-bound timing watch and recovery fences

Date: 2026-10-27. Single-operator Linux development. Porch is excluded.

## Three connected steps

1. One exact-image local recovery preflight. The saved source must still be an
   authenticated Rootwell staging completion with retained matching material.
   Pending timing, provider block, unknown/maintenance/owned DNS cleanup, an
   active/unknown request, unavailable account or inadequate unreserved
   event/generation/byte headroom prevents enabling. Public reasons link to
   existing local retirement, same-request read, read-only DNS recovery or owned
   cleanup controls. No counter reset, operator verdict, unknown-scope abandonment,
   history pruning or write replay. Terminal blocked/exhausted scopes still need
   separately reviewed maintenance; this is admission/guidance, not general repair.
2. An explicit session-scoped **timing-only** worker. Start requires fresh
   Rootwell authentication, exact source/generation and separate literal
   `session-timing-only` consent. One-check consent cannot grant a watch. One job
   per daemon; owner is the original session hash, revision and unchanged expiry.
   No retained password, data key, installation key, signer, token, URI or
   independent unlock. Each attempt transiently borrows a live session key and
   clears that copy. No automatic startup, restart/restore resume, migration to
   another login or lifetime extension. Logout/lock/revision/expiry/shutdown cancel.
3. Existing Automation renewal card and selected certificate. Collapsed optional
   local preflight/status, separate password/consent, Waiting/Checking/Paused
   reasons and Stop. Stop uses ready-session authority and exact job ID, not
   another password or crypto slot. A stale stop cannot revoke a newly granted
   job. No second picker/menu, raw provider text or certificate-renewed message.

## Runtime and failure boundaries

Job authority is memory only. Existing encrypted intent/result, chosen time,
counter and provider wait stay durable and retain full restore semantics.
Maximum twelve provider checks per explicit job, at least five elapsed minutes
apart, respecting longer persisted waits. Monotonic runtime time protects spacing
and a twelve-hour ceiling; original session expiry retains its monotonic component.
Busy ticks never shorten waits. Local metadata is revalidated each minute, even
while a future provider read waits. Browser is not needed after separate consent.

Only fixed staging RenewalInformation through existing private writer/intent/
one-use lease may contact a provider. Exact generation is never auto-adopted after
an unrelated write. Shared crypto/provider budgets apply. Confirmed error, lost/
malformed response, changed storage, ended source or unsafe recovery pauses the
job. No automatic error retry chain or pending-intent retirement. Fresh manual
permission cannot erase existing waits/counters. Existing reserved outcome slot/
8KiB is preserved; preflight never replaces exact writer admission.

Stop is cancellation, not rollback: sent public GET bytes cannot be recalled.
In-flight cancellation can leave pending intent; refresh readiness and explicitly
finish locally, retaining wait/count. A clearly cancelled/failed start publication
pauses its job; ambiguous delivery requires status, not blind enable-again.
No private key/password/DNS credential is sent to the CA.

Exact bounded UTF-8/duplicate-free API shapes, fixed scope/provider, origin/host/
fetch checks, five-second body and thirty-second response bounds. Attempts use
25-second context and existing shorter protocol deadline. Status/Stop grant no
outbound authority. Only fixed public job/preflight metadata; no notes/provider
record IDs/internal URI/raw text. Browser: 25-second/16KiB streamed fatal UTF-8,
60-second stale, clock/source/hidden/late rejection and secret clearing. Hiding
the page clears UI authority but does NOT withdraw an already granted watch;
Stop/logout/lock/session end do that. This is explicitly disclosed.

## Evidence and remaining scope

Native policy/parser/owner/spacing/constructor/UI tests, actual Linux source/
intent/stop/logout/shutdown/pending recovery, architecture fencing, two-way
sabotage, request fuzz and final-head CI are required. Fake TLS and read-only
browser examples do not prove real interoperability. Demo password/consent/
Enable/Stop disabled; no actual background job or CA/DNS connection there.

Actual compiling two-way sabotage: disabling the pending recovery guard admitted
an interrupted source and failed the intended refusal; inverting the same guard
refused the legitimate exact source and failed acceptance. Both were restored,
then the full targeted policy/constructor/parser/architecture/UI suite passed.
Review also caught a busy tick shortening the five-minute gap and an old
preflight hiding an immediately paused start. Preserve the later wait, add a
monotonic spacing floor, and render the current job reason after Start; regression
tests cover both. Linux execution and every final-head check remain merge gates,
not inferred from native Windows tests or cross-vet.

No DNS write, account/order creation, signing, issuance, replacement, deployment,
production/custom CA, unattended unlock or automatic full renewal. The wider
blocked/indefinite DNS maintenance/history-retention milestone remains open;
timing-only automation cannot bypass it. Future mutation pipelines need their
own authority/recovery design and independent release audit. Host/runtime
compromise, old-image rollback and guaranteed heap erasure remain outside scope.
