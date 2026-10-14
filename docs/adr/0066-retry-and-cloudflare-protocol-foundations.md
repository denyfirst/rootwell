# ADR 0066 — Retry policy and bounded Cloudflare TXT protocol foundations

Date: 2026-10-14. Development component gate, not enabled automation.
The user requested both retry rules and DNS automation and explicitly chose
Cloudflare as the first provider. Porch remains excluded.

## Decision

Build and test the common retry policy and one exact Cloudflare TXT protocol
before enabling new secret storage or browser mutation. Both are executable
components, not a completed user-facing automation feature. Current V8 UI/API,
30-second RAM CA cooldown, encrypted inventory/backup format and CA replay
rules are unchanged. No Cloudflare token/credentials or live DNS were used.

Retry policy reserves a count before I/O, at most six attempts, exponential
30/60/120/240/480/960-second minimums plus caller-chosen 0–30-second jitter.
Canonical UTC state can be serialized for future encrypted custody. Fractional
clock results round UP; backwards/invalid clocks and exhausted budgets refuse.
Single bounded Retry-After accepts delta seconds or canonical IMF-fixdate,
retains longer waits, and rejects malformed/duplicate/over-seven-day hints,
never clamps them to an earlier retry. Error text contains no provider data.
This policy cannot authorize reissuing orders/challenges/finalize. Its consumer
must persist the attempt before sending and retain prior intent on errors.
It is not yet connected to a scheduler, saved CA operations or a retry UI.

Cloudflare protocol is unexported and architecture-blocked outside its file.
It accepts only one exact DNS-01 TXT scope at a time: fixed zone ID/name,
canonical challenge name/value, bounded bearer token and one preallocated
128-bit ownership marker. The trusted future custody layer must generate and
authenticate the marker, select CA-derived records and provide durable commit.
No Global API-key/email scheme, arbitrary URL/provider/zone discovery, A/AAAA,
overwrite, PATCH/PUT, certificate issuance or trust authority.

Reuse fixed-host Linux transport policy for exactly api.cloudflare.com and the
existing staging host: system TLS/SNI, all-public bounded DNS, numeric pinning,
no proxy/compression/redirect/retry or shared connections. Target is internal,
never an API input; other hosts refuse before DNS. Each component invocation
has a 20-second deadline, three requests maximum, 8 KiB response headers and
32 KiB strict UTF-8/unique JSON. Known field aliases/nulls, missing pagination,
foreign values, ambiguous duplicates and incomplete result pages refuse.
Bounded extensions are ignored, never followed or reflected.

## Record workflow

- Read and confirm the exact active full zone before record operations.
- List the exact TXT name AND value; no broad export or pagination traversal.
- Existing foreign/pre-existing record is borrowed, NEVER cleanup-owned.
- New creation requires a successful durable creating checkpoint before POST.
  One exact TXT, TTL 60, non-proxied, ownership comment; no replace.
- An uncertain creating scope only lists. Exact owner marker can reconcile the
  same created record; no result/absence never falls back to POST.
- Cleanup first reads the exact previously owned ID and repeats type/name/value/
  marker/non-proxied checks, then commits deleting before a single DELETE.
  Changed/foreign/borrowed records never receive a delete intent.
- A bare 404 is NOT cleanup success: a complete filtered list must also lack
  the exact saved ID. Other matching records are left unchanged.
- 429/503 yield only a fixed retry hint, no body reflection or internal retry.

## Required next integration gates

1. Purpose-separated encrypted provider configuration and CA-order-bound DNS
   intent/record ownership/retry state, entire-image validation, exact generation,
   writer/revision/permit, fresh password, bounded secret inputs and full recovery.
2. One opaque exact-image DNS operation lease. Persist attempt and irreversible
   intent before I/O, final receipt recheck/atomic result; unknown creates remain
   reconciliation-only. Reserve history/capacity for owned-record cleanup; do not
   let expiry/local closure silently abandon ownership or release replay authority.
3. Simple UI in Automation: configure scoped token locally, explicitly add saved
   CA TXT records, read uncertain results, request CA verification separately and
   clean only owned records. Show borrowed/created/pending/cleanup-needed states,
   provider wait/exhausted/paused states. Manual DNS alternative stays available.
4. Actual Linux storage/API/full restore/race tests, browser QA, signed PR/all
   checks/self-review for each increment. No unattended unlock, production CA,
   live customer DNS, deployment or release without their separate authority.

## Residuals

Cloudflare zone-level DNS edit permission is broader than a single TXT record;
TXT-only restriction is enforced locally, NOT a provider permission guarantee.
Use only specific-zone DNS Edit and Zone Read token, never a Global API key;
token grants cannot be inferred from a successful zone read. No token storage
exists in this increment. Provider clocks/results and local host remain trusted
boundaries; encryption/memory cannot protect a compromised host.

Cloudflare documentation reviewed here offers no atomic content/marker compare-
and-delete precondition. A concurrent external editor may change an owned ID
between GET and DELETE. Exact ID avoids deleting a different record, but this
is NOT an atomic unchanged-content guarantee. Before live cleanup, the operator
must confirm exclusive ownership or separately resolve provider concurrency;
the UI must not promise protection against concurrent external edits. Filtered
absence is a momentary observation, not global DNS propagation or CA validation.

Protocol fixture success is not live Cloudflare interoperability. Provider
response profiles (full zones, canonical unquoted TXT, complete one-page filter)
are deliberately narrow. Rate-policy state is tested, but persistence/restore
and production jitter generation remain the next integration, not completed
claims. ARI RFC 9773 renewal-window fetching/selection is a separate capability;
no hard-coded certificate validity, new rate exemption or scheduler is implied.

## Evidence

Synthetic local TLS provider tests verify exact host/SNI, numeric dialing, ignored
proxy, exact single TXT create/delete, commit-before-write, preserved borrowed
record, GET-only lost-create reconciliation, changed/foreign/duplicate refusal,
bare-404 refusal, unsafe scope/token/DNS/commit/permit/cancellation, bounded
malformed/oversized JSON and fixed 429 hint without retry/error-body disclosure.
Retry tests cover success, early/backwards clock, budget exhaustion, longer
provider hint, malformed/duplicate headers, partial state and fractional/year
overflow. Two parser fuzz targets are in the scheduled inventory.

Actual compiling two-way sabotage: early Ready time failed intent/backoff;
rejecting valid State failed legitimate next attempt. Removing marker ownership
failed foreign-delete refusal (a foreign intent/DELETE was observed); requiring
proxied TXT failed legitimate creation. All sabotage was restored and relevant
suites pass. Final pinned gates and exact-head CI/self-review are recorded in
the PR; no audit or user-facing DNS automation completion is claimed.

Local three-second/two-worker fuzz samples passed: Retry-After 82,556 executions;
Cloudflare record preflight 16,188 executions. These samples are not exhaustive.
Full local shuffled Go/module/format/vet/build, pinned staticcheck/actionlint,
native and Linux gosec, Linux/Darwin cross-vet pass. No module change;
govulncheck reports zero reachable/imported-package findings and one unused
module-only residual. Actual Linux race and full UI/volume gates remain CI.

Sources reviewed: [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html),
[RFC 9773](https://www.rfc-editor.org/rfc/rfc9773.html),
[Cloudflare token scoping](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/),
[records list](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/),
[record creation](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/),
[record deletion](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/delete/)
and [zone details](https://developers.cloudflare.com/api/resources/zones/methods/get/).
