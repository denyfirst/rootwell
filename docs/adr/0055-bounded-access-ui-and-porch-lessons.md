# ADR 0055 — Bounded access UI and read-only Porch lessons

Date: 2026-10-10. Single-operator development; independent release audit remains.

The operator explicitly authorized reading Porch without changing it. A
read-only comparison covered its README/self-hosting/scope/engineering/release
documentation, workspace/domain/access templates, session client, domain proof
boundary, authoritative DNS implementation and representative tests. This was
not an exhaustive line-by-line audit or live browser/network test. No Porch
file, configuration, branch, dependency, signing material or data was changed.

## Adopted increment

Porch's session client uses an explicit fifteen-second request deadline and
does not claim sign-out without a positive response. Rootwell already refused
unconfirmed sign-out, but had no client deadline: a stalled header or login
body could leave its controls locked. Adopt the reliability principle, not
the other product's authentication/storage implementation.

The Rootwell access client now has one fifteen-second deadline across fetch
and the complete login body, an 8 KiB streaming cap, fatal UTF-8 decoding and
the exact one-field setup/ready response contract. Password changes/sign-out
require the existing 204 response, login requires 200. One operation at a time;
disable editing and clear entered fields after capturing the explicit request.
Refusal, malformed/oversized/broken bodies and transport/deadline failures
release controls, clear fields and never echo server/error data or redirect.
Hidden/pagehide events clear fields, abort pending work and reject late results,
even in tests where the synthetic fetch deliberately ignores cancellation.

A timed-out write can already have committed, or an unconfirmed login can
already have set a cookie. Do not automatically retry, claim rollback/revocation,
or show false success. Tell the operator to refresh/check the current state;
uncertain password change must not say the old password still works.
Cancellation cannot recall sent bytes, and Go/JavaScript/browser memory erasure
is not guaranteed. A compromised browser/host/same-origin script is not solved.

No server authentication, password policy, initial setup, access revision,
cookie, recovery, key custody, endpoint, network destination or session lifetime
changes. No password logging is adopted. Original ACME work-in-progress is
preserved in its separate checkout, not shipped by this increment.

## Lessons for the subsequent manual DNS increment

Use a simple ordered explanation and Type / Name / Value presentation, with
optional DNS-panel help, instead of putting every technical detail up front.
Hide unusable controls; distinguish DNS lookup failure from a missing value.
Keep warnings readable in both themes and do not rely on colour alone.

Do not copy Porch's proof semantics: its installation-derived
`_porch-challenge` authorizes scans, not ACME issuance. ACME instructions must
come from the validated CA order and correct account key; local acknowledgement
is not the CA's domain-validation verdict. Never infer one TXT value covers a
wildcard/apex pair. Domain proof also grants no DNS-provider API authority.
Manual DNS needs no provider credentials; automated renewal remains a separate
limited-scope connector decision.

## Evidence

`scripts/test-rootwelld-auth.mjs` exercises confirmed setup/ready login,
setup/account password change, sign-out; all three action refusal paths;
status/JSON/type/UTF-8/duplicate/oversize/broken/stalled-body cases; header and
body deadlines; hidden/pagehide and late result refusal; overlap prevention,
post-timeout reuse, credential clearing and fixed diagnostic text.
The same CI job already executes it. VM tests are not live browser QA.
Two-direction sabotage and final development gates are recorded in the PR;
these do not constitute independent audit.
