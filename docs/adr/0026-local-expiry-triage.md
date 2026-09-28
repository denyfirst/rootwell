# ADR 0026 — Local expiry triage without automation

**Status:** accepted, 2026-09-28.

## Decision

The authenticated inventory page offers priority ordering, expiry and
missing-note filters, and text search over an already-loaded public-metadata
response. These are browser-memory operations. No filter term is sent to the
server or retained in browser storage. Counts cover the whole response while
the list states how many records remain visible.

The displayed as-of timestamp comes from the browser clock, which Rootwell
does not authenticate. `NotAfter` is exclusive: equality is expired. The page
offers human next-action guidance, never a renewal, deployment, trust, or
alert verdict. Operators must check device time, actual deployment, issuer,
and owner before acting. An incorrect or compromised clock can misprioritize
records; this view is not a monitoring service.

## Rejected alternatives

Server-triggered notifications or automated renewal would require a scheduler,
network policy, credentials, and new failure/recovery boundaries. They are
not implied by a read-only public inventory. Persisting search terms would
unnecessarily disclose internal names. A filter must not alter the encrypted
record or decide retention.
