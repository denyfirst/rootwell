# ADR 0081 — Fixed environments and independent production receipt trust

Date: 2026-10-29. Foundation for the authorised production stage; production
enrolment/custody/UI remains closed until the next integration gate is complete.

The current account/order/DNS/renewal flow is explicitly staging-only. Replacing
its hostname or relabelling an existing completion would mix account identity,
trust roots, saved ownership, waits and test provenance. Do not enable production
through a process-global mutable mode, arbitrary directory URL, shared account
or generic uploaded root configuration.

Add two immutable `acmeprofile.Profile` constants: `Staging` and `Production`.
Their identifiers, origin/host/directory and future custody namespaces are fixed.
Zero/unknown values return no endpoint/namespace and never select a default.
Only exact provider identifiers parse. Account/order/resource URL validation
keeps account binding and bounded case-sensitive ASCII paths, without URL
normalisation, aliases, default ports, redirects, query/fragment/credentials or
cross-environment acceptance. This is syntax, not order ownership or network
authority. Legacy `acmeorder` wrappers delegate explicitly to `Staging`; every
existing route, key, account, backup, origin and network destination stays in
that environment. The catalog has no network, filesystem, crypto or state.

Add separate offline `acmecertificate.CheckProduction`. It uses only independently
embedded/pinned self-signed ISRG Root X1/X2, never the four staging roots or host
trust. The existing exact key/CSR/SAN/usage/expiry and bounded whole-chain checks
apply. Only a successful checked receipt yields `TestOnly: false`; refusal is a
fixed production error with zero partial evidence. Response-supplied, changed,
reordered, duplicate, substituted or staging trust fails. No AIA/OCSP/CRL request
or ambient store modification. A private synthetic test seam proves positive
path binding; both fixed entries must still reject its unpinned root.

Architecture tests restrict catalog imports/exports and keep every production
trust symbol inside this fixed offline boundary. No runtime consumer or route
can select production yet. Official assets were fetched over HTTPS with no
redirects and independently reparsed/self-checked; provenance and exact DER
fingerprints are in `internal/acmecertificate/roots.md`. This is source review,
not an independent out-of-band trust ceremony or live CA interoperability test.

Next required integration: separate authenticated ACME environment namespaces
for accounts, active/closed orders, independent prepared keys/completions,
DNS ownership/configuration, ARI choices and provider waits, with one shared
Certificates library and existing global image/history/generation limits.
Explicit fresh-password provider selection must never overwrite/migrate a test
account or uncertain DNS scope; existing pending work must first be reconciled
and owned cleanup completed. Profile identity must be authenticated and repeated
at every reader/writer/lease/callback/backup/restore boundary. A completed test
pair cannot be relabelled production or become a production renewal source.
The original-session worker must freeze the environment along with source and
DNS configuration; no profile change can extend or transfer its grant.

Only after those custody, connector and UI gates pass may the real fixed
production endpoint be called. Terms and account creation remain the operator's
explicit decision. Dedicated-domain/scoped-token live staging and production
tests, CA rate/wait handling and cleanup are separate evidence, not synthetic
green tests. Install/upgrade/full restore and independent release audit remain
the fourth stage. No Porch repository changes.

Primary sources, checked 2026-10-29:

- [Staging environment and separate accounts](https://letsencrypt.org/docs/staging-environment/).
- [Production chains and self-signed root assets](https://letsencrypt.org/certificates/).
- [Fixed production/staging API endpoints](https://letsencrypt.org/docs/acme-protocol-updates/).

Local evidence: complete native shuffled suite, targeted receipt/profile/order/
connector/architecture tests, Linux cross-vet/staticcheck/gosec, tidy/checksum/
build/actionlint and reachable-vulnerability checks passed. The URL parser ran
2,695,726 fuzz executions. Neutralising the root pin check accepted a reordered
bundle and failed the refusal test; inverting receipt error handling refused
the valid synthetic path and failed the success test. Both compiling sabotages
were restored and the affected suites passed again. The public root asset has
explicit narrow Git and Docker ignore exceptions so clean checkouts and
container build contexts include both pins. No wildcard PEM exception is added.

Operator update (2026-11-02): no dedicated test domain or restricted Cloudflare
token is available. Continue local/synthetic development; live CA/DNS account,
terms, issuance and cleanup evidence is pending. These tests are not a live
interoperability claim. Final-head CI and maintainer review remain merge gates;
independent release audit is separate.
