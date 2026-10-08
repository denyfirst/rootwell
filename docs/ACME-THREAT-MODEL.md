# ACME staged implementation boundary

Date: 2026-10-08. Single operator, existing loopback access gate. Porch is
excluded. Offline Workbench acquires no CA network capability.

## First increment: setup check, not issuance

Automation accepts 1–32 unique ASCII DNS identifiers and a manual DNS-01 or
HTTP-01 choice for one fixed Let's Encrypt staging provider. It performs only
bounded syntactic checks on the operator's own daemon. No DNS lookup, HTTP
request, account/key creation, terms acceptance, secret input, persistence,
challenge provisioning, renewal or deployment. Ready login, exact host/origin,
custom request header, POST-only strict JSON and no-store apply. Preview grants
no authority; a valid-looking name does not prove ownership, eligibility,
reachability, CAA permission or CA acceptance. Unicode and IP identifiers are
outside this initial policy. Wildcards require DNS-01.

Assets: private service names, future account key and account URL, certificate
keys/CSRs, DNS credentials, authorizations, orders, challenge values, instance
identity, backups and future explicit authority. Trust browser/daemon/host;
untrusted inputs include names, JSON, responses, CA-provided URLs, clocks,
storage images and stale sessions. Runtime strings/host compromise remain.

## Second increment: optional staging directory connection

ADR 0050 adds a separate explicit-consent, ready-session connection check.
Only one GET to the fixed staging directory; no names, keys, account or terms
decision. IP/DNS visibility is disclosed. System TLS trust, original SNI,
public-only bounded DNS with numeric dial pinning, no proxies/redirect/retry,
8-second deadline, 8 KiB headers, 32 KiB strict JSON, validated known endpoint
URLs, one in-flight operation and 30-second RAM cooldown. Cancellation and live
session checks surround network boundaries and result publication; already-sent
bytes cannot be recalled. Only a fixed reachability summary is returned; no
CA error/metadata reflection, filesystem write or issuance authority. Unknown
bounded extension metadata is ignored and never followed. Setup remains offline.
Tests use an isolated synthetic TLS CA, not the public staging service.
Live provider access is Linux/Docker-only; native platform verification may
perform additional OS-managed certificate retrievals, so Windows/macOS refuses
this capability before DNS. Local syntax/Workbench functionality is unchanged.

## Third increment: local account-key preparation, not registration

ADR 0051 saves one newly generated P-256 staging account key in a distinct
purpose-separated encrypted field of the complete image. Explicit local status
and preparation, fresh password, shared attempt/crypto budgets, displayed
generation, exact access revision and live permission under the writer lock.
Atomic history, certificate mutation preservation, full backup/restore and
offline password recovery apply. No key in browser/history/logs; only public
identity and prepared time. Native Windows/macOS refuses this custody.
No new outbound capability, CA registration, terms decision, email/domain,
key import/export/replacement or issuance. An uncertain save is reconciled by
refreshing the existing key's status, not generating/replacing it. Old binaries
refuse the new manifest field. Manual backups and complete-image rollback risks
remain. Preparation grants no authority to the directory-only connector.

## Sequence and gates

1. Directory-only dependency/transport increment implemented in ADR 0050;
   broader ACME/Pebble protocol testing remains future work. Explicit ready-session opt-in
   must show destination and data sent. No production/custom URL fallback.
   Validate HTTPS URL/host/path/port, every directory/order/authorization/Link
   endpoint and redirect. Reject private/loopback/link-local/metadata addresses,
   DNS rebinding, env proxies and cross-origin redirects; enforce dial-time
   address checks, TLS verification, response/time/concurrency/retry limits.
   Test all redirects/SSRF/timeout/oversize cases; no real CA in default CI.
2. Account: separate staging/production identity; fresh instance authentication
   and explicit terms decision; purpose-separated encrypted signer, installation
   binding, exact generation and atomic account/history/full backup/restore.
   No account key/export/credential in logs, browser output, URLs or storage.
   Registration uncertainty must retain the same key and reconcile rather than
   blindly register again. Profile/account/domain authority is revalidated at
   each operation; no unlock lifetime extension. No EAB until separately reviewed.
3. Manual DNS-01 first: one bounded order, domain-bound challenge instruction,
   explicit user acknowledgement after provisioning; no fabricated TXT token
   during setup. Wildcard/apex can require separate values at one TXT name.
   Do not fetch arbitrary user endpoints or change DNS through full-account
   credentials. Provider tokens later need minimum zone/record scope and
   encrypted custody with explicit cleanup ownership and failure reporting.
   HTTP-01 later needs separately scoped webroot/listener permission, not a
   remote shell or the loopback access-gate listener made public.
4. Issue: new signer + signed exact-SAN CSR; reconcile returned non-CA
   certificate, exact public key/names, policy/time and issuer path using
   independently selected trust. Staging roots stay test-only, never system
   trusted. Save complete material atomically to Certificates; no overwrite,
   no duplicate new order on uncertain completion, no claimed deployment.
5. Manual renewal before scheduler: new issuance, preserved prior usable
   certificate until explicit replacement, bounded retries/backoff/jitter,
   Retry-After/CA rate limits, clock errors, pause/unlock and visible failures.
   Manual DNS is not unattended renewal. ARI/renewal rules need current review;
   do not hard-code assumed validity or renew every fixed number of days.
6. Deployment is separate: exact target/action authority, staging/validation,
   atomic replacement, reload, independent live verification and rollback.
   No Porch changes or shell/SSH capability in this increment. Production
   enrollment/release requires independent audit and explicit decisions.

## Evidence required

Success, malformed/refusal, secret-free errors, no unapproved outbound/storage capability,
origin/setup/session/host, late/hidden/source-changed UI and two-way sabotage.
Every future increment must add its own protocol/crypto/permission/recovery
tests before enabling its capability. Green development CI is not audit.

Sources checked 2026-10-08: [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555.html),
[Let's Encrypt staging](https://letsencrypt.org/docs/staging-environment/) and
[challenge types](https://letsencrypt.org/docs/challenge-types/).
