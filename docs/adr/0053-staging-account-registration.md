# ADR 0053 — Same-key staging registration and explicit reconciliation

Date: 2026-10-09. Development Linux/loopback only; independent release audit
is still required. Porch and the offline Workbench are unchanged.

## Decision and user flow

Reuse the locally prepared P-256 account key. A separate explicit connection
preview obtains the fixed staging directory and its current, validated Let's
Encrypt terms URL. It does not fetch the terms document or accept terms.
One RAM-only, five-minute, single-use preview binds the session, exact access
revision, image generation, public fingerprint and terms URL. Registration
requires that preview, fresh Rootwell authentication and explicit agreement.
Refetch the directory and refuse changed terms before nonce/signing/POST.
Never use a generic AcceptTOS callback. No contact email, domains, EAB, custom
provider, certificate order, account replacement or production fallback.

Before any registration network request, atomically persist an encrypted
`registration-pending` intent with the same key and accepted terms URL/time.
Reserve one history/generation slot for completion. Hold the private writer
lock throughout the bounded operation; concurrent operations refuse, not queue.
If an error, cancellation, crash or unconfirmed commit occurs, retain pending
state. No automatic retry/new key/new account. A separate fresh-password,
explicitly authorized reconciliation performs onlyReturnExisting using the
same key. A confirmed account is committed; a strict accountDoesNotExist
response returns to prepared state without changing the key. Another explicit
preview/terms decision is required before a new registration attempt.

## Protocol and transport

Use the pinned Go-team x/crypto/acme Register/GetReg implementations for JWS
and nonce handling. The existing public-only DNS, numeric dial pinning, original
SNI/system trust and Linux-only TLS verification boundary is reused.
The registration transport permits only one directory GET, one nonce HEAD
and one newAccount POST, to exact fixed endpoints, within ten seconds.
No proxy, redirects, retries, compression, cookie/auth header, account-resource
fetch, order/challenge/revoke/key-change/terms-document requests. Requests and
responses are bounded, strict UTF-8/unique-key JSON. Preflight library-produced
JWS for ES256, the exact stored public JWK, nonce, destination and mode-specific
payload, never broad signing authority. Sanitize CA responses before the
maintained parser; no CA error text or extension fields reach the browser/logs.

Account URLs/orders URLs must be canonical fixed-origin numeric account paths;
they remain encrypted, are not followed and do not become browser capabilities.
Explicitly selected terms links use only canonical https://letsencrypt.org
documents URLs, no query/credentials/escapes; no-referrer/noopener applies.
Exact URL matching is not a hash or legal interpretation of the terms document.
Reading the linked terms is the operator's responsibility. Registration of an
existing account is distinguished by reconciliation; no duplicate creation is
claimed. Account registration is not issuance readiness.

## Storage, authorization and residual risks

Every whole-image open authenticates the key and registration payload before
any metadata output. Account identity, accepted terms/time and registration
state are in the existing purpose-separated sealed payload. Public status
contains fixed states, the SPKI fingerprint and generation, not account URL,
signer, nonce or JWS. Atomic encrypted history, existing certificate preservation,
full snapshots, fresh-volume restore and offline password recovery apply.
Old binaries refuse new payload/history fields; do not downgrade after writes.
Manual backups must be repeated after transitions. Restoring an old intact
image can replay intent or lose registration metadata: no anti-rollback claim.

Ready exact-origin/fetch metadata, custom header, strict bounded POST shapes,
fresh password, shared KDF/attempt limits, one global in-flight provider operation
and 30-second RAM cooldown apply. Permission/context are rechecked under lock,
around network boundaries and immediately before each atomic commit/publication.
Already-sent requests cannot be recalled; aborted client work may have persisted.
Runtime/host compromise, reliable erasure, custom deployments and rollback remain
outside the guarantee. Default CI uses only an isolated synthetic TLS CA and
real library JWS verification, never the public CA or real operator credentials.

Sources reviewed: [pinned ACME package](https://pkg.go.dev/golang.org/x/crypto@v0.57.0/acme),
[RFC 8555 account management](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3),
[separate staging accounts](https://letsencrypt.org/docs/staging-environment/).

## Reproducible evidence and toolchain patch

The isolated CA validates the real maintained client's ES256 signature, stored
public identity, nonce, destination and exact mode-specific payload. Tests cover
changed terms before signing, foreign URLs, malformed/duplicate responses,
timeouts, no retries, late revocation, durable pending intent, reserved history,
same-key reconciliation, password recovery and snapshot restoration. Browser
VM tests exercise consent, reauthentication, invalid responses and lifecycle
cleanup; these are not live visual browser QA or a live public-CA test.

Deliberate two-direction sabotage was performed and restored: bypassing the
changed-terms check and rejecting valid directories; bypassing the exact storage
generation and refusing valid intents; bypassing browser network consent and
disabling valid operations. The corresponding protocol, storage and browser
tests failed in each direction, then passed after restoration.

The 2026-10-09 vulnerability scan found eleven reachable standard-library
advisories in Go 1.26.7 (GO-2026-6603/6604/6605/6607/6608/6609/6610/6611/6612/
6613/6617). All report a Go 1.26.9 fix. Raise the module minimum to 1.26.9 and
pin the official `golang:1.26.9-bookworm` build image by its registry manifest
digest. No vulnerability exemption or global host-toolchain modification.
Historical ADR references to 1.26.7 remain historical. See the
[Go release history](https://go.dev/doc/devel/release) and
[Go vulnerability database](https://pkg.go.dev/vuln/GO-2026-6617).
The patched scan has zero reachable/imported-package findings. Its residual
module-level GO-2026-5932 notice concerns unmaintained x/crypto/openpgp, which
Rootwell does not import or call (PGP is outside scope), not x/crypto/acme.
No suppression is added; the architecture gate forbids that OpenPGP package.
