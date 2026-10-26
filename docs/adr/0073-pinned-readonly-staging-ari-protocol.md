# ADR 0073 — Internal pinned staging ARI reads

Date: 2026-10-26. Development protocol component; no runtime consumer. Continues
the session-bound automation wave. Porch and real CA/DNS/customer data excluded.

Build on ADR0072 with a separately tested read-only transport before granting
it custody or UI authority. The pinned upstream ACME client currently provides
no ARI API, so this unsigned GET resource uses standard net/http directly, not
custom JWS/crypto or a new dependency. No account signer, private key or DNS token.

The internal function accepts bounded public certificate DER, a trusted internal
replaced flag, live permit and test-only dependency seam. Validate public ID,
current validity/lifetime and non-replaced status before DNS. This is not issuer/
account/domain authentication: the later writer must select only its exact saved
staging completion and bind the full generation/source before borrowing a lease.

At most one fixed staging directory GET, then one GET under the advertised exact
`/acme/renewal-info` profile path with the computed public ID. Missing advertisement
returns a distinct unavailable result without sending an ID. Other paths/hosts,
queries/fragments/escaped separators and malformed IDs refuse; no arbitrary URLs.
Eight-second total budget, inherited public-only bounded DNS/numeric dial pinning,
original SNI/system TLS, 8 KiB headers, no proxy/compression/redirect/keepalive/
automatic retry. Fresh one-use requests and a two-request budget. Strict bounded
directory JSON and 8 KiB ARI JSON/body/type/charset/encoding/header checks precede
policy parsing; no Link/explanation/error metadata is followed or reflected.

Permission, context, backwards clock and certificate expiry repeat before network
and publication. Already-sent requests cannot be recalled. HTTP errors return
fixed typed temporary/long-term failure plus only the existing bounded provider
wait hint; raw errors/body/URL never escape. A body deadline can be temporary;
transport failures whose class is intentionally hidden by shared pinning are
conservatively long-term. No persisted delay or retry loop is claimed here.
Windows fake TLS tests do not establish a native live capability: no exported
entry exists, and a future live wrapper must refuse native platforms before DNS.

Architecture permits net/http and the pure policy import only in this component,
blocks exported functions (except its fixed error method) and all production
consumers before the scoped custody review. No storage format, lease, API/UI,
production profile, scheduled fetch or automatic renewal added. Next: exact saved
certificate/source-bound intent/result/selection/error wait, full backup/recovery
and explicit privacy/step-up UI; then opt-in ready-session worker and pause.

## Evidence

Fake isolated TLS checks exact GET paths/SNI/public numeric dialing, empty bodies,
no credentials/cookies/proxy, optional unsupported advertisement and two-request
budget. Expired/replaced/future/invalid/cancelled sources refuse before DNS.
Wrong hosts/resources/redirect/type/encoding/oversize/duplicate headers/JSON,
future-expiry windows, provider wait, revocation between requests/before send/
after result and slow body cannot return partial information. Ten shuffled
protocol repetitions pass. Actual compiling sabotage: removing the URI grammar
guard failed the unsafe-URI test; inverting HTTP success acceptance failed the
legitimate two-GET path. Restored positives pass.

Pinned full local/cross-platform checks, Linux race/all exact-head CI and separate
maintainer adversarial self-review remain required. Fake TLS is not public CA
interop, an independent audit, durable scheduling or production readiness.
Protocol source: [RFC9773](https://www.rfc-editor.org/rfc/rfc9773.html) sections
3–4, checked 2026-10-26. Provider profile changes need explicit review, not an
arbitrary endpoint fallback.

## Existing overview robustness

Inspection for the next ARI source picker found that otherwise accepted imported
certificates may contain long/control-bearing DNS names. Do not copy such a name
into the bounded overview label and disable the entire page. Use a canonical
bounded DNS hint when available, otherwise a fixed saved-certificate label with
a short public identity hint. Imported records remain manual and original DER/
notes/material are unchanged. The UI additionally rejects impossible activity/
generation headroom; correct the synthetic fixture to be internally coherent.
No new UI/network authority or schema field. New generated long/control-name
regression passes. Actual two-way label sabotage: copying the raw name failed
the unusual-import test; inverted name acceptance failed the valid staging label
test. Guards restored and positives pass. URI fuzz smoke: 423943 executions/15s,
no finding; not exhaustive assurance.
