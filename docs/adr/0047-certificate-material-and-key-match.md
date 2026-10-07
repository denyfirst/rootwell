# ADR 0047 — Explicit key match and one certificate-material entry

Status: implemented for development; signed PR, required CI and self-review
gates apply, not production approval. Supersedes ADR 0046's
matched-only new import boundary, not its authentication/encryption controls.

Inspect gains a distinct optional secret picker and one-shot offline worker.
Public Inspect/Verify parsers still reject mixed/private input. The operation
returns only public fingerprints and computed matched/mismatch verdicts. It
never saves, exports, uploads or decides trust; malformed/password failure is
not mismatch. Source changes, navigation, deadlines and hidden-page aborts
invalidate results and clear owned buffers. Runtime copies remain a risk.

Certificates uses one primary certificate or bounded public PEM bundle and
optional key. Check is optional; Save performs the same server validation.
Ambiguous primary selection requires an exact fingerprint from the supplied
collection. Included issuer signatures are checked, not CA trust; unrelated
and ambiguous issuer paths refuse. Up to 16 certificates / 768 KiB public input
and 512 KiB aggregate decoded DER (shared preview/storage budget),
64 KiB key, 256-byte transient existing-key password. No PFX library import.
The main public picker also accepts up to 8 separate related public files;
the existing public-only WASM importer reconstructs a bounded PEM collection
before own-daemon processing. All selected file identities and output digest
are rechecked; no secret is routed through that public importer.

Mismatch may be stored only after explicit acknowledgement. A new purpose-
separated encrypted material attachment preserves parsed public certificates
and canonical key, not raw input/password/file name. All attachments are
authenticated and revalidated before metadata output; mismatch status is
derived, never caller-authored. Legacy matched-key images remain supported.
Older binaries refuse the new manifest field. Notes/delete/full backups must
preserve/remove/restore the complete material; rollback remains possible.

Downloads distinguish certificate, supplied public bundle, matching-pair ZIP,
and encrypted key only. A loose mismatched key must never enter pair/PFX or
deployment workflows. Key-only export still requires fresh instance password,
the shared attempt budget and separate strong output password. ZIP is not
encrypted. Multiple unrelated public imports remain under Advanced, not a
second main form. No production/audit claim or Porch mutation is authorized.

Evidence: generated RSA/EC/Ed25519 positive and unrelated-key comparisons,
unordered issuer bundles, same-key renewal ambiguity and explicit selection,
name-only issuer/duplicate/malformed/CA refusal; encrypted key/password and
actual Go WASM comparisons; acknowledgement/atomicity/tamper/metadata/delete
store tests; Linux own-daemon separate exports and full restore; no-network
Inspect UI worker deadlines/nav/hidden/error clearing; direct-Save, ambiguity,
mismatch consent, multifile revalidation and authenticated download UI tests.
Local fuzz smoke: 146824 executions in 10 seconds, two workers, no failure.

Deliberate sabotage (restored): forcing a nonmatching final bundle member to
match failed the mismatch assertion; forcing every comparison to false failed
the valid bundle assertion. Removing only the writer's consent guard still
refused through attachment revalidation; removing both guards caused the
unacknowledged-store test to fail. UI auto-saving an unacknowledged mismatch
failed its refusal assertion; suppressing matched direct-Save failed its
success assertion. Final self-review aligned aggregate decoded DER limits
between preview and storage; disabling that budget failed the oversized-input
test and reducing it to one byte failed the valid-input test. All restored
tests rerun. These assertions are evidence,
not a claim that every defect is excluded. Larger per-record collections and
revalidating up to 500 stored records increase authenticated CPU/memory costs;
resource/host/runtime/old-snapshot risks require independent release review.
