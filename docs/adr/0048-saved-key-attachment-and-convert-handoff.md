# ADR 0048 — Add a key to an existing certificate; one Convert workspace

Date: 2026-10-08. Status: development implementation, required signed PR/CI
and separately recorded maintainer self-review; not independent audit.

## Decision and authority

Certificates gains **Add private key** only on a saved public-only record.
Select one supported plaintext/encrypted PKCS#8, PKCS#1 or SEC1 key, optionally
Check, confirm the current Rootwell password and Save. Encrypted PKCS#8 input
uses a separate transient file password. Save repeats the mathematical check
under the writer lock; browser preview grants no authority. A valid mismatch
requires explicit consent and stays a loose attachment, never a usable pair.
Unsupported/CA/malformed keys or password failures are not mismatch results.

This operation adds, never replaces or removes, a key. Both legacy key and
material-bearing records refuse replacement. The existing certificate,
bounded supplied public bundle, import provenance, order and service notes
remain intact. One atomic authenticated image upgrades the public-only
material or adds one to a legacy public record; the same generation/history
limits apply. A `key-added` event joins the encrypted history. Notes, delete,
pair/key-only export and full backup/restore preserve their earlier semantics.

Ready Linux loopback sessions only: POST, exact host/origin/custom header,
strict bounded mode-specific JSON, session revision, exact fingerprint and
generation. Save requires fresh instance authentication through the shared
five-attempts/minute budget and single expensive parse/KDF slot. Check does not
authenticate a second time or write. No client-supplied certificate, notes or
status may change this record through the attachment API.

The UI binds preview to file identity, reread digest, generation and a
120-second lifetime. Changed/hidden/pagehide/cancel/deadline state clears owned
buffers/passwords, aborts and discards late replies. Check/direct Save use a
30-second deadline. Cancellation after Save transmission is not rollback;
show an uncertain outcome and require refresh. Lost session after committed
write returns an uncertain server error, not a definitive pre-write refusal.
Raw file/network/server error text is never displayed. Runtime copies remain.

**Details → Convert format** explicitly submits only existing record identity,
generation and tool to the current native POST handoff. The server emits only
selected public DER; actual offline WASM reparses and checks its fingerprint
before opening the existing Convert panel. No private key, bundle, service
notes or trust authority is automatically transferred. For private/PFX
conversion the operator explicitly downloads the separately encrypted key
after reauthentication and selects it in Convert. There is no second converter,
secret URL/storage handoff or new Workbench networking capability.

## Evidence and residuals

`TestAttachKeyPreservesRecordAndRefusesOverwrite` covers legacy/material
upgrade, match/consent/stale/malformed/tamper refusals, provenance, key loans,
notes, delete and no secret metadata. `TestAttachEncryptedKeyAndCapacityRefusals`
covers encrypted password, byte bounds, order/unrelated record preservation,
history and generation ceilings. `TestKeyAttachmentRequestModesAreStrict`
rejects duplicate/unknown/wrong-mode/malformed fields. Linux
`TestLinuxSavedKeyRequiresFreshAuthenticationAndPreservesRefusedImage` covers
auth/origin/header, no-write refusals, direct Save, no overwrite and shared
attempt limits. `TestLinuxMaterialMismatchExportAndBundleFullRestore` adds a
key to a public bundle and restores it with earlier loose material intact.
Native handoff tests and actual WASM `scripts/test-inventory-workbench.mjs`
cover Convert, unknown tools, exact selection and empty private picker.
`scripts/test-saved-key-attachment.mjs` covers optional Check/direct Save,
consent, file substitution/content mutation, fixed errors, malformed response,
late/hidden/deadline cancellation and uncertain writes; existing library tests
continue to cover import/download controls.

Deliberate sabotage (restored): bypassing the existing-key guard failed the
overwrite refusal assertion; forcing every key input invalid failed the valid
preview assertion. Bypassing the UI mismatch consent guard failed its no-Save
assertion; suppressing matched direct Save failed its positive two-request
assertion. Denying Convert failed the valid native form test; admitting every
tool failed the unknown-tool refusal test. All altered sources were restored
and targeted tests rerun. These tests detect these regressions, not every flaw.

Local gates: Go tests/vet/build/module cleanliness, pinned staticcheck/gosec/
actionlint/govulncheck; Linux API compile and vet; complete actual Go WASM/UI
suite. Linux durable integration/race and container recovery execute in CI.
The module-level GO-2026-5932 advisory is for x/crypto/openpgp, which Rootwell
does not import; verbose scanning reports zero affected imported packages or
reachable symbols. No dependency changed. Browser VM checks are not a new
visual-browser inspection or an independent audit.

Residuals: manual full backups (make a new one after adding a key), old backups
and complete-image rollback, host/browser/daemon compromise, runtime copies,
authenticated parser resource use. Native Windows remains read-only. No key
replacement, CA custody, PFX library import, unattended unlock, remote listener,
ACME account or network challenge is authorized by this increment.

Next: design ACME staging account/challenge authority, CA endpoint validation,
account-secret custody, timeouts/retries, explicit enrollment/renewal and
deployment boundaries. Do not silently enroll a live CA or send a real domain.
