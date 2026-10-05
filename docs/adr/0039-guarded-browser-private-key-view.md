# ADR 0039 — Explicit, transient browser private-key view

Status: accepted for development; independent release audit still required.

## Decision

The private-key converter and modern-profile PFX opener gain a separate eye
button. Inspection remains public-only. Viewing creates no Blob, clipboard
write, download, Inventory write or Vault record.

Encrypted PKCS#8 requires the freshly entered current file password and
the previously displayed public-key fingerprint. PFX requires its freshly
entered password and matching-certificate fingerprint; bounded authenticated
decoding and certificate/key match are repeated before returning PKCS#8 PEM.
Wrong password, changed identity, malformed input, timeout or stale selection
must not show a key. Plaintext files have no password: renewed screen-exposure
consent is required instead. A future saved Vault key must require separate
instance reauthentication; this increment does not implement secret custody.

The shared viewer accepts bounded PKCS#8 PEM using textContent. Only one key
may be visible. Text is cleared after 30 seconds, on Hide, page/tool/hash
change, pagehide, blur, hidden document, source/choice change or closing PFX
key tools. Page boundaries also cancel pending operations so delayed output
cannot revive a view. Print CSS excludes it. Passwords and owned buffers are
cleared best-effort. PFX key downloads remain encrypted.

## Residual risks and evidence

This is display of the operator's own local file, not multi-user authorization.
The preview is synthetic-only; the self-hosted gateway still requires login
and mandatory initial password change. Screen capture, selection/copy by the
operator, extensions, same-origin compromise, assistive technology, runtime
strings, swap and a compromised host remain residual risks. Clearing and
worker termination do not guarantee memory erasure. Do not reveal real keys
while screen sharing.

`TestPFXRevealReauthenticatesAndMatches` and
`TestPFXRevealRefusesUnsafeInputs` cover authentication, identity, tamper,
truncation, trailing data and limits. Node independently parses WASM output.
UI tests cover fresh passwords/consent, no download, closing tools, buffer
clearing and stale cancellation. `scripts/test-workbench-secret-view.mjs`
covers timeout, page/tool boundaries, single-view replacement and malformed
text. Capability/gateway tests cover the new asset. Two-direction deliberate
sabotage evidence and separate adversarial self-review are recorded in the PR.
