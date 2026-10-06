# ADR 0045 — One workspace appearance, separate processing boundaries

Status: implemented for development; independent release audit remains required.

Inventory uses the existing Workbench `/style.css`, sidebar, palette and
`/theme.js`. Only Inventory controls have scoped additional CSS. No Workbench
file-processing scripts run on Inventory, and no API capability is added to
the offline Workbench. Existing ready-session asset gates are unchanged.

The single-column page starts with a closed Add certificates control and the
saved list. Notes, technical identities, monitoring settings, history and
background explanations expand on demand. Expiry, stale/error state and worker
health remain visible. The explicit public-upload notice has a distinct class:
Workbench's mobile rule must not hide it. There is no second export/converter,
private custody, automatic trust, renewal or new external network activity.

The shared theme persists only `light`/`dark` under the existing
`rootwell-workbench-theme` key. Inventory content, search, notes, files and
credentials are not persisted in browser storage. Denied/malformed preference
storage falls back safely; encrypted server persistence remains Linux-only.

The loopback synthetic fixture also serves the real Workbench at `/index.html`
so both sidebar directions work. GET provides no saved DER. Only the existing
explicit generation-bound synthetic POST handoff can include the demo leaf.
Inventory writes remain disabled, and preview notices disclose the absence of
authentication/durable storage. This is not a production server preview.
Local preview in the read-only fixture explicitly says saving is unavailable,
instead of presenting a disabled Save next to a "Ready to save" instruction.

Evidence: `scripts/test-rootwelld-inventory.mjs` checks shell, initially closed
import, visible health/upload notice, no additional Workbench scripts, theme-only
storage and existing success/refusal/late-work behavior. The fixture test covers
round-trip links, assets, no-store, GET without source, unsupported methods and
query refusal. Go session/asset gates and actual WASM bulk/lifecycle tests remain
mandatory. Browser QA checks navigation, filters, details, local preview,
comparison and responsive layout. These are maintainer checks, not an audit.

Separate adversarial maintainer self-review: final routes, asset/session gates,
DOM IDs, hidden panels, responsive upload/health warnings, default Save refusal,
theme-only storage, fixture no-write behavior and API/Workbench separation were
reviewed. No backend authority or crypto behavior changed. Deliberate broken
valid navigation and an incorrect offline/no-upload claim each failed the UI
gate, then were restored. Actual WASM import/lifecycle and Go tests passed.
Read-only preview status mutations in both directions were also detected:
inviting Save in the fixture and falsely saying real Save is unavailable.
Residuals: the Windows browser uses synthetic read-only records and history;
Linux durable/background/restore/race checks run in CI. This visual unification
does not remove ADR 0044 retention, unlock-lifetime, rollback or audit limits.
