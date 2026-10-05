import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const events = new Map();
const timers = new Map();
const elements = new Map();
let sequence = 0;
function element() {
  return { hidden: true, textContent: "", listeners: {}, addEventListener(name, fn) { this.listeners[name] = fn; } };
}
const document = { hidden: false, getElementById(id) { if (!elements.has(id)) elements.set(id, element()); return elements.get(id); },
  addEventListener(name, fn) { events.set(name, fn); } };
const context = vm.createContext({ document, Uint8Array, TextDecoder,
  addEventListener(name, fn) { events.set(name, fn); },
  setTimeout(fn, duration) { assert.equal(duration, 30000); timers.set(++sequence, fn); return sequence; },
  clearTimeout(id) { timers.delete(id); } });
vm.runInContext(fs.readFileSync("web/workbench/secret-view.js", "utf8"), context);
const panel = element(), content = element(), button = element();
let cancelled = 0, hidden = 0;
const view = context.rootwellSecretView.create(panel, content, button, () => { cancelled++; }, () => { hidden++; });
const key = new TextEncoder().encode("-----BEGIN PRIVATE KEY-----\n" + "A".repeat(80) + "\n-----END PRIVATE KEY-----\n");
view.show(key);
assert.equal(panel.hidden, false);
assert.equal(content.textContent, new TextDecoder().decode(key));
assert.equal(key[0], 45, "view mutated caller bytes");
assert.equal(timers.size, 1);
[...timers.values()][0]();
assert.equal(panel.hidden, true, "timeout did not hide private key");
assert.equal(content.textContent, "", "timeout merely hid retained plaintext");
assert.equal(hidden, 1);
for (const event of ["blur", "pagehide", "hashchange", "visibilitychange"]) {
  view.show(key);
  if (event === "visibilitychange") document.hidden = true;
  events.get(event)();
  assert.equal(content.textContent, "", event + " retained private key");
  assert.equal(panel.hidden, true);
  document.hidden = false;
}
assert.equal(cancelled, 4, "page boundaries failed to cancel pending operations");
for (const id of ["inspect-tab", "convert-tab", "verify-tab", "request-tab", "convert-open-inspect"]) {
  view.show(key);
  elements.get(id).listeners.click();
  assert.equal(content.textContent, "", "tool change retained private key");
}
view.show(key);
button.listeners.click();
assert.equal(content.textContent, "", "manual hide retained private key");
for (const invalid of [new Uint8Array(), new Uint8Array(96 * 1024 + 1), new TextEncoder().encode("<script>unsafe</script>"),
  new TextEncoder().encode("-----BEGIN PRIVATE KEY-----\n<script>unsafe</script>\n-----END PRIVATE KEY-----\n"), new Uint8Array(100).fill(255)]) {
  assert.throws(() => view.show(invalid));
  assert.equal(content.textContent, "");
}
document.hidden = true;
assert.throws(() => view.show(key));
document.hidden = false;
const otherPanel = element(), otherContent = element();
let otherCancelled = 0;
const other = context.rootwellSecretView.create(otherPanel, otherContent, element(), () => { otherCancelled++; }, () => {});
other.show(key);
const before = otherCancelled;
view.show(key);
assert.equal(otherPanel.hidden, true, "two keys remained visible");
assert.equal(otherContent.textContent, "");
assert.equal(otherCancelled, before + 1, "new reveal did not cancel another pending view");
view.hide();
assert.equal(timers.size, 0);
console.log("Transient private-key view timeout, consent-boundaries, cancellation and safe-text checks passed.");
