import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

class Element {
  constructor() { this.listeners = {}; this.files = []; this.value = ""; this.textContent = ""; this.hidden = false; this.disabled = false; this.children = []; }
  addEventListener(event, fn) { this.listeners[event] = fn; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = [...nodes]; }
  click() { this.clicked = true; }
  remove() {}
}
const elements = new Map();
const get = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
const document = { getElementById: get, createElement: () => new Element(), body: new Element(), addEventListener() {} };
const boundaries = {};
get("pfx-reveal-panel").hidden = true;
const fingerprint = "AA:".repeat(31) + "AA";
get("pfx-cert-format").value = "pem";
let downloaded = 0;
let inspected = 0;
let exported = 0;
let revealed = 0;
let holdReveal = false;
let releaseReveal;
let created = 0;
let held = false;
let holdCreate = false;
let releaseCreate;
let release;
let sourceByte = 65;
let captured;
let responseBytes;
const summary = JSON.stringify({ schema_version: "rootwell.browser.pfx.v1", ok: true, error: null,
  result: { certificates: [{ subject: "synthetic.example", issuer: "synthetic CA", not_after: "2030-01-01T00:00:00Z",
    fingerprint, is_ca: false, matching_key: true }] } });
class Module {}
const worker = {
  async run(_module, operation, inputs, password, second, option, signal) {
    assert.equal(signal.aborted, false);
    captured = { inputs, password, second };
    if (operation === "inspect") {
      inspected++;
      if (held) return new Promise(resolve => { release = () => resolve(summary); });
      return summary;
    }
    if (operation === "create") {
      created++;
      assert.equal(new TextDecoder().decode(second), "existing-synthetic-key-password", "existing key password did not reach worker");
    }
    else if (operation === "reveal") { revealed++; assert.equal(option, fingerprint); assert.equal(second.length, 0); }
    else exported++;
    const format = operation === "create" ? "pfx" : operation === "key" ? "encrypted-pkcs8-pem" : operation === "reveal" ? "pkcs8-pem" : "pem";
    const filename = operation === "reveal" ? "" : operation === "create" ? "rootwell-bundle-" + "b".repeat(32) + ".pfx" :
      "rootwell-" + (operation === "key" ? "encrypted-key" : "certificate") + "-" + "a".repeat(16) + "-" + "b".repeat(32) + ".pem";
    responseBytes = operation === "create" ? Uint8Array.of(0x30, 0x03, 0x01) :
      new TextEncoder().encode("-----BEGIN " + (operation === "key" ? "ENCRYPTED PRIVATE KEY" : operation === "reveal" ? "PRIVATE KEY" : "CERTIFICATE") + "-----\n" + "A".repeat(80) + "\n-----END " + (operation === "key" ? "ENCRYPTED PRIVATE KEY" : operation === "reveal" ? "PRIVATE KEY" : "CERTIFICATE") + "-----\n");
    const answer = { schema_version: "rootwell.browser.pfx.v1", ok: true, error: null,
      result: { bytes: responseBytes, format, filename } };
    if (operation === "create" && holdCreate) return new Promise(resolve => { releaseCreate = () => resolve(answer); });
    if (operation === "reveal" && holdReveal) return new Promise(resolve => { releaseReveal = () => resolve(answer); });
    return answer;
  }
};
const context = vm.createContext({ document, TextEncoder, TextDecoder, Uint8Array, Blob, AbortController,
  WebAssembly: { Module }, rootwellPFXWorker: worker, rootwellWorkbenchReady: Promise.resolve({ module: new Module() }),
  URL: { createObjectURL() { downloaded++; return "blob:test"; }, revokeObjectURL() {} }, setTimeout() {}, clearTimeout() {},
  addEventListener(event, fn) { boundaries[event] = fn; } });
vm.runInContext(fs.readFileSync("web/workbench/secret-view.js", "utf8"), context);
vm.runInContext(fs.readFileSync("web/workbench/pfx.js", "utf8"), context);
await new Promise(resolve => setImmediate(resolve));

const file = { size: 1, slice: () => ({ arrayBuffer: async () => Uint8Array.of(sourceByte).buffer }) };
get("pfx-open-file").files = [file];
get("pfx-open-file").listeners.change();
assert.equal(get("pfx-open-button").disabled, false);
get("pfx-open-password").value = "synthetic-PFX-password-2026";
await get("pfx-open-button").listeners.click();
assert.equal(inspected, 1);
assert.equal(get("pfx-open-result").hidden, false);
assert.equal(get("pfx-open-password").value, "");
assert.equal(captured.inputs[0][0], 0, "inspection source was not cleared");
assert.equal(captured.password[0], 0, "inspection password was not cleared");
assert.equal(get("pfx-certificates").children.length, 1);
get("pfx-cert-choice").value = fingerprint;
await get("pfx-cert-download").listeners.click();
assert.equal(exported, 0, "certificate export skipped fresh PFX password");
get("pfx-open-password").value = "synthetic-PFX-password-2026";
await get("pfx-cert-download").listeners.click();
assert.equal(exported, 1);
assert.equal(downloaded, 1);
assert.equal(responseBytes[0], 0, "public output buffer was not cleared");

get("pfx-key-password").value = "new-synthetic-output-password-2026";
get("pfx-key-confirm").value = "mismatch";
get("pfx-open-password").value = "synthetic-PFX-password-2026";
await get("pfx-key-download").listeners.click();
assert.equal(exported, 1, "mismatched output password accepted");
get("pfx-key-password").value = "new-synthetic-output-password-2026";
get("pfx-key-confirm").value = "new-synthetic-output-password-2026";
get("pfx-open-password").value = "synthetic-PFX-password-2026";
await get("pfx-key-download").listeners.click();
assert.equal(exported, 2);
assert.equal(downloaded, 2);
assert.equal(captured.second[0], 0, "key output password was not cleared");

await get("pfx-reveal-button").listeners.click();
assert.equal(revealed, 0, "PFX reveal skipped fresh password");
get("pfx-open-password").value = "synthetic-PFX-password-2026";
await get("pfx-reveal-button").listeners.click();
assert.equal(revealed, 1);
assert.equal(downloaded, 2, "viewing a key requested a download");
assert.equal(get("pfx-reveal-panel").hidden, false);
assert.match(get("pfx-reveal-content").textContent, /^-----BEGIN PRIVATE KEY-----/);
assert.equal(responseBytes[0], 0);
get("pfx-key-tools").open = false;
get("pfx-key-tools").listeners.toggle();
assert.equal(get("pfx-reveal-content").textContent, "", "closing key tools retained plaintext");
holdReveal = true;
get("pfx-open-password").value = "synthetic-PFX-password-2026";
const pendingReveal = get("pfx-reveal-button").listeners.click();
await new Promise(resolve => setImmediate(resolve));
boundaries.pagehide();
releaseReveal();
await pendingReveal;
holdReveal = false;
assert.equal(get("pfx-reveal-panel").hidden, true, "late reveal revived hidden key");
assert.equal(responseBytes[0], 0);
assert.equal(downloaded, 2);

get("pfx-create-cert").files = [file];
get("pfx-create-key").files = [file];
get("pfx-create-cert").listeners.change();
get("pfx-create-key").listeners.change();
assert.equal(get("pfx-create-button").disabled, false);
get("pfx-create-password").value = "new-synthetic-PFX-password-2026";
get("pfx-create-confirm").value = "new-synthetic-PFX-password-2026";
get("pfx-create-input-password").value = "existing-synthetic-key-password";
await get("pfx-create-button").listeners.click();
assert.equal(created, 1);
assert.equal(downloaded, 3);
assert.equal(responseBytes[0], 0, "PFX output buffer was not cleared");
assert.equal(captured.inputs[1][0], 0, "private input key was not cleared");
assert.equal(captured.second[0], 0, "existing key password was not cleared");
assert.equal(get("pfx-create-input-password").value, "");

holdCreate = true;
get("pfx-create-input-password").value = "existing-synthetic-key-password";
get("pfx-create-password").value = "new-synthetic-PFX-password-2026";
get("pfx-create-confirm").value = "new-synthetic-PFX-password-2026";
const pendingCreate = get("pfx-create-button").listeners.click();
await new Promise(resolve => setImmediate(resolve));
get("pfx-create-input-password").value = "changed";
get("pfx-create-input-password").listeners.input();
releaseCreate();
await pendingCreate;
assert.equal(created, 2);
assert.equal(downloaded, 3, "late result downloaded a PFX after the password changed");
assert.equal(responseBytes[0], 0, "stale PFX output was not cleared");
holdCreate = false;

get("pfx-create-input-password").value = "new-synthetic-PFX-password-2026";
get("pfx-create-password").value = "new-synthetic-PFX-password-2026";
get("pfx-create-confirm").value = "new-synthetic-PFX-password-2026";
await get("pfx-create-button").listeners.click();
assert.equal(created, 2, "reused input/output password reached worker");
assert.equal(downloaded, 3);
get("pfx-create-input-password").value = "ü".repeat(129);
get("pfx-create-password").value = "new-synthetic-PFX-password-2026";
get("pfx-create-confirm").value = "new-synthetic-PFX-password-2026";
await get("pfx-create-button").listeners.click();
assert.equal(created, 2, "over-limit UTF-8 input password reached worker");
assert.equal(get("pfx-create-input-password").value, "");

held = true;
get("pfx-open-file").files = [file];
get("pfx-open-file").listeners.change();
get("pfx-open-password").value = "synthetic-PFX-password-2026";
const pending = get("pfx-open-button").listeners.click();
await new Promise(resolve => setImmediate(resolve));
get("pfx-open-file").files = [];
get("pfx-open-file").listeners.change();
release();
await pending;
assert.equal(get("pfx-open-result").hidden, true, "late worker result revived stale PFX");
assert.equal(downloaded, 3);
console.log("PFX UI fresh-password, no-partial-download, stale-result and buffer-clearing checks passed.");
