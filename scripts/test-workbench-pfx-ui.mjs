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
const document = { getElementById: get, createElement: () => new Element(), body: new Element() };
const fingerprint = "AA:".repeat(31) + "AA";
get("pfx-cert-format").value = "pem";
let downloaded = 0;
let inspected = 0;
let exported = 0;
let created = 0;
let held = false;
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
    if (operation === "create") created++;
    else exported++;
    const format = operation === "create" ? "pfx" : operation === "key" ? "encrypted-pkcs8-pem" : "pem";
    const filename = operation === "create" ? "rootwell-bundle-" + "b".repeat(32) + ".pfx" :
      "rootwell-" + (operation === "key" ? "encrypted-key" : "certificate") + "-" + "a".repeat(16) + "-" + "b".repeat(32) + ".pem";
    responseBytes = operation === "create" ? Uint8Array.of(0x30, 0x03, 0x01) :
      new TextEncoder().encode("-----BEGIN " + (operation === "key" ? "ENCRYPTED PRIVATE KEY" : "CERTIFICATE") + "-----\n" + "A".repeat(40));
    return { schema_version: "rootwell.browser.pfx.v1", ok: true, error: null,
      result: { bytes: responseBytes, format, filename } };
  }
};
const context = vm.createContext({ document, TextEncoder, Uint8Array, Blob, AbortController,
  WebAssembly: { Module }, rootwellPFXWorker: worker, rootwellWorkbenchReady: Promise.resolve({ module: new Module() }),
  URL: { createObjectURL() { downloaded++; return "blob:test"; }, revokeObjectURL() {} }, setTimeout() {} });
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

get("pfx-create-cert").files = [file];
get("pfx-create-key").files = [file];
get("pfx-create-cert").listeners.change();
get("pfx-create-key").listeners.change();
assert.equal(get("pfx-create-button").disabled, false);
get("pfx-create-password").value = "new-synthetic-PFX-password-2026";
get("pfx-create-confirm").value = "new-synthetic-PFX-password-2026";
await get("pfx-create-button").listeners.click();
assert.equal(created, 1);
assert.equal(downloaded, 3);
assert.equal(responseBytes[0], 0, "PFX output buffer was not cleared");
assert.equal(captured.inputs[1][0], 0, "private input key was not cleared");

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
