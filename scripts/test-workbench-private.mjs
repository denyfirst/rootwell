import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

class Element {
  constructor() {
    this.listeners = {};
    this.files = [];
    this.value = "";
    this.textContent = "";
    this.hidden = false;
    this.disabled = false;
  }
  addEventListener(event, listener) { this.listeners[event] = listener; }
  click() { this.clicked = true; }
  remove() {}
}
const elements = new Map();
const get = (id) => {
  if (!elements.has(id)) elements.set(id, new Element());
  return elements.get(id);
};
const document = { getElementById: get, createElement: () => new Element(), body: { append() {} } };
const fingerprint = "AA:".repeat(31) + "AA";
let inspectCalls = 0;
let exportCalls = 0;
let downloaded = null;
let capturedInput = null;
let capturedPassword = null;
let output = null;
let invalidResponse = false;
const engine = {
  privateInspect(bytes) {
    inspectCalls++;
    capturedInput = bytes;
    return JSON.stringify({ schema_version: "rootwell.browser.private-convert.v1", ok: true, error: null,
      result: { input_format: "pkcs1-pem", algorithm: "RSA", bits: 2048, curve: "", public_fingerprint: fingerprint } });
  },
  privateExportEncrypted(bytes, selected, password) {
    exportCalls++;
    assert.equal(bytes[0], 65);
    assert.equal(selected, fingerprint);
    capturedInput = bytes;
    capturedPassword = password;
    output = new TextEncoder().encode("-----BEGIN ENCRYPTED PRIVATE KEY-----\n" + "A".repeat(80));
    return { schema_version: "rootwell.browser.private-convert.v1", ok: true, error: null,
      result: { filename: invalidResponse ? "unsafe.pem" : "rootwell-encrypted-key-aaaaaaaaaaaaaaaa-" + "b".repeat(32) + ".pem", bytes: output } };
  }
};
const context = vm.createContext({ document, TextEncoder, Uint8Array, Blob,
  URL: { createObjectURL(blob) { downloaded = blob; return "blob:private-test"; }, revokeObjectURL() {} },
  setTimeout() {}, rootwellWorkbenchReady: Promise.resolve(engine) });
vm.runInContext(fs.readFileSync("web/workbench/private-key.js", "utf8"), context, { filename: "private-key.js" });
await new Promise((resolve) => setImmediate(resolve));

let sourceByte = 65;
const file = { size: 1, slice: () => ({ arrayBuffer: async () => Uint8Array.of(sourceByte).buffer }) };
get("private-convert-file").files = [file];
get("private-convert-file").listeners.change();
assert.equal(get("private-convert-inspect").disabled, false);
await get("private-convert-inspect").listeners.click();
assert.equal(inspectCalls, 1);
assert.equal(capturedInput[0], 0, "inspected key buffer was retained");
assert.equal(get("private-convert-result").hidden, false);
assert.equal(get("private-convert-summary").textContent.includes(fingerprint), true);
assert.equal(get("private-convert-summary").textContent.includes("PRIVATE KEY"), false);

get("private-convert-password").value = "too-short";
get("private-convert-confirm").value = "too-short";
await get("private-convert-download").listeners.click();
assert.equal(exportCalls, 0);
assert.equal(downloaded, null);
assert.equal(get("private-convert-password").value, "");

get("private-convert-password").value = "non-production-output-password-12345";
get("private-convert-confirm").value = "non-production-output-password-12345";
await get("private-convert-download").listeners.click();
assert.equal(exportCalls, 1);
assert.equal(capturedInput[0], 0, "source key bytes were not cleared");
assert.equal(capturedPassword[0], 0, "output password bytes were not cleared");
assert.equal(output[0], 0, "encrypted output buffer was not cleared");
assert.ok(downloaded instanceof Blob);
assert.equal(get("private-convert-password").value, "");
assert.equal(get("private-convert-confirm").value, "");

invalidResponse = true;
get("private-convert-password").value = "non-production-output-password-12345";
get("private-convert-confirm").value = "non-production-output-password-12345";
await get("private-convert-download").listeners.click();
assert.equal(exportCalls, 2);
assert.equal(output[0], 0, "rejected output buffer was not cleared");
assert.equal(get("private-convert-error").hidden, false);

await get("private-convert-inspect").listeners.click();
assert.equal(get("private-convert-result").hidden, false);

sourceByte = 66;
get("private-convert-password").value = "non-production-output-password-12345";
get("private-convert-confirm").value = "non-production-output-password-12345";
await get("private-convert-download").listeners.click();
assert.equal(exportCalls, 3);
assert.equal(get("private-convert-result").hidden, true, "changed key left a stale export result visible");
assert.equal(get("private-convert-download").disabled, true);
sourceByte = 65;

get("private-convert-file").files = [];
get("private-convert-file").listeners.change();
assert.equal(get("private-convert-result").hidden, true);
await get("private-convert-download").listeners.click();
assert.equal(exportCalls, 3, "stale selection allowed another export");

let releaseRead;
const slowFile = { size: 1, slice: () => ({ arrayBuffer: () => new Promise((resolve) => { releaseRead = resolve; }) }) };
get("private-convert-file").files = [slowFile];
get("private-convert-file").listeners.change();
const pendingInspect = get("private-convert-inspect").listeners.click();
get("private-convert-file").files = [file];
get("private-convert-file").listeners.change();
releaseRead(Uint8Array.of(65).buffer);
await pendingInspect;
assert.equal(get("private-convert-inspect").disabled, false, "new selection stayed disabled after stale read");
assert.equal(get("private-convert-result").hidden, true, "stale read showed a result");
console.log("Private-key Workbench state and refusal tests passed.");
