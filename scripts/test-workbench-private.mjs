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
    this.options = [];
    this.selectedOptions = [];
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
get("private-convert-format").options = ["encrypted-pkcs8-pem", "pkcs8-pem", "pkcs8-der", "pkcs1-pem", "pkcs1-der", "sec1-pem", "sec1-der"].map(value => ({ value, disabled: false }));
Object.defineProperty(get("private-convert-format"), "selectedOptions", { get() { return this.options.filter(option => option.value === this.value); } });
let inspectCalls = 0;
let exportCalls = 0;
let downloaded = null;
let capturedInput = null;
let capturedPassword = null;
let output = null;
let invalidResponse = false;
let encryptedMode = false;
let capturedCurrentPassword = null;
let holdInspect = false;
let releaseInspect;
let holdExport = false;
let releaseExport;
const engine = {
  privateInspect(bytes, currentPassword) {
    inspectCalls++;
    capturedInput = bytes;
    if (encryptedMode && currentPassword.byteLength === 0) {
      return JSON.stringify({ schema_version: "rootwell.browser.private-convert.v1", ok: false, result: null, error: "input-password-required" });
    }
    assert.equal(new TextDecoder().decode(currentPassword), encryptedMode ? "current-password" : "");
    return JSON.stringify({ schema_version: "rootwell.browser.private-convert.v1", ok: true, error: null,
      result: { input_format: encryptedMode ? "encrypted-pkcs8-pem" : "pkcs1-pem", algorithm: "RSA", bits: 2048, curve: "", public_fingerprint: fingerprint } });
  },
  privateExport(bytes, selected, currentPassword, format, password) {
    exportCalls++;
    assert.equal(bytes[0], 65);
    assert.equal(selected, fingerprint);
    assert.equal(new TextDecoder().decode(currentPassword), encryptedMode ? "current-password" : "");
    capturedInput = bytes;
    capturedCurrentPassword = currentPassword;
    capturedPassword = password;
    output = new TextEncoder().encode("-----BEGIN " + (format === "encrypted-pkcs8-pem" ? "ENCRYPTED " : "") + "PRIVATE KEY-----\n" + "A".repeat(80));
    return { schema_version: "rootwell.browser.private-convert.v1", ok: true, error: null,
      result: { format, filename: invalidResponse ? "unsafe.pem" : "rootwell-" + (format === "encrypted-pkcs8-pem" ? "encrypted" : "plaintext") + "-key-aaaaaaaaaaaaaaaa-" + "b".repeat(32) + ".pem", bytes: output } };
  }
};
class MockModule {}
const workerApi = {
  async run(_module, operation, bytes, currentPassword, fingerprint, format, password, signal) {
    assert.equal(signal.aborted, false);
    if (holdInspect && operation === "inspect") return new Promise(resolve => { releaseInspect = () => resolve(engine.privateInspect(bytes, currentPassword)); });
    if (holdExport && operation === "export") return new Promise(resolve => { releaseExport = () => resolve(engine.privateExport(bytes, fingerprint, currentPassword, format, password)); });
    return operation === "inspect" ? engine.privateInspect(bytes, currentPassword) :
      engine.privateExport(bytes, fingerprint, currentPassword, format, password);
  }
};
const context = vm.createContext({ document, TextEncoder, Uint8Array, Blob,
  AbortController, WebAssembly: { Module: MockModule }, rootwellPrivateWorker: workerApi,
  URL: { createObjectURL(blob) { downloaded = blob; return "blob:private-test"; }, revokeObjectURL() {} },
  setTimeout() {}, rootwellWorkbenchReady: Promise.resolve({ module: new MockModule() }) });
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

get("private-convert-format").value = "pkcs8-pem";
get("private-convert-format").listeners.change();
await get("private-convert-download").listeners.click();
assert.equal(exportCalls, 1, "plaintext export lacked confirmation but was accepted");
get("private-convert-plaintext-confirm").checked = true;
await get("private-convert-download").listeners.click();
assert.equal(exportCalls, 2, "confirmed plaintext export did not run");
assert.equal(capturedPassword.byteLength, 0);
get("private-convert-format").value = "encrypted-pkcs8-pem";
get("private-convert-format").listeners.change();

invalidResponse = true;
get("private-convert-password").value = "non-production-output-password-12345";
get("private-convert-confirm").value = "non-production-output-password-12345";
await get("private-convert-download").listeners.click();
assert.equal(exportCalls, 3);
assert.equal(output[0], 0, "rejected output buffer was not cleared");
assert.equal(get("private-convert-error").hidden, false);

await get("private-convert-inspect").listeners.click();
assert.equal(get("private-convert-result").hidden, false);

sourceByte = 66;
get("private-convert-password").value = "non-production-output-password-12345";
get("private-convert-confirm").value = "non-production-output-password-12345";
await get("private-convert-download").listeners.click();
assert.equal(exportCalls, 4);
assert.equal(get("private-convert-result").hidden, true, "changed key left a stale export result visible");
assert.equal(get("private-convert-download").disabled, true);
sourceByte = 65;

get("private-convert-file").files = [];
get("private-convert-file").listeners.change();
assert.equal(get("private-convert-result").hidden, true);
await get("private-convert-download").listeners.click();
assert.equal(exportCalls, 4, "stale selection allowed another export");

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

holdInspect = true;
get("private-convert-file").files = [file];
get("private-convert-file").listeners.change();
const pendingWorker = get("private-convert-inspect").listeners.click();
await new Promise(resolve => setImmediate(resolve));
get("private-convert-file").files = [];
get("private-convert-file").listeners.change();
releaseInspect();
await pendingWorker;
holdInspect = false;
assert.equal(get("private-convert-result").hidden, true, "stale worker response showed a key");
assert.equal(get("private-convert-file-state").textContent, "No private key selected");

invalidResponse = false;
encryptedMode = true;
get("private-convert-file").files = [file];
get("private-convert-file").listeners.change();
await get("private-convert-inspect").listeners.click();
assert.match(get("private-convert-error").textContent, /current password/);
assert.equal(get("private-convert-result").hidden, true);
get("private-convert-input-password").value = "current-password";
await get("private-convert-inspect").listeners.click();
assert.equal(get("private-convert-input-password").value, "", "current password retained after inspection");
get("private-convert-format").value = "pkcs8-pem";
get("private-convert-format").listeners.change();
get("private-convert-plaintext-confirm").checked = true;
await get("private-convert-download").listeners.click();
assert.equal(exportCalls, 4, "encrypted source exported without current password");
get("private-convert-input-password").value = "current-password";
get("private-convert-plaintext-confirm").checked = true;
await get("private-convert-download").listeners.click();
assert.equal(exportCalls, 5);
assert.equal(capturedCurrentPassword[0], 0, "current password bytes were not cleared");
assert.equal(get("private-convert-plaintext-confirm").checked, false, "plaintext consent persisted after download");
assert.equal(get("private-convert-result").hidden, false, "successful encrypted-input export lost inspection: " + get("private-convert-error").textContent);

holdExport = true;
get("private-convert-format").value = "encrypted-pkcs8-pem";
get("private-convert-format").listeners.change();
get("private-convert-input-password").value = "current-password";
get("private-convert-password").value = "non-production-output-password-12345";
get("private-convert-confirm").value = "non-production-output-password-12345";
const beforeCancelled = downloaded;
const pendingExport = get("private-convert-download").listeners.click();
await new Promise(resolve => setImmediate(resolve));
assert.equal(typeof releaseExport, "function", "export did not start: " + get("private-convert-error").textContent + " / " + get("private-convert-status").textContent);
get("private-convert-format").value = "pkcs8-pem";
get("private-convert-format").listeners.change();
releaseExport();
await pendingExport;
holdExport = false;
assert.equal(downloaded, beforeCancelled, "changed output choice downloaded a stale private key");
assert.equal(get("private-convert-download").disabled, false, "cancelled export could not be retried");
console.log("Private-key Workbench state and refusal tests passed.");
