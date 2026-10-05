import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

class Element {
  constructor() { this.listeners = {}; this.files = []; this.value = ""; this.textContent = ""; this.hidden = false; this.disabled = false; this.children = []; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = [...nodes]; }
  click() { this.clicked = true; }
  remove() {}
}
const elements = new Map();
const get = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
const docEvents = {}, boundaries = {};
const document = { hidden: false, getElementById: get, createElement: () => new Element(), body: new Element(), addEventListener(event, fn) { docEvents[event] = fn; } };
get("csr-mode").value = "generate"; get("csr-algorithm").value = "rsa-3072"; get("csr-key-format").value = "pem";
get("csr-result").hidden = get("csr-comparison").hidden = true;
const fingerprint = "AA:".repeat(31) + "AA";
const csrText = "-----BEGIN CERTIFICATE REQUEST-----\n" + "A".repeat(80) + "\n-----END CERTIFICATE REQUEST-----\n";
const summary = { input_format: "pem", subject: "CN=demo.rootwell.invalid", dns_names: ["demo.rootwell.invalid"], ip_addresses: [], algorithm: "RSA", bits: 3072, curve: "", signature_algorithm: "SHA256-RSA", signature_checked: true, request_fingerprint: fingerprint, public_fingerprint: fingerprint };
const encoder = new TextEncoder();
let downloads = 0, calls = 0, held = false, release, captured, output, malformed = false, invalidSignature = false, badPassword = false, trusted = false, differentKey = false, csrOutputSize = 0;
class Module {}
const worker = {
  async run(_module, operation, input, cert, secret, option, signal) {
    assert.equal(signal.aborted, false); calls++; captured = { input, cert, secret, operation, option, signal };
    let answer;
    if (operation === "inspect") answer = JSON.stringify({ schema_version: "rootwell.browser.csr.v1", ok: true, error: null, result: { ...summary, signature_checked: !invalidSignature } });
    else if (operation === "match") {
      assert.equal(option, fingerprint); assert.equal(input[0], 45, "matching lost its original public CSR");
      answer = JSON.stringify({ schema_version: "rootwell.browser.csr.v1", ok: true, error: null, result: { key_match: !differentKey, subject_changed: true, certificate_is_ca: false, trust_checked: trusted, missing_names: ["DNS:missing.rootwell.invalid"], additional_names: ["DNS:extra.rootwell.invalid"] } });
    } else {
      if (operation === "generate") { assert.equal(input.length, 0); assert.equal(cert.length, 0); assert.equal(new TextDecoder().decode(secret), "synthetic-new-key-password-2026"); }
      if (operation === "key") { assert.equal(new TextDecoder().decode(secret), badPassword ? "wrong" : "synthetic-existing-key-password-2026"); }
      const format = operation === "generate" ? "zip" : operation === "key" ? JSON.parse(option).format : option.slice(96);
      const filename = format === "zip" ? "rootwell-request-and-key-" + "b".repeat(32) + ".zip" : "rootwell-request-" + "b".repeat(32) + (format === "pem" ? ".csr" : ".der");
      output = { bytes: format === "zip" ? Uint8Array.of(0x50, 0x4b, 1) : format === "der" ? Uint8Array.of(0x30, 3, 1) : encoder.encode(csrText), csr: encoder.encode(csrText), format, filename, summary: JSON.stringify(summary) };
      if (csrOutputSize) { output.csr = encoder.encode(csrText.padEnd(csrOutputSize, "A")); if (format === "pem") output.bytes = output.csr.slice(); }
      answer = badPassword ? { schema_version: "rootwell.browser.csr.v1", ok: false, error: "failed", result: null } :
        { schema_version: "rootwell.browser.csr.v1", ok: true, error: null, result: malformed ? { ...output, bytes: "unsafe" } : output };
    }
    if (held) return new Promise(resolve => { release = () => resolve(answer); });
    return answer;
  }
};
const context = vm.createContext({ document, TextEncoder, Uint8Array, Blob, AbortController, WebAssembly: { Module }, rootwellCSRWorker: worker,
  rootwellWorkbenchReady: Promise.resolve({ module: new Module() }), addEventListener(name, fn) { boundaries[name] = fn; },
  URL: { createObjectURL() { downloads++; return "blob:csr-test"; }, revokeObjectURL() {} }, setTimeout() {} });
vm.runInContext(fs.readFileSync("web/workbench/csr.js", "utf8"), context);
await new Promise(resolve => setImmediate(resolve));
function newPassword() { get("csr-password").value = get("csr-confirm").value = "synthetic-new-key-password-2026"; }
await get("csr-create-button").listeners.click();
assert.equal(calls, 0, "empty request names reached generation");
get("csr-dns").value = "demo.rootwell.invalid";
newPassword(); get("csr-confirm").value = "wrong";
await get("csr-create-button").listeners.click();
assert.equal(calls, 0); assert.equal(get("csr-password").value, "");
newPassword();
await get("csr-create-button").listeners.click();
assert.equal(downloads, 1); assert.equal(captured.secret[0], 0); assert.equal(output.bytes[0], 0); assert.equal(output.csr[0], 0);
assert.equal(get("csr-result").hidden, false); assert.match(get("csr-summary").textContent, /Signed request/);
assert.equal(get("csr-password").value, "");
const file = { size: 1, slice: () => ({ arrayBuffer: async () => Uint8Array.of(65).buffer }) };
get("csr-certificate").files = [file]; get("csr-certificate").listeners.change();
await get("csr-match-button").listeners.click();
assert.equal(downloads, 1); assert.equal(get("csr-comparison").hidden, false); assert.match(get("csr-match-summary").textContent, /names are missing/);
assert.equal(get("csr-match-differences").children.length, 3); assert.equal(captured.cert[0], 0); assert.equal(captured.input[0], 0);
differentKey = true;
await get("csr-match-button").listeners.click(); assert.match(get("csr-match-summary").textContent, /Different public key/); differentKey = false;
trusted = true;
await get("csr-match-button").listeners.click(); assert.equal(get("csr-comparison").hidden, true, "trust-claiming comparison was displayed"); trusted = false;
assert.match(get("csr-error").textContent, /one public site certificate/); assert.doesNotMatch(get("csr-error").textContent, /key password/);
await get("csr-download-pem").listeners.click();
assert.equal(downloads, 2); assert.equal(output.bytes[0], 0); assert.equal(output.csr[0], 0);

held = true;
const pendingMatch = get("csr-match-button").listeners.click(); await new Promise(resolve => setImmediate(resolve));
get("csr-certificate").files = []; get("csr-certificate").listeners.change(); release(); await pendingMatch;
assert.equal(get("csr-comparison").hidden, true, "late comparison revived changed certificate selection"); held = false;

get("csr-mode").value = "key"; get("csr-mode").listeners.change();
assert.equal(get("csr-result").hidden, true); assert.equal(get("csr-existing-key").hidden, false);
get("csr-key-file").files = [file]; get("csr-key-file").listeners.change();
get("csr-input-password").value = "ü".repeat(129); const beforeLong = calls;
await get("csr-create-button").listeners.click(); assert.equal(calls, beforeLong, "over-limit UTF-8 password reached worker");
get("csr-input-password").value = "wrong"; badPassword = true;
await get("csr-create-button").listeners.click(); assert.equal(downloads, 2, "wrong key password downloaded a request"); badPassword = false;
assert.match(get("csr-error").textContent, /current key password/); assert.doesNotMatch(get("csr-error").textContent, /wrong/);
get("csr-input-password").value = "synthetic-existing-key-password-2026";
await get("csr-create-button").listeners.click(); assert.equal(downloads, 3); assert.equal(captured.input[0], 0); assert.equal(captured.secret[0], 0);
assert.equal(get("csr-input-password").value, "");
get("csr-open-file").files = [file]; get("csr-open-file").listeners.change();
invalidSignature = true;
await get("csr-open-button").listeners.click(); assert.equal(get("csr-result").hidden, true, "unchecked CSR signature was displayed"); invalidSignature = false;
assert.match(get("csr-error").textContent, /signed CSR, not a certificate or private key/); assert.doesNotMatch(get("csr-error").textContent, /key password/);
await get("csr-open-button").listeners.click(); assert.equal(get("csr-result").hidden, false);
malformed = true;
await assert.doesNotReject(get("csr-download-der").listeners.click());
assert.equal(downloads, 3, "malformed output downloaded"); assert.equal(get("csr-open-button").disabled, false); malformed = false;

get("csr-mode").value = "generate"; get("csr-mode").listeners.change(); newPassword(); held = true;
const pendingCreate = get("csr-create-button").listeners.click(); await new Promise(resolve => setImmediate(resolve));
document.hidden = true; docEvents.visibilitychange(); release(); await pendingCreate; document.hidden = false; held = false;
assert.equal(downloads, 3, "hidden page downloaded late key package"); assert.equal(output.bytes[0], 0); assert.equal(output.csr[0], 0);
assert.equal(get("csr-result").hidden, true); assert.equal(get("csr-create-button").disabled, false);
for (const name of ["blur", "pagehide", "hashchange"]) { get("csr-password").value = "synthetic-secret"; boundaries[name](); assert.equal(get("csr-password").value, ""); }
await get("csr-open-button").listeners.click();
csrOutputSize = 90 << 10;
await get("csr-download-pem").listeners.click(); assert.equal(downloads, 4, "bounded DER expansion was refused");
assert.equal(output.bytes[0], 0); assert.equal(output.csr[0], 0); assert.match(get("csr-status").textContent, /retain the original DER/);
csrOutputSize = (96 << 10) + 1;
await get("csr-download-pem").listeners.click(); assert.equal(downloads, 4, "oversized expanded CSR was downloaded");
assert.equal(output.bytes[0], 0); assert.equal(output.csr[0], 0); csrOutputSize = 0;
console.log("CSR UI names/password refusal, no partial output, public-only state, key/name differences, stale cancellation and buffer clearing passed.");
