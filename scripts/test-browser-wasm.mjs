import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const [wasmPath, runtimePath, certificatePath] = process.argv.slice(2);
if (!wasmPath || !runtimePath || !certificatePath) {
  throw new Error("usage: node test-browser-wasm.mjs <wasm> <wasm_exec.js> <certificate>");
}

const runtimeSource = fs.readFileSync(runtimePath, "utf8");
vm.runInThisContext(runtimeSource, { filename: runtimePath });
assert.equal(typeof globalThis.Go, "function", "Go browser runtime did not initialize");

let resolveReady;
const ready = new Promise(function (resolve) {
  resolveReady = resolve;
});
globalThis.rootwellWasmReady = resolveReady;

const go = new globalThis.Go();
const wasm = fs.readFileSync(wasmPath);
const module = await WebAssembly.instantiate(wasm, go.importObject);
const execution = go.run(module.instance);

await Promise.race([
  ready,
  new Promise(function (_, reject) {
    setTimeout(function () { reject(new Error("Rootwell browser engine readiness timed out")); }, 5000);
  })
]);

assert.equal(typeof globalThis.rootwellInspect, "function");
assert.equal(globalThis.rootwellInspectMaxBytes, 16 * 1024 * 1024);

const certificate = new Uint8Array(fs.readFileSync(certificatePath));
const success = JSON.parse(globalThis.rootwellInspect(certificate));
certificate.fill(0);
assert.equal(success.schema_version, "rootwell.browser.inspect.v1");
assert.equal(success.ok, true);
assert.equal(success.error, null);
assert.equal(success.result.schema_version, "rootwell.inspect.x509.v1");
assert.equal(success.result.subject, "CN=workbench.rootwell.invalid,O=Rootwell non-production demo");
assert.deepEqual(success.result.subject_alternative_names.dns, [
  "workbench.rootwell.invalid",
  "api.rootwell.invalid"
]);

const marker = "malformed-sensitive-marker";
const malformed = new TextEncoder().encode(marker);
const refusalText = globalThis.rootwellInspect(malformed);
malformed.fill(0);
const refusal = JSON.parse(refusalText);
assert.equal(refusal.ok, false);
assert.equal(refusal.result, null);
assert.equal(refusal.error.code, "invalid-certificate");
assert.equal(refusalText.includes(marker), false, "browser failure echoed input");

const oversized = new Uint8Array(globalThis.rootwellInspectMaxBytes + 1);
const oversizedResponse = JSON.parse(globalThis.rootwellInspect(oversized));
oversized.fill(0);
assert.equal(oversizedResponse.ok, false);
assert.equal(oversizedResponse.error.code, "input-too-large");

const invalidRequest = JSON.parse(globalThis.rootwellInspect("not a byte array"));
assert.equal(invalidRequest.ok, false);
assert.equal(invalidRequest.error.code, "invalid-browser-request");

console.log("Rootwell browser WebAssembly integration passed.");
void execution;
process.exit(0);
