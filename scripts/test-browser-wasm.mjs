import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const [wasmPath, runtimePath, certificatePath, bundlePath] = process.argv.slice(2);
if (!wasmPath || !runtimePath || !certificatePath || !bundlePath) {
  throw new Error("usage: node test-browser-wasm.mjs <wasm> <wasm_exec.js> <certificate> <bundle>");
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
assert.equal(typeof globalThis.rootwellExplore, "function");
assert.equal(globalThis.rootwellInspectMaxBytes, 16 * 1024 * 1024);

const certificate = new Uint8Array(fs.readFileSync(certificatePath));
const explored = JSON.parse(globalThis.rootwellExplore(certificate));
const success = JSON.parse(globalThis.rootwellInspect(certificate));
certificate.fill(0);
assert.equal(explored.schema_version, "rootwell.browser.explore.v1");
assert.equal(explored.ok, true);
assert.equal(explored.error, null);
assert.equal(explored.result.count, 1);
assert.equal(explored.result.verification, "not-performed");
assert.equal(explored.result.trust_anchor, "not-selected");
assert.equal(explored.result.certificates[0].subject, "CN=workbench.rootwell.invalid,O=Rootwell non-production demo");

const bundle = new Uint8Array(fs.readFileSync(bundlePath));
const bundleResponse = JSON.parse(globalThis.rootwellExplore(bundle));
bundle.fill(0);
assert.equal(bundleResponse.ok, true);
assert.equal(bundleResponse.result.count, 2);
assert.equal(bundleResponse.result.verification, "not-performed");
assert.equal(bundleResponse.result.trust_anchor, "not-selected");
assert.equal(bundleResponse.result.certificates[1].subject, "CN=second.rootwell.invalid,O=Rootwell non-production demo");
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

const secret = new TextEncoder().encode("-----BEGIN PRIVATE KEY-----\nsecret-marker\n-----END PRIVATE KEY-----");
const secretResponseText = globalThis.rootwellExplore(secret);
secret.fill(0);
const secretResponse = JSON.parse(secretResponseText);
assert.equal(secretResponse.ok, false);
assert.equal(secretResponse.result, null);
assert.equal(secretResponse.error.code, "unsupported-public-bundle");
assert.equal(secretResponseText.includes("secret-marker"), false);

const duplicateBundle = new Uint8Array(fs.readFileSync(certificatePath));
const duplicateInput = new Uint8Array(duplicateBundle.length * 2);
duplicateInput.set(duplicateBundle);
duplicateInput.set(duplicateBundle, duplicateBundle.length);
duplicateBundle.fill(0);
const duplicateResponse = JSON.parse(globalThis.rootwellExplore(duplicateInput));
duplicateInput.fill(0);
assert.equal(duplicateResponse.ok, false);
assert.equal(duplicateResponse.result, null);
assert.equal(duplicateResponse.error.code, "duplicate-certificate");

const oversized = new Uint8Array(globalThis.rootwellInspectMaxBytes + 1);
const oversizedResponse = JSON.parse(globalThis.rootwellInspect(oversized));
oversized.fill(0);
assert.equal(oversizedResponse.ok, false);
assert.equal(oversizedResponse.error.code, "input-too-large");

const oversizedExplore = new Uint8Array(globalThis.rootwellInspectMaxBytes + 1);
const oversizedExploreResponse = JSON.parse(globalThis.rootwellExplore(oversizedExplore));
oversizedExplore.fill(0);
assert.equal(oversizedExploreResponse.ok, false);
assert.equal(oversizedExploreResponse.error.code, "input-too-large");

const invalidRequest = JSON.parse(globalThis.rootwellInspect("not a byte array"));
assert.equal(invalidRequest.ok, false);
assert.equal(invalidRequest.error.code, "invalid-browser-request");

const invalidExploreRequest = JSON.parse(globalThis.rootwellExplore("not a byte array"));
assert.equal(invalidExploreRequest.ok, false);
assert.equal(invalidExploreRequest.error.code, "invalid-browser-request");

console.log("Rootwell browser WebAssembly integration passed.");
void execution;
process.exit(0);
