import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
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
assert.equal(typeof globalThis.rootwellAnalyze, "function");
assert.equal(typeof globalThis.rootwellExportBundle, "function");
assert.equal(typeof globalThis.rootwellVerifySimple, "function");
assert.equal(typeof globalThis.rootwellVerifyExplicit, "function");
assert.equal(typeof globalThis.rootwellExportVerifiedSimple, "function");
assert.equal(typeof globalThis.rootwellExportVerifiedExplicit, "function");
assert.equal(typeof globalThis.rootwellExport, "function");
assert.equal(globalThis.rootwellInspectMaxBytes, 16 * 1024 * 1024);

const verifyFixture = JSON.parse(execFileSync("go", ["run", "./scripts/generate-browser-verify-fixture.go"], { encoding: "utf8" }));
const encodePublic = (value) => new TextEncoder().encode(value);
const verifySource = encodePublic(verifyFixture.source);
const verifyLeaf = encodePublic(verifyFixture.leaf);
const verifyIntermediate = encodePublic(verifyFixture.intermediate);
const verifyRoot = encodePublic(verifyFixture.root);
const simpleVerification = JSON.parse(globalThis.rootwellVerifySimple(
  [verifySource], verifyRoot, verifyFixture.hostname, verifyFixture.evaluated_at));
const explicitVerification = JSON.parse(globalThis.rootwellVerifyExplicit(
  verifyLeaf, verifyIntermediate, verifyRoot, verifyFixture.hostname, verifyFixture.evaluated_at));
assert.equal(simpleVerification.ok, true, JSON.stringify(simpleVerification.error));
assert.equal(explicitVerification.ok, true, JSON.stringify(explicitVerification.error));
assert.equal(simpleVerification.result.trust_source, "explicit-file");
assert.equal(simpleVerification.result.root_pin, "not-provided");
assert.equal(simpleVerification.result.ignored_source_roots, 1);
assert.equal(simpleVerification.result.chain.length, 3);
assert.deepEqual(simpleVerification.result.chain, explicitVerification.result.chain);
const noTrust = JSON.parse(globalThis.rootwellVerifySimple(
  [verifySource], new Uint8Array(0), verifyFixture.hostname, verifyFixture.evaluated_at));
assert.equal(noTrust.ok, false);
assert.equal(noTrust.result, null);
const wrongHostname = JSON.parse(globalThis.rootwellVerifyExplicit(
  verifyLeaf, verifyIntermediate, verifyRoot, "other.rootwell.invalid", verifyFixture.evaluated_at));
assert.equal(wrongHostname.ok, false);
assert.equal(wrongHostname.error.code, "hostname-mismatch");
const invalidTime = JSON.parse(globalThis.rootwellVerifyExplicit(
  verifyLeaf, verifyIntermediate, verifyRoot, verifyFixture.hostname, "yesterday"));
assert.equal(invalidTime.ok, false);
assert.equal(invalidTime.error.code, "invalid-time");
const secretSource = encodePublic("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n");
const secretVerification = JSON.parse(globalThis.rootwellVerifySimple(
  [secretSource], verifyRoot, verifyFixture.hostname, verifyFixture.evaluated_at));
assert.equal(secretVerification.ok, false);
assert.equal(secretVerification.error.code, "invalid-public-source");
const verifiedFingerprints = simpleVerification.result.chain.map((member) => member.SHA256Fingerprint);
const rootFingerprint = verifiedFingerprints.at(-1);
const pinnedSimple = JSON.parse(globalThis.rootwellVerifySimple(
  [verifySource], verifyRoot, verifyFixture.hostname, verifyFixture.evaluated_at, rootFingerprint));
const pinnedExplicit = JSON.parse(globalThis.rootwellVerifyExplicit(
  verifyLeaf, verifyIntermediate, verifyRoot, verifyFixture.hostname, verifyFixture.evaluated_at,
  rootFingerprint.replaceAll(":", "").toLowerCase()));
assert.equal(pinnedSimple.ok, true);
assert.equal(pinnedSimple.result.root_pin, "matched");
assert.equal(pinnedExplicit.ok, true);
assert.equal(pinnedExplicit.result.root_pin, "matched");
for (const pin of ["00".repeat(32), rootFingerprint.slice(0, -3), rootFingerprint + ":00"]) {
  const refused = JSON.parse(globalThis.rootwellVerifySimple(
    [verifySource], verifyRoot, verifyFixture.hostname, verifyFixture.evaluated_at, pin));
  assert.equal(refused.ok, false);
  assert.equal(refused.result, null);
  assert.equal(refused.error.code, pin.length === 64 ? "root-pin-mismatch" : pin.length > 95 ? "invalid-browser-request" : "invalid-root-pin");
}
const simpleFullchain = globalThis.rootwellExportVerifiedSimple(
  [verifySource], verifyRoot, verifyFixture.hostname, verifyFixture.evaluated_at, verifiedFingerprints);
const explicitFullchain = globalThis.rootwellExportVerifiedExplicit(
  verifyLeaf, verifyIntermediate, verifyRoot, verifyFixture.hostname, verifyFixture.evaluated_at, verifiedFingerprints);
assert.equal(simpleFullchain.ok, true, simpleFullchain.error);
assert.equal(explicitFullchain.ok, true, explicitFullchain.error);
assert.equal(simpleFullchain.result.trust_source, "explicit-file");
assert.equal(simpleFullchain.result.root_included, false);
assert.deepEqual(Array.from(simpleFullchain.result.fingerprints), verifiedFingerprints.slice(0, -1));
assert.deepEqual(Array.from(simpleFullchain.result.bytes), Array.from(explicitFullchain.result.bytes));
const fullchainExploration = JSON.parse(globalThis.rootwellExplore(simpleFullchain.result.bytes));
assert.equal(fullchainExploration.ok, true);
assert.deepEqual(fullchainExploration.result.certificates.map((member) => member.sha256), verifiedFingerprints.slice(0, -1));
const changedFullchain = globalThis.rootwellExportVerifiedSimple(
  [verifySource], verifyRoot, verifyFixture.hostname, verifyFixture.evaluated_at,
  [verifiedFingerprints[0], verifiedFingerprints[2], verifiedFingerprints[1]]);
assert.equal(changedFullchain.ok, false);
assert.equal(changedFullchain.result, null);
assert.equal(changedFullchain.error, "changed-verification");
const untrustedFullchain = globalThis.rootwellExportVerifiedSimple(
  [verifySource], new Uint8Array(0), verifyFixture.hostname, verifyFixture.evaluated_at, verifiedFingerprints);
assert.equal(untrustedFullchain.ok, false);
assert.equal(untrustedFullchain.result, null);
simpleFullchain.result.bytes.fill(0);
explicitFullchain.result.bytes.fill(0);
secretSource.fill(0);
verifySource.fill(0);
verifyLeaf.fill(0);
verifyIntermediate.fill(0);
verifyRoot.fill(0);

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
assert.match(explored.result.certificates[0].not_before, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
assert.match(explored.result.certificates[0].not_after, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);

const bundle = new Uint8Array(fs.readFileSync(bundlePath));
const bundleResponse = JSON.parse(globalThis.rootwellExplore(bundle));
const analyzed = JSON.parse(globalThis.rootwellAnalyze([bundle]));
assert.equal(analyzed.ok, true);
assert.equal(analyzed.result.verification, "not-performed");
assert.equal(analyzed.result.trust_anchor, "not-selected");
assert.equal(analyzed.result.certificates.length, 2);
assert.equal(analyzed.result.certificates[0].sha256, bundleResponse.result.certificates[0].sha256);
assert.equal(bundleResponse.ok, true);
assert.equal(bundleResponse.result.count, 2);
assert.equal(bundleResponse.result.verification, "not-performed");
assert.equal(bundleResponse.result.trust_anchor, "not-selected");
assert.equal(bundleResponse.result.certificates[1].subject, "CN=second.rootwell.invalid,O=Rootwell non-production demo");
const secondFingerprint = bundleResponse.result.certificates[1].sha256;
const expectedFingerprints = bundleResponse.result.certificates.map((item) => item.sha256);
const combined = globalThis.rootwellExportBundle([bundle], expectedFingerprints, expectedFingerprints);
assert.equal(combined.schema_version, "rootwell.browser.bundle-export.v1");
assert.equal(combined.ok, true, combined.error);
assert.match(combined.result.filename, /^rootwell-public-bundle-[0-9a-f]{32}\.pem$/);
assert.deepEqual(Array.from(combined.result.fingerprints), expectedFingerprints);
const combinedParsed = JSON.parse(globalThis.rootwellExplore(combined.result.bytes));
assert.equal(combinedParsed.ok, true);
assert.deepEqual(combinedParsed.result.certificates.map((item) => item.sha256), expectedFingerprints);
combined.result.bytes.fill(0);
const changedBundle = globalThis.rootwellExportBundle([bundle], [secondFingerprint, expectedFingerprints[0]], [secondFingerprint]);
assert.equal(changedBundle.ok, false);
assert.equal(changedBundle.error, "changed-public-source");
for (const format of ["pem", "der"]) {
  const exported = globalThis.rootwellExport(bundle, secondFingerprint, format);
  assert.equal(exported.schema_version, "rootwell.browser.export.v1");
  assert.equal(exported.ok, true);
  assert.equal(exported.error, null);
  assert.equal(exported.result.encoding, format);
  assert.equal(exported.result.fingerprint, secondFingerprint);
  const fingerprintPrefix = secondFingerprint.replaceAll(":", "").slice(0, 16).toLowerCase();
  assert.match(exported.result.filename, new RegExp(`^rootwell-public-${fingerprintPrefix}-[0-9a-f]{32}\\.${format}$`));
  assert.equal(exported.result.bytes instanceof Uint8Array, true);
  const reparsed = JSON.parse(globalThis.rootwellExplore(exported.result.bytes));
  assert.equal(reparsed.ok, true);
  assert.equal(reparsed.result.count, 1);
  assert.equal(reparsed.result.certificates[0].sha256, secondFingerprint);
  exported.result.bytes.fill(0);
}
const missingExport = globalThis.rootwellExport(bundle, "00:".repeat(31) + "00", "pem");
assert.equal(missingExport.ok, false);
assert.equal(missingExport.result, null);
assert.equal(missingExport.error, "certificate-not-found");
const unsafeFormatExport = globalThis.rootwellExport(bundle, secondFingerprint, "pfx");
assert.equal(unsafeFormatExport.ok, false);
assert.equal(unsafeFormatExport.error, "invalid-browser-request");
bundle.fill(0);
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
const secretExport = globalThis.rootwellExport(secret, secondFingerprint, "pem");
const secretBundleExport = globalThis.rootwellExportBundle([secret], [secondFingerprint], [secondFingerprint]);
secret.fill(0);
const secretResponse = JSON.parse(secretResponseText);
assert.equal(secretResponse.ok, false);
assert.equal(secretResponse.result, null);
assert.equal(secretResponse.error.code, "unsupported-public-bundle");
assert.equal(secretResponseText.includes("secret-marker"), false);
assert.equal(secretExport.ok, false);
assert.equal(secretExport.result, null);
assert.equal(secretExport.error, "invalid-public-source");
assert.equal(secretBundleExport.ok, false);
assert.equal(secretBundleExport.result, null);
assert.equal(secretBundleExport.error, "invalid-public-source");

const duplicateBundle = new Uint8Array(fs.readFileSync(certificatePath));
const duplicateInput = new Uint8Array(duplicateBundle.length * 2);
duplicateInput.set(duplicateBundle);
duplicateInput.set(duplicateBundle, duplicateBundle.length);
duplicateBundle.fill(0);
const duplicateResponse = JSON.parse(globalThis.rootwellExplore(duplicateInput));
const duplicateExport = globalThis.rootwellExport(duplicateInput, secondFingerprint, "der");
const duplicateBundleExport = globalThis.rootwellExportBundle([duplicateInput], [secondFingerprint], [secondFingerprint]);
duplicateInput.fill(0);
assert.equal(duplicateResponse.ok, false);
assert.equal(duplicateResponse.result, null);
assert.equal(duplicateResponse.error.code, "duplicate-certificate");
assert.equal(duplicateExport.ok, false);
assert.equal(duplicateExport.error, "invalid-public-source");
assert.equal(duplicateBundleExport.ok, false);
assert.equal(duplicateBundleExport.result, null);
assert.equal(duplicateBundleExport.error, "invalid-public-source");

const oversized = new Uint8Array(globalThis.rootwellInspectMaxBytes + 1);
const oversizedResponse = JSON.parse(globalThis.rootwellInspect(oversized));
oversized.fill(0);
assert.equal(oversizedResponse.ok, false);
assert.equal(oversizedResponse.error.code, "input-too-large");

const oversizedExplore = new Uint8Array(globalThis.rootwellInspectMaxBytes + 1);
const oversizedExploreResponse = JSON.parse(globalThis.rootwellExplore(oversizedExplore));
const oversizedExport = globalThis.rootwellExport(oversizedExplore, secondFingerprint, "pem");
const oversizedBundleExport = globalThis.rootwellExportBundle([oversizedExplore], [secondFingerprint], [secondFingerprint]);
oversizedExplore.fill(0);
assert.equal(oversizedExploreResponse.ok, false);
assert.equal(oversizedExploreResponse.error.code, "input-too-large");
assert.equal(oversizedExport.ok, false);
assert.equal(oversizedExport.error, "input-too-large");
assert.equal(oversizedBundleExport.error, "input-too-large");

const invalidRequest = JSON.parse(globalThis.rootwellInspect("not a byte array"));
assert.equal(invalidRequest.ok, false);
assert.equal(invalidRequest.error.code, "invalid-browser-request");

const invalidExploreRequest = JSON.parse(globalThis.rootwellExplore("not a byte array"));
assert.equal(invalidExploreRequest.ok, false);
assert.equal(invalidExploreRequest.error.code, "invalid-browser-request");
const invalidExportRequest = globalThis.rootwellExport("not a byte array", secondFingerprint, "pem");
assert.equal(invalidExportRequest.ok, false);
assert.equal(invalidExportRequest.error, "invalid-browser-request");
const invalidBundleRequest = globalThis.rootwellExportBundle(["not a byte array"], [secondFingerprint], [secondFingerprint]);
assert.equal(invalidBundleRequest.ok, false);
assert.equal(invalidBundleRequest.error, "invalid-browser-request");

console.log("Rootwell browser WebAssembly integration passed.");
void execution;
process.exit(0);
