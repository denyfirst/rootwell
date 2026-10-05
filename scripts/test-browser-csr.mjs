import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import { execFileSync, spawnSync } from "node:child_process";
import { createPrivateKey, createPublicKey, createHash } from "node:crypto";

const [wasmPath, runtimePath] = process.argv.slice(2);
if (!wasmPath || !runtimePath) throw new Error("usage: test-browser-csr.mjs <wasm> <wasm_exec.js>");
const openssl = process.platform === "win32" ? "C:/Program Files/Git/usr/bin/openssl.exe" : "openssl";
const version = execFileSync(openssl, ["version"], { encoding: "utf8" }).trim();
vm.runInThisContext(fs.readFileSync(runtimePath, "utf8"), { filename: runtimePath });
let ready; const signal = new Promise(resolve => { ready = resolve; }); globalThis.rootwellWasmReady = ready;
const go = new Go(); const module = await WebAssembly.instantiate(fs.readFileSync(wasmPath), go.importObject); go.run(module.instance);
await Promise.race([signal, new Promise((_, reject) => setTimeout(() => reject(new Error("CSR WASM initialization timeout")), 10000))]);
assert.equal(typeof rootwellCSROperate, "function");
const fixture = JSON.parse(execFileSync("go", ["run", "scripts/generate-browser-csr-fixture.go"], { encoding: "utf8" }));
const bytes = name => Uint8Array.from(Buffer.from(fixture[name], "base64"));
const csr = bytes("synthetic-request.csr"), key = bytes("synthetic-key.pem"), certificate = bytes("synthetic-certificate.pem"), different = bytes("synthetic-other-certificate.pem");
const empty = new Uint8Array(), encoder = new TextEncoder();
const params = { dns_names: ["demo.rootwell.invalid", "www.demo.rootwell.invalid"], ip_addresses: [], common_name: "", organization: "Synthetic test only", organizational_unit: "", country: "AZ", locality: "", province: "" };
function publicResult(operation, input, cert = empty, option = "") {
  const value = rootwellCSROperate(operation, input, cert, empty, option);
  assert.equal(typeof value, "string", "valid public CSR request failed");
  const response = JSON.parse(value); assert.equal(response.ok, true); return response.result;
}
function verifyOpenSSL(input, format) {
  const result = spawnSync(openssl, ["req", "-verify", "-noout", "-inform", format.toUpperCase()], { input: Buffer.from(input), encoding: "utf8" });
  assert.equal(result.status, 0, "OpenSSL CSR verification process failed");
  assert.match(result.stdout + result.stderr, /(?:self-signature )?verify OK/, "OpenSSL did not confirm the CSR signature");
}
const inspected = publicResult("inspect", csr);
assert.equal(inspected.signature_checked, true);
assert.equal(publicResult("match", csr, certificate, inspected.request_fingerprint).key_match, true);
const other = publicResult("match", csr, different, inspected.request_fingerprint);
assert.equal(other.key_match, false); assert.equal(other.trust_checked, false);
for (const format of ["pem", "der"]) {
  const output = rootwellCSROperate("key", key, empty, empty, JSON.stringify({ algorithm: "", params, format }));
  assert.equal(output.ok, true); assert.equal(output.result.format, format);
  verifyOpenSSL(output.result.bytes, format);
  const summary = JSON.parse(output.result.summary);
  const back = rootwellCSROperate("convert", output.result.bytes, empty, empty, summary.request_fingerprint + ":pem");
  assert.equal(back.ok, true); assert.equal(publicResult("inspect", back.result.bytes).request_fingerprint, summary.request_fingerprint);
  output.result.bytes.fill(0); output.result.csr.fill(0); back.result.bytes.fill(0); back.result.csr.fill(0);
}
const currentPassword = encoder.encode("synthetic-current-key-password-2026-4fbd");
const encrypted = Uint8Array.from(Buffer.from(createPrivateKey(Buffer.from(key)).export({ type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase: Buffer.from(currentPassword) })));
const signed = rootwellCSROperate("key", encrypted, empty, currentPassword, JSON.stringify({ algorithm: "", params, format: "pem" }));
assert.equal(signed.ok, true); verifyOpenSSL(signed.result.bytes, "pem");
assert.equal(rootwellCSROperate("key", encrypted, empty, empty, JSON.stringify({ algorithm: "", params, format: "pem" })).ok, false);
assert.equal(rootwellCSROperate("key", encrypted, empty, encoder.encode("wrong"), JSON.stringify({ algorithm: "", params, format: "pem" })).ok, false);
for (const algorithm of ["ec-p256", "rsa-2048"]) {
  const password = encoder.encode(fixture.password);
  const output = rootwellCSROperate("generate", empty, empty, password, JSON.stringify({ algorithm, params, format: "" }));
  assert.equal(output.ok, true); assert.equal(output.result.format, "zip");
  const unpacked = JSON.parse(execFileSync("go", ["run", "scripts/generate-browser-csr-fixture.go", "--read-zip"], { input: Buffer.from(output.result.bytes), encoding: "utf8" }));
  const encryptedKey = Buffer.from(unpacked["encrypted-private-key.pem"], "base64"), publicCSR = Buffer.from(unpacked["certificate-request.csr"], "base64");
  verifyOpenSSL(publicCSR, "pem");
  const privateKey = createPrivateKey({ key: encryptedKey, passphrase: Buffer.from(password) });
  const publicDER = createPublicKey(privateKey).export({ type: "spki", format: "der" });
  const requestPublic = execFileSync(openssl, ["req", "-pubkey", "-noout"], { input: publicCSR });
  assert.deepEqual(createPublicKey(requestPublic).export({ type: "spki", format: "der" }), publicDER, "OpenSSL CSR public key differs from Node-decoded private key");
  const fingerprint = createHash("sha256").update(publicDER).digest("hex").toUpperCase().match(/../g).join(":");
  assert.equal(JSON.parse(output.result.summary).public_fingerprint, fingerprint, "Node-parsed new key differs from CSR");
  assert.deepEqual(Buffer.from(output.result.csr), publicCSR);
  assert.throws(() => createPrivateKey({ key: encryptedKey, passphrase: "wrong" }));
  encryptedKey.fill(0); publicCSR.fill(0); password.fill(0); output.result.bytes.fill(0); output.result.csr.fill(0);
}
const damaged = bytes("synthetic-request.der"); damaged[damaged.length - 1] ^= 1;
for (const invalid of [damaged, new Uint8Array(65537), new Uint8Array(), key]) assert.equal(rootwellCSROperate("inspect", invalid, empty, empty, "").ok, false);
assert.equal(rootwellCSROperate("convert", csr, empty, empty, "AA:".repeat(31) + "AA:pem").ok, false);
assert.equal(rootwellCSROperate("match", csr, certificate, empty, "AA:".repeat(31) + "AA").ok, false);
assert.equal(rootwellCSROperate("generate", empty, empty, encoder.encode("short"), JSON.stringify({ algorithm: "ec-p256", params, format: "" })).ok, false);
assert.equal(rootwellCSROperate("generate", empty, empty, encoder.encode(fixture.password), JSON.stringify({ algorithm: "ec-p256", params, format: "", unknown: true })).ok, false);
for (const input of [csr, key, certificate, different, encrypted, currentPassword, signed.result.bytes, signed.result.csr, damaged]) input.fill(0);
console.log("CSR WASM generation, encrypted input, signed-request conversion, key comparison and independent Node/" + version + " verification passed.");
