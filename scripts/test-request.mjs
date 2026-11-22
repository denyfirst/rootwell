import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createPrivateKey } from "node:crypto";
import fs from "node:fs";
import vm from "node:vm";

// Request, driven with the real browser engine: names typed or pasted become
// chips, a new key is made and locked with the person's password, or their
// own key signs the request. The worker client is replaced by a direct engine
// call; the page script, its helpers and the engine are the real ones.
const [wasmPath, runtimePath] = process.argv.slice(2);
if (!wasmPath || !runtimePath) throw new Error("usage: node test-request.mjs <wasm> <wasm_exec.js>");
const read = (name) => fs.readFileSync(new URL("../web/workbench/" + name, import.meta.url), "utf8");
const uiSource = read("ui.js");
const source = read("request.js");
const html = read("request.html");
for (const forbidden of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "fetch(", "XMLHttpRequest", "localStorage", "sessionStorage", "indexedDB"]) {
  assert.ok(!source.includes(forbidden), `request.js must not use ${forbidden}`);
}
assert.match(html, /<a class="nav-item" href="\/request" aria-current="page">/);
for (const script of ["/wasm_exec.js", "/wasm-loader.js", "/ui.js", "/csr-worker-client.js", "/request.js"]) {
  assert.ok(html.includes(`<script src="${script}" defer></script>`), `request.html loads ${script}`);
}
assert.doesNotMatch(html, /style="|demo|example\.com/i, "no inline style and no demo material");
const radios = [...html.matchAll(/<input type="radio" name="request-key" value="([a-z0-9-]+)"( checked)?>/g)].map((m) => m[1] + (m[2] ? "*" : ""));
assert.deepEqual(radios, ["ec-p256*", "rsa-2048", "own"]);

vm.runInThisContext(fs.readFileSync(runtimePath, "utf8"), { filename: runtimePath });
let started;
const ready = new Promise((resolve) => { started = resolve; });
globalThis.rootwellWasmReady = started;
const go = new Go();
const instance = await WebAssembly.instantiate(fs.readFileSync(wasmPath), go.importObject);
go.run(instance.instance);
await Promise.race([ready, new Promise((_, reject) => setTimeout(() => reject(new Error("WASM timeout")), 10000))]);
const fixture = JSON.parse(execFileSync("go", ["run", "./scripts/generate-convert-fixture.go"], { encoding: "utf8" }));
const bytesOf = (name) => Uint8Array.from(Buffer.from(fixture[name], "base64"));
const text = (bytes) => new TextDecoder().decode(bytes);
const inspectCSR = (bytes) => JSON.parse(rootwellCSROperate("inspect", bytes, new Uint8Array(), new Uint8Array(), "")).result;

const copy = (bytes) => bytes.slice();
const calls = [];
const win = {
  rootwellWorkbenchReady: Promise.resolve({ module: {} }),
  rootwellCSRWorker: { run: async (module, operation, input, certificate, password, option) => {
    calls.push({ operation, option: JSON.parse(option) });
    return rootwellCSROperate(operation, copy(input), copy(certificate), copy(password), option);
  } },
  listeners: {},
  addEventListener(name, fn) { this.listeners[name] = fn; },
};

class Node {
  constructor(tag) {
    Object.assign(this, { tag, children: [], textContent: "", className: "", attributes: {}, hidden: false, disabled: false,
      value: "", type: "", checked: false, placeholder: "", files: null, listeners: {}, download: "" });
    this.classList = { add: (c) => { this.className = (this.className + " " + c).trim(); } };
  }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  focus() {}
  remove() {}
  click() { if (this.tag === "a") downloads.push({ name: this.download, blob: lastBlob }); else this.listeners.click?.(); }
  all() { return [this, ...this.children.flatMap((c) => c.all())]; }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  querySelectorAll(selector) {
    const inputs = this.all().filter((n) => n !== this && n.tag === "input");
    return selector === "input:checked" ? inputs.filter((n) => n.checked) : inputs;
  }
  text() { return [this.textContent, ...this.children.map((c) => c.text())].join(" ").replace(/\s+/g, " ").trim(); }
}
const ids = {};
const inputs = new Set(["request-name", "request-secret", "request-own-file", "request-own-password", "request-organization", "request-city", "request-state", "request-country"]);
const $ = (id) => (ids[id] ??= new Node(inputs.has(id) ? "input" : "div"));
for (const value of ["ec-p256", "rsa-2048", "own"]) {
  const radio = new Node("input");
  Object.assign(radio, { type: "radio", value, checked: value === "ec-p256" });
  $("request-keys").appendChild(new Node("label")).appendChild(radio);
}
const document = { getElementById: $, createElement: (tag) => new Node(tag), createElementNS: (_, tag) => new Node(tag), body: new Node("body") };
const downloads = [];
let lastBlob = null;
class TestURL extends URL {
  static createObjectURL(blob) { lastBlob = blob; return "blob:test"; }
  static revokeObjectURL() {}
}
const timers = [];
const navigator_ = { clipboard: { writeText: async () => {} } };
const load = (src, filename) => vm.runInThisContext("(function (globalThis, document, setTimeout, clearTimeout, navigator, URL) {" + src + "\n})", { filename })(
  win, document, (fn, ms) => { timers.push({ fn, ms }); return timers.length; }, () => {}, navigator_, TestURL);
load(uiSource, "ui.js");
load(source, "request.js");

const settle = async () => { for (let i = 0; i < 40; i++) await new Promise((r) => setImmediate(r)); };
const chips = () => $("request-names").children.filter((n) => n.className === "chip").map((n) => n.textContent);
const type = (value) => { $("request-name").value = value; $("request-name").listeners.input(); };
const key = (name) => { let stopped = false; $("request-name").listeners.keydown({ key: name, preventDefault() { stopped = true; } }); return stopped; };
const pickKey = (value) => {
  for (const radio of $("request-keys").querySelectorAll("input")) radio.checked = radio.value === value;
  $("request-keys").querySelectorAll("input").find((r) => r.value === value).listeners.change();
};
const submit = async () => { await $("request-form").listeners.submit({ preventDefault() {} }); await settle(); };
const statusText = () => $("request-status").text();
// The engine's ZIP streams each file, so sizes live in the central directory.
function unzip(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const end = bytes.byteLength - 22;
  assert.equal(view.getUint32(end, true), 0x06054b50, "end of central directory");
  let at = view.getUint32(end + 16, true);
  const files = {};
  for (let i = 0; i < view.getUint16(end + 10, true); i++) {
    const size = view.getUint32(at + 20, true), nameLength = view.getUint16(at + 28, true), offset = view.getUint32(at + 42, true);
    const name = text(bytes.subarray(at + 46, at + 46 + nameLength));
    const start = offset + 30 + view.getUint16(offset + 26, true) + view.getUint16(offset + 28, true);
    files[name] = bytes.slice(start, start + size);
    at += 46 + nameLength + view.getUint16(at + 30, true) + view.getUint16(at + 32, true);
  }
  return files;
}

// Names: pasted lists split, schemes, paths and ports drop, international
// names take their xn-- form, repeats and bad names are left out.
assert.equal($("request-name").placeholder, "Type a name, press Enter");
type("Shop.Test, www.shop.test https://api.shop.test:8443/x bad_name! 192.0.2.10 bücher.test shop.test");
assert.deepEqual(chips(), ["shop.test", "www.shop.test", "api.shop.test", "192.0.2.10", "xn--bcher-kva.test"]);
assert.match(statusText(), /bad_name! is not a name a certificate can hold/);
assert.equal($("request-name").value, "");
$("request-name").value = "*.shop.test";
assert.equal(key("Enter"), true, "Enter adds the typed name instead of sending the form");
assert.equal(chips().at(-1), "*.shop.test");
assert.equal(statusText(), "", "a good name clears the note");
assert.equal(key("Enter"), false, "Enter on an empty field sends the form");
assert.equal(key("Backspace"), false);
assert.deepEqual(chips(), ["shop.test", "www.shop.test", "api.shop.test", "192.0.2.10", "xn--bcher-kva.test"]);
$("request-names").children.find((n) => n.textContent === "api.shop.test").children[0].listeners.click();
assert.deepEqual(chips(), ["shop.test", "www.shop.test", "192.0.2.10", "xn--bcher-kva.test"]);
type(Array.from({ length: 40 }, (_, i) => "n" + i + ".shop.test").join(" "));
assert.match(statusText(), /up to 32 names and 8 addresses/);
assert.equal(chips().filter((n) => !/^\d/.test(n)).length, 32);
for (let i = 0; i < 30; i++) key("Backspace");
assert.equal(chips().length, 3);

// A new key needs a strong password; Generate makes one.
assert.equal($("request-own").hidden, true);
assert.equal($("request-secret-row").hidden, false);
$("request-secret").value = "short";
await submit();
assert.match(statusText(), /20 to 128/);
assert.equal(calls.length, 0);
$("request-country").value = "Germany";
$("request-generate").listeners.click();
await submit();
assert.match(statusText(), /two letters/);
$("request-country").value = "de";
$("request-organization").value = "  Synthetic Shop  ";
const password = $("request-secret").value;
assert.match(password, /^[A-HJ-NP-Za-km-z2-9]{24}$/);
await submit();
assert.equal(statusText(), "");
assert.deepEqual(calls.at(-1), { operation: "generate", option: { algorithm: "ec-p256", format: "", params: {
  dns_names: ["shop.test", "www.shop.test"], ip_addresses: ["192.0.2.10"], common_name: "", organization: "Synthetic Shop",
  organizational_unit: "", country: "DE", locality: "", province: "" } } });
assert.equal($("request-result").hidden, false);
assert.equal($("request-result-title").textContent, "Request ready for shop.test");
assert.match($("request-facts").text(), /Works for shop\.test, www\.shop\.test, 192\.0\.2\.10 Key ECDSA P-256/);
const rows = $("request-files").children;
assert.deepEqual(rows.map((r) => r.children[1].children[0].textContent), ["shop.test-key-and-request.zip", "shop.test.csr"]);
assert.equal(rows[0].children[2].className, "btn btn-sm", "the key comes first and stands out");
rows[0].children[2].listeners.click();
rows[1].children[2].listeners.click();
assert.deepEqual(downloads.map((d) => d.name + " " + d.blob.type), ["shop.test-key-and-request.zip application/zip", "shop.test.csr application/pkcs10"]);
{
  const files = unzip(new Uint8Array(await downloads[0].blob.arrayBuffer()));
  assert.deepEqual(Object.keys(files), ["encrypted-private-key.pem", "certificate-request.csr"]);
  const privateKey = createPrivateKey({ key: Buffer.from(files["encrypted-private-key.pem"]), passphrase: password });
  assert.equal(privateKey.asymmetricKeyType, "ec");
  const csr = new Uint8Array(await downloads[1].blob.arrayBuffer());
  assert.match(text(csr), /^-----BEGIN CERTIFICATE REQUEST-----\n/);
  assert.deepEqual(Buffer.from(files["certificate-request.csr"]), Buffer.from(csr));
  const summary = inspectCSR(csr);
  assert.deepEqual(summary.dns_names, ["shop.test", "www.shop.test"]);
  assert.deepEqual(summary.ip_addresses, ["192.0.2.10"]);
  assert.match(summary.subject, /O=Synthetic Shop/);
  assert.match(summary.subject, /C=DE/);
}

// Your own key: protected keys need their password; only the request comes out.
pickKey("own");
assert.equal($("request-own").hidden, false);
assert.equal($("request-secret-row").hidden, true);
await submit();
assert.match(statusText(), /Choose your key file/);
$("request-own-file").files = [new File([bytesOf("locked_key")], "shop.test.key")];
$("request-own-password").value = "not-the-password";
await submit();
assert.match(statusText(), /Check the key file and its password/);
assert.equal($("request-result").hidden, true, "a failed request shows nothing old");
assert.equal($("request-own-password").value, "", "the key password field is emptied");
$("request-own-password").value = fixture.key_password;
await submit();
assert.equal(calls.at(-1).operation, "key");
assert.equal(calls.at(-1).option.format, "pem");
assert.deepEqual($("request-files").children.map((r) => r.children[1].children[0].textContent + " " + r.children[2].className), ["shop.test.csr btn btn-sm"]);
$("request-files").children[0].children[2].listeners.click();
{
  const csr = new Uint8Array(await downloads.at(-1).blob.arrayBuffer());
  const keyFingerprint = JSON.parse(rootwellPrivateInspect(bytesOf("locked_key"), new TextEncoder().encode(fixture.key_password))).result.public_fingerprint;
  assert.equal(inspectCSR(csr).public_fingerprint, keyFingerprint, "the request carries the person's own key");
}

// Nothing to name yet.
for (let i = 0; i < 5; i++) key("Backspace");
await submit();
assert.match(statusText(), /Add the name the certificate is for/);

// Ten idle minutes, or leaving the page, forget the request and its key.
type("shop.test");
pickKey("ec-p256");
$("request-generate").listeners.click();
await submit();
assert.equal($("request-result").hidden, false);
timers.filter((t) => t.ms === 10 * 60 * 1000).pop().fn();
assert.equal($("request-result").hidden, true);
assert.equal($("request-secret").value, "");
assert.match(statusText(), /cleared after ten idle minutes/);
$("request-generate").listeners.click();
await submit();
win.listeners.pagehide();
assert.equal($("request-result").hidden, true);
assert.equal($("request-files").children.length, 0);
assert.equal($("request-secret").value, "");

console.log("Request makes a CSR with a new locked key or the person's own key, with the real engine.");
