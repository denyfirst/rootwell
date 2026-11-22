import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createPrivateKey } from "node:crypto";
import fs from "node:fs";
import vm from "node:vm";
import zlib from "node:zlib";

// Convert, driven end to end with the real browser engine: a PFX, a
// certificate with its key, a certificate alone, and keys alone, each turned
// into every format the page offers. The worker clients are replaced by direct
// engine calls; the page script, its helpers and the engine are the real ones.
const [wasmPath, runtimePath] = process.argv.slice(2);
if (!wasmPath || !runtimePath) throw new Error("usage: node test-convert.mjs <wasm> <wasm_exec.js>");
const read = (name) => fs.readFileSync(new URL("../web/workbench/" + name, import.meta.url), "utf8");
const uiSource = read("ui.js");
const source = read("convert.js");
const html = read("convert.html");

for (const [name, text] of [["convert.js", source], ["ui.js", uiSource]]) {
  for (const forbidden of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "fetch(", "XMLHttpRequest", "localStorage", "sessionStorage", "indexedDB"]) {
    assert.ok(!text.includes(forbidden), `${name} must not use ${forbidden}`);
  }
}
assert.match(html, /<link rel="stylesheet" href="\/rootwell\.css">/);
assert.match(html, /<a class="nav-item" href="\/convert" aria-current="page">/);
for (const script of ["/wasm_exec.js", "/wasm-loader.js", "/ui.js", "/private-worker-client.js", "/pfx-worker-client.js", "/csr-worker-client.js", "/convert.js"]) {
  assert.ok(html.includes(`<script src="${script}" defer></script>`), `convert.html loads ${script}`);
}
assert.doesNotMatch(html, /style="|demo|example\.com/i, "no inline style and no demo material");

// The real engine.
vm.runInThisContext(fs.readFileSync(runtimePath, "utf8"), { filename: runtimePath });
let started;
const ready = new Promise((resolve) => { started = resolve; });
globalThis.rootwellWasmReady = started;
const go = new Go();
const instance = await WebAssembly.instantiate(fs.readFileSync(wasmPath), go.importObject);
go.run(instance.instance);
await Promise.race([ready, new Promise((_, reject) => setTimeout(() => reject(new Error("WASM timeout")), 10000))]);
const engine = Object.freeze({
  explore: rootwellExplore, analyze: rootwellAnalyze, inspect: rootwellInspect, exportPublic: rootwellExport,
  module: {}, maxBytes: rootwellInspectMaxBytes,
});
const fixture = JSON.parse(execFileSync("go", ["run", "./scripts/generate-convert-fixture.go"], { encoding: "utf8" }));
const bytesOf = (name) => Uint8Array.from(Buffer.from(fixture[name], "base64"));
const text = (bytes) => new TextDecoder().decode(bytes);
const certificates = (bytes) => JSON.parse(engine.explore(bytes)).result.certificates;

// The worker clients, as direct engine calls on copies, the way the workers
// receive them.
const copy = (bytes) => bytes.slice();
const win = {
  rootwellWorkbenchReady: Promise.resolve(engine),
  rootwellPFXWorker: { run: async (module, operation, inputs, password, second, option) => operation === "inspect" ?
    rootwellPFXInspect(copy(inputs[0]), copy(password)) :
    rootwellPFXOutput(operation, copy(inputs[0]), copy(inputs[1]), copy(inputs[2]), copy(password), copy(second), option) },
  rootwellPrivateWorker: { run: async (module, operation, input, current, fingerprint, format, output) => operation === "inspect" ?
    rootwellPrivateInspect(copy(input), copy(current)) :
    rootwellPrivateExport(copy(input), fingerprint, copy(current), format, copy(output)) },
  rootwellCSRWorker: { run: async (module, operation, input, certificate, password) => {
    assert.equal(operation, "certificate-key-match");
    return rootwellCertificateKeyMatch(copy(certificate), copy(input), copy(password));
  } },
  listeners: {},
  addEventListener(name, fn) { this.listeners[name] = fn; },
};

// A small DOM: enough for the page's own elements and the ones it builds.
class Node {
  constructor(tag) {
    Object.assign(this, { tag, children: [], textContent: "", className: "", attributes: {}, hidden: false, disabled: false,
      value: "", type: "", checked: false, name: "", placeholder: "", files: null, listeners: {}, download: "", href: "" });
    this.classList = { add: (c) => { this.className = (this.className + " " + c).trim(); }, remove() {} };
  }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  focus() {}
  remove() {}
  click() {
    if (this.tag === "a" && this.download) downloads.push({ name: this.download, blob: lastBlob });
    else this.listeners.click?.();
  }
  all() { return [this, ...this.children.flatMap((c) => c.all())]; }
  querySelector(selector) {
    if (selector === "input:checked") return this.all().find((n) => n.tag === "input" && n.checked) || null;
    return this.all().find((n) => n.tag === selector) || null;
  }
  text() { return [this.textContent, ...this.children.map((c) => c.text())].join(" ").replace(/\s+/g, " ").trim(); }
}
const ids = {};
const $ = (id) => (ids[id] ??= new Node(id.endsWith("-file") || id === "convert-password" || id === "convert-secret" ? "input" : "div"));
const document = { getElementById: $, createElement: (tag) => new Node(tag), createElementNS: (_, tag) => new Node(tag), body: new Node("body") };
const downloads = [];
let lastBlob = null;
const URL_ = { createObjectURL(blob) { lastBlob = blob; return "blob:test"; }, revokeObjectURL() {} };
const timers = [];
const fakeSetTimeout = (fn, ms) => { timers.push({ fn, ms }); return timers.length; };
const clipboard = [];
const navigator_ = { clipboard: { writeText: async (value) => { clipboard.push(value); } } };
const load = (src, filename) => vm.runInThisContext("(function (globalThis, document, setTimeout, clearTimeout, navigator, URL) {" + src + "\n})", { filename })(
  win, document, fakeSetTimeout, () => {}, navigator_, URL_);
load(uiSource, "ui.js");
load(source, "convert.js");

const settle = async () => { for (let i = 0; i < 40; i++) await new Promise((r) => setImmediate(r)); };
const file = (name, fixtureName) => new File([bytesOf(fixtureName)], name);
const drop = async (...files) => { $("convert-file").files = files; $("convert-file").listeners.change(); await settle(); };
const again = () => { $("convert-again").listeners.click(); };
const choices = () => $("convert-choices").children.map((label) => label.children[0].value);
const pick = (id) => {
  for (const label of $("convert-choices").children) label.children[0].checked = label.children[0].value === id;
  $("convert-choices").children.find((label) => label.children[0].value === id).children[0].listeners.change();
};
const unlock = async (password) => { $("convert-password").value = password; await $("convert-unlock").listeners.submit({ preventDefault() {} }); await settle(); };
const save = async () => {
  const before = downloads.length;
  await $("convert-download").listeners.click();
  await settle();
  if (downloads.length === before) return { status: $("convert-status").text() };
  const got = downloads[downloads.length - 1];
  return { name: got.name, type: got.blob.type, bytes: new Uint8Array(await got.blob.arrayBuffer()), status: $("convert-status").text() };
};
function unzip(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const end = bytes.byteLength - 22;
  assert.equal(view.getUint32(end, true), 0x06054b50, "end of central directory");
  const count = view.getUint16(end + 10, true);
  let at = view.getUint32(end + 16, true);
  const files = {};
  for (let i = 0; i < count; i++) {
    assert.equal(view.getUint32(at, true), 0x02014b50, "central directory entry");
    const crc = view.getUint32(at + 16, true), size = view.getUint32(at + 24, true), nameLength = view.getUint16(at + 28, true);
    const offset = view.getUint32(at + 42, true);
    const name = text(bytes.subarray(at + 46, at + 46 + nameLength));
    assert.equal(view.getUint32(offset, true), 0x04034b50, "local header");
    const start = offset + 30 + view.getUint16(offset + 26, true) + view.getUint16(offset + 28, true);
    const body = bytes.slice(start, start + size);
    assert.equal(zlib.crc32(body), crc, name + " CRC");
    files[name] = body;
    at += 46 + nameLength;
  }
  return files;
}

// A PFX: locked until its password opens it, then every format.
await drop(file("shop.test.pfx", "pfx"));
assert.equal($("convert-unlock").hidden, false);
assert.equal($("convert-password-label").textContent, "PFX password");
assert.equal($("convert-formats").hidden, true);
await unlock("not-the-password");
assert.match($("convert-unlock-error").textContent, /does not open this PFX/);
await unlock(fixture.pfx_password);
assert.equal($("convert-unlock").hidden, true);
assert.equal($("convert-password").value, "", "the password field is emptied");
assert.equal($("convert-chip-name").textContent, "shop.test");
assert.match($("convert-chip-info").textContent, /^shop\.test\.pfx · Certificate, 1 intermediate and the private key$/);
assert.deepEqual(choices(), ["pem-files", "crt", "der", "pfx"]);
assert.match($("convert-download-name").textContent, /^Download shop\.test\.zip$/);
assert.equal($("convert-contents").textContent, "fullchain.pem · cert.pem · chain.pem · privkey.pem");
{
  const zip = await save();
  assert.equal(zip.name, "shop.test.zip");
  assert.equal(zip.type, "application/zip");
  const files = unzip(zip.bytes);
  assert.deepEqual(Object.keys(files), ["fullchain.pem", "cert.pem", "chain.pem", "privkey.pem"]);
  assert.deepEqual(certificates(files["fullchain.pem"]).map((c) => c.subject), ["CN=shop.test", "CN=Synthetic Convert Issuing CA"]);
  assert.deepEqual(certificates(files["cert.pem"]).map((c) => c.subject), ["CN=shop.test"]);
  assert.deepEqual(certificates(files["chain.pem"]).map((c) => c.subject), ["CN=Synthetic Convert Issuing CA"]);
  assert.match(text(files["privkey.pem"]), /^-----BEGIN PRIVATE KEY-----\n/);
  assert.equal(createPrivateKey(Buffer.from(files["privkey.pem"])).asymmetricKeyType, "ec");
  assert.match(zip.status, /Downloaded shop\.test\.zip/);
}
{
  $("convert-secret").value = "too-short";
  assert.match((await save()).status, /20 to 128/);
  const password = "Separate-Key-Password-2026-zz";
  $("convert-secret").value = password;
  const files = unzip((await save()).bytes);
  assert.match(text(files["privkey.pem"]), /^-----BEGIN ENCRYPTED PRIVATE KEY-----\n/);
  assert.equal(createPrivateKey({ key: Buffer.from(files["privkey.pem"]), passphrase: password }).asymmetricKeyType, "ec");
  $("convert-secret").value = "";
}
pick("crt");
{
  const crt = await save();
  assert.equal(crt.name, "shop.test.crt");
  assert.deepEqual(certificates(crt.bytes).map((c) => c.subject + " " + c.encoding), ["CN=shop.test pem"]);
}
pick("der");
{
  const der = await save();
  assert.equal(der.name, "shop.test.cer");
  assert.equal(der.bytes[0], 0x30);
  assert.deepEqual(certificates(der.bytes).map((c) => c.encoding), ["der"]);
}
pick("pfx");
assert.equal($("convert-secret-row").hidden, false);
assert.equal($("convert-secret-optional").hidden, true);
assert.match((await save()).status, /20 to 128/, "a new PFX needs a password");
$("convert-secret").value = fixture.pfx_password;
assert.match((await save()).status, /different from the current one/);
$("convert-generate").listeners.click();
const generated = $("convert-secret").value;
assert.match(generated, /^[A-HJ-NP-Za-km-z2-9]{24}$/);
assert.equal($("convert-secret").type, "text");
assert.equal($("convert-secret-note").hidden, false);
assert.equal($("convert-generate").hidden, true, "Generate turns into Copy");
await $("convert-copy").listeners.click();
assert.deepEqual(clipboard, [generated]);
{
  const made = await save();
  assert.equal(made.name, "shop.test.pfx");
  assert.equal(made.type, "application/x-pkcs12");
  const opened = JSON.parse(rootwellPFXInspect(made.bytes, new TextEncoder().encode(generated)));
  assert.equal(opened.ok, true);
  assert.deepEqual(opened.result.certificates.map((c) => c.subject + (c.matching_key ? " +key" : "")), ["CN=shop.test +key", "CN=Synthetic Convert Issuing CA"]);
}

// A certificate with its chain and key, dropped together.
again();
assert.equal($("convert-card").hidden, true);
assert.equal($("convert-secret").value, "", "other files forget the password");
await drop(new File([bytesOf("leaf"), bytesOf("issuer")], "fullchain.pem"), file("root.pem", "root"), file("shop.test.key", "key"));
assert.equal($("convert-error").hidden, true, $("convert-error").textContent);
assert.equal($("convert-chip-info").textContent, "3 files · Certificate, 1 intermediate, the root and the private key");
assert.deepEqual(choices(), ["pem-files", "crt", "der", "pfx"]);
{
  const files = unzip((await save()).bytes);
  assert.deepEqual(certificates(files["fullchain.pem"]).map((c) => c.subject), ["CN=shop.test", "CN=Synthetic Convert Issuing CA"], "the full chain leaves the root out");
  pick("pfx");
  $("convert-generate").listeners.click();
  const made = await save();
  const opened = JSON.parse(rootwellPFXInspect(made.bytes, new TextEncoder().encode($("convert-secret").value)));
  assert.equal(opened.result.certificates.length, 2);
}

// A key that belongs to another certificate is refused.
again();
await drop(file("shop.test.crt", "leaf"), file("other.key", "other_key"));
assert.equal($("convert-error").hidden, false);
assert.match($("convert-error").textContent, /does not belong to the certificate/);
assert.equal($("convert-card").hidden, true);

// A certificate alone: PEM, and a PFX once its key is added.
again();
await drop(file("shop.test.crt", "leaf"), file("chain.pem", "issuer"));
assert.equal($("convert-chip-info").textContent, "2 files · Certificate and 1 intermediate");
assert.deepEqual(choices(), ["pem", "crt", "der", "pfx"]);
{
  const pem = await save();
  assert.equal(pem.name, "shop.test-fullchain.pem");
  assert.deepEqual(certificates(pem.bytes).map((c) => c.subject), ["CN=shop.test", "CN=Synthetic Convert Issuing CA"]);
}
pick("pfx");
assert.equal($("convert-key-row").hidden, false);
assert.equal($("convert-go").hidden, true, "no download until the key is there");
$("convert-key-file").files = [file("locked.key", "locked_key")];
await $("convert-key-file").listeners.change();
await settle();
assert.equal($("convert-unlock").hidden, false);
assert.equal($("convert-password-label").textContent, "Key password");
await unlock(fixture.key_password);
assert.equal($("convert-key-row").hidden, true);
assert.equal($("convert-go").hidden, false);
assert.equal($("convert-choices").querySelector("input:checked").value, "pfx", "the choice is kept");
{
  $("convert-generate").listeners.click();
  const made = await save();
  assert.match(made.status, /Downloaded shop\.test\.pfx/);
  assert.equal(JSON.parse(rootwellPFXInspect(made.bytes, new TextEncoder().encode($("convert-secret").value))).ok, true);
}

// An RSA key alone: modern PEM, the older RSA form and DER.
again();
await drop(file("server.key", "rsa_key"));
assert.equal($("convert-chip-name").textContent, "server.key");
assert.equal($("convert-chip-info").textContent, "Private key · RSA 2048");
assert.deepEqual(choices(), ["key-pem", "key-der", "key-traditional"]);
{
  const pem = await save();
  assert.equal(pem.name, "server.key");
  assert.match(text(pem.bytes), /^-----BEGIN PRIVATE KEY-----\n/);
  pick("key-traditional");
  assert.match(text((await save()).bytes), /^-----BEGIN RSA PRIVATE KEY-----\n/);
  pick("key-der");
  const der = await save();
  assert.equal(der.name, "server-key.der");
  assert.equal(createPrivateKey({ key: Buffer.from(der.bytes), format: "der", type: "pkcs8" }).asymmetricKeyType, "rsa");
}

// A protected key alone: opened with its password, saved plain or with a new one.
again();
await drop(file("locked.key", "locked_key"));
assert.equal($("convert-chip-info").textContent, "Private key · protected");
await unlock("wrong-password-for-this-key");
assert.match($("convert-unlock-error").textContent, /does not open this key/);
await unlock(fixture.key_password);
assert.equal($("convert-chip-info").textContent, "Private key · ECDSA P-256 · protected");
assert.deepEqual(choices(), ["key-pem", "key-der", "key-traditional"]);
assert.match(text((await save()).bytes), /^-----BEGIN PRIVATE KEY-----\n/);
$("convert-secret").value = fixture.key_password;
assert.match((await save()).status, /different from the current one/);
$("convert-secret").value = "Another-Strong-Password-2026";
assert.match(text((await save()).bytes), /^-----BEGIN ENCRYPTED PRIVATE KEY-----\n/);
pick("key-traditional");
assert.match(text((await save()).bytes), /^-----BEGIN EC PRIVATE KEY-----\n/);

// Files that are none of these, too many files, and two PFX-like mixes.
again();
await drop(new File(["hello"], "notes.txt"));
assert.match($("convert-error").textContent, /notes\.txt is not a certificate, key or PFX file/);
again();
await drop(file("a.pem", "leaf"), file("b.pem", "leaf"), file("c.pem", "leaf"), file("d.pem", "leaf"), file("e.pem", "leaf"));
assert.match($("convert-error").textContent, /up to 4 files/);
again();
await drop(file("shop.test.pfx", "pfx"), file("shop.test.key", "key"));
assert.match($("convert-error").textContent, /Open a PFX on its own/);

// Ten idle minutes, or leaving the page, forget everything.
again();
await drop(file("shop.test.pfx", "pfx"));
await unlock(fixture.pfx_password);
const idle = timers.filter((t) => t.ms === 10 * 60 * 1000).pop();
idle.fn();
assert.equal($("convert-card").hidden, true);
assert.match($("convert-error").textContent, /cleared after ten idle minutes/);
await drop(file("shop.test.pfx", "pfx"));
await unlock(fixture.pfx_password);
win.listeners.pagehide();
assert.equal($("convert-card").hidden, true);
assert.equal($("convert-choices").children.length, 0);

// Helpers the page leans on.
{
  const ui = win.rootwellUI;
  assert.equal(ui.isStrongPassword("a".repeat(19)), false);
  assert.equal(ui.isStrongPassword("a".repeat(20)), true);
  assert.equal(ui.isStrongPassword("a".repeat(129)), false);
  assert.equal(ui.isStrongPassword("with space and more letters"), false);
  const seen = new Set(Array.from({ length: 50 }, () => ui.strongPassword()));
  assert.equal(seen.size, 50);
  const empty = unzip(ui.zip([{ name: "a.txt", bytes: new Uint8Array() }, { name: "ü.pem", bytes: new TextEncoder().encode("x") }]));
  assert.deepEqual(Object.keys(empty), ["a.txt", "ü.pem"]);
}

console.log("Convert opens PFX files, certificates and keys, and makes every format with the real engine.");
