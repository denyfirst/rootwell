import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import vm from "node:vm";

// Inspect, driven end to end with the real browser engine: a chain dropped as
// separate files, a certificate alone, files that belong on another page, too
// many files, a private key checked against the certificate, and forgetting on
// leaving the page. The key-match worker client is replaced by a direct engine
// call; the page script, its helpers and the engine are the real ones.
const [wasmPath, runtimePath] = process.argv.slice(2);
if (!wasmPath || !runtimePath) throw new Error("usage: node test-inspect.mjs <wasm> <wasm_exec.js>");
const read = (name) => fs.readFileSync(new URL("../web/workbench/" + name, import.meta.url), "utf8");
const uiSource = read("ui.js");
const source = read("inspect.js");
const html = read("inspect.html");

for (const [name, text] of [["inspect.js", source], ["ui.js", uiSource]]) {
  for (const forbidden of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "fetch(", "XMLHttpRequest", "localStorage", "sessionStorage", "indexedDB"]) {
    assert.ok(!text.includes(forbidden), `${name} must not use ${forbidden}`);
  }
}
assert.match(html, /<link rel="stylesheet" href="\/rootwell\.css">/);
assert.match(html, /<a class="nav-item" href="\/inspect" aria-current="page">/);
for (const script of ["/wasm_exec.js", "/wasm-loader.js", "/ui.js", "/csr-worker-client.js", "/inspect.js"]) {
  assert.ok(html.includes(`<script src="${script}" defer></script>`), `inspect.html loads ${script}`);
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

// The key-match worker client, as a direct engine call on copies, the way the
// worker receives them. Every call is counted, so a check that never reaches
// the engine is seen.
const copy = (bytes) => bytes.slice();
const matches = [];
const win = {
  rootwellWorkbenchReady: Promise.resolve(engine),
  rootwellCSRWorker: { run: async (module, operation, key, certificate, password, option, signal) => {
    assert.equal(operation, "certificate-key-match");
    assert.equal(option, "");
    assert.ok(signal && typeof signal.addEventListener === "function", "the check can be cancelled");
    matches.push(operation);
    return rootwellCertificateKeyMatch(copy(certificate), copy(key), copy(password));
  } },
  listeners: {},
  addEventListener(name, fn) { this.listeners[name] = fn; },
};

// A small DOM: enough for the page's own elements and the ones it builds.
class Node {
  constructor(tag) {
    Object.assign(this, { tag, children: [], textContent: "", className: "", attributes: {}, hidden: false, disabled: false,
      value: "", files: null, listeners: {}, title: "", style: {} });
    this.classList = { add: (c) => { this.className = (this.className + " " + c).trim(); }, remove() {} };
  }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  click() { this.listeners.click?.(); }
  all() { return [this, ...this.children.flatMap((c) => c.all())]; }
  querySelector(selector) { return this.all().find((n) => n.tag === selector) || null; }
  find(tag, className) { return this.all().filter((n) => n.tag === tag && (!className || n.className.split(" ").includes(className))); }
  text() { return [this.textContent, ...this.children.map((c) => c.text())].join(" ").replace(/\s+/g, " ").trim(); }
}
const ids = {};
const inputs = new Set(["inspect-file", "key-file", "key-password"]);
const $ = (id) => (ids[id] ??= new Node(inputs.has(id) ? "input" : "div"));
const docListeners = {};
const document = { getElementById: $, createElement: (tag) => new Node(tag), createElementNS: (_, tag) => new Node(tag),
  body: new Node("body"), hidden: false, addEventListener(name, fn) { docListeners[name] = fn; } };
const load = (src, filename) => vm.runInThisContext("(function (globalThis, document) {" + src + "\n})", { filename })(win, document);
load(uiSource, "ui.js");
load(source, "inspect.js");

const settle = async () => { for (let i = 0; i < 40; i++) await new Promise((r) => setImmediate(r)); };
const file = (name, fixtureName) => new File([bytesOf(fixtureName)], name);
const drop = async (...files) => { $("inspect-file").files = files; $("inspect-file").listeners.change(); await settle(); };
const again = () => { $("inspect-again").listeners.click(); };
const cards = () => $("inspect-result").children;
const checkKey = async (key, password = "") => {
  $("key-file").files = key ? [key] : null;
  $("key-password").value = password;
  await $("key-check").listeners.click();
  await settle();
  return $("key-status");
};
const shown = () => $("inspect-result").hidden === false && $("key-card").hidden === false;

// A chain dropped as three files, root first: the website certificate leads,
// and the chain is complete with all three links.
await drop(file("root.pem", "root"), file("issuer.pem", "issuer"), file("shop.test.crt", "leaf"));
assert.equal($("inspect-error").hidden, true, $("inspect-error").textContent);
assert.ok(shown(), "the result and the key check are shown");
assert.equal($("inspect-drop").hidden, true);
assert.equal($("inspect-chip").hidden, false);
assert.equal($("inspect-chip-name").textContent, "3 files");
assert.equal($("inspect-chip-info").textContent, "3 certificates");
assert.equal(cards().length, 2, "a hero card and a chain card");
{
  const [hero, chain] = cards();
  assert.equal(hero.find("h2")[0].textContent, "shop.test");
  assert.equal(hero.find("p")[0].textContent, "Issued by Synthetic Convert Issuing CA");
  const pill = hero.find("span", "pill")[0];
  assert.match(pill.className, /pill-good/);
  assert.match(pill.textContent, /^(89|90) days left$/);
  assert.equal(hero.find("div", "lifetime-bar").length, 1, "the lifetime bar is drawn");
  assert.match(hero.text(), /Works for shop\.test, www\.shop\.test/);
  assert.match(hero.text(), /Key ECDSA/);
  const fingerprint = hero.find("strong", "mono")[0];
  assert.match(fingerprint.textContent, /^[0-9A-F:…. ]+$/);
  assert.equal(chain.find("h3")[0].textContent, "Chain");
  const status = chain.find("span", "pill")[0];
  assert.equal(status.textContent, "Complete");
  assert.match(status.className, /pill-good/);
  const links = chain.find("div", "link");
  assert.equal(links.length, 3);
  assert.deepEqual(links.map((l) => l.find("strong")[0].textContent), ["shop.test", "Synthetic Convert Issuing CA", "Synthetic Convert Root"]);
  assert.deepEqual(links.map((l) => l.find("small")[0].textContent), ["Website certificate", "Intermediate", "Root"]);
  assert.ok(links.every((l) => l.className.split(" ").includes("ok")), "no link is expired");
  assert.equal(chain.find("p", "meta").length, 0, "every certificate is part of the chain");
}

// The private key: the right one, another one, a locked one without and with
// its password. The password field is emptied after each check.
{
  let status = await checkKey(file("shop.test.key", "key"));
  assert.equal(status.children[0].className, "notice good");
  assert.match(status.text(), /This key belongs to the certificate\./);
  status = await checkKey(file("other.key", "other_key"));
  assert.equal(status.children[0].className, "notice bad");
  assert.match(status.text(), /This key does not belong to the certificate\./);
  status = await checkKey(file("locked.key", "locked_key"));
  assert.match(status.text(), /This key is protected\. Enter its password and check again\./);
  status = await checkKey(file("locked.key", "locked_key"), fixture.key_password);
  assert.equal(status.children[0].className, "notice good");
  assert.equal($("key-password").value, "", "the key password is forgotten");
  assert.equal($("key-file").value, "", "the key file is forgotten");
  assert.equal($("key-check").disabled, false);
  status = await checkKey(null);
  assert.match(status.text(), /Choose the private key file first\./);
  assert.equal(matches.length, 4);
}

// Hiding the page forgets the certificate and a typed password: a key check
// then has nothing to compare with, and never reaches the engine.
$("key-password").value = "typed-before-leaving";
document.hidden = true;
docListeners.visibilitychange();
document.hidden = false;
assert.equal($("key-password").value, "", "hiding the page forgets a typed password");
{
  const before = matches.length;
  assert.match((await checkKey(file("shop.test.key", "key"))).text(), /Choose the private key file first\./);
  assert.equal(matches.length, before);
}

// A certificate alone: its card, and no chain card.
again();
assert.equal($("inspect-result").hidden, true);
assert.equal($("key-card").hidden, true);
assert.equal($("inspect-drop").hidden, false);
await drop(file("shop.test.crt", "leaf"));
assert.ok(shown());
assert.equal($("inspect-chip-name").textContent, "shop.test.crt");
assert.equal($("inspect-chip-info").textContent, "1 certificate");
assert.equal(cards().length, 1, "no chain card for one certificate");
assert.equal(cards()[0].find("h2")[0].textContent, "shop.test");

// Leaving the page forgets the certificate too.
win.listeners.pagehide();
assert.match((await checkKey(file("shop.test.key", "key"))).text(), /Choose the private key file first\./);

// Files that belong on another page say where to take them.
for (const [name, fixtureName, message] of [
  ["shop.test.pfx", "pfx", "This is a PFX file. Open it in Convert to see what is inside."],
  ["shop.test.key", "key", "This is a private key, not a certificate. Use Check a private key after opening its certificate."],
  ["shop.test.csr", "csr", "This is a certificate request. Send it to your certificate provider."],
]) {
  again();
  await drop(file(name, fixtureName));
  assert.equal($("inspect-error").hidden, false, name);
  assert.equal($("inspect-error").textContent, message);
  assert.equal($("inspect-result").hidden, true);
  assert.equal($("key-card").hidden, true);
}
again();
await drop(new File(["hello"], "notes.txt"));
assert.equal($("inspect-error").textContent, "This is not a certificate file Rootwell can read.");

// More than eight files are refused before any is read.
again();
const nine = Array.from({ length: 9 }, (_, i) => file(`part-${i}.pem`, "leaf"));
await drop(...nine);
assert.equal($("inspect-error").textContent, "Choose up to 8 files at once.");
assert.equal($("inspect-result").hidden, true);

console.log("Inspect reads chains, certificates and keys with the real engine, and forgets them on leaving.");
