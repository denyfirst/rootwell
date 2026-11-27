import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import vm from "node:vm";

// Request, driven with the real browser engine: names typed or pasted become
// chips; a new key is made and kept by Rootwell, through request-keep.js and
// a stand-in for its API that signs a real request with the engine; or the
// person's own key signs the request in the browser. The worker client is
// replaced by a direct engine call; the page scripts, their helpers and the
// engine are the real ones.
const [wasmPath, runtimePath] = process.argv.slice(2);
if (!wasmPath || !runtimePath) throw new Error("usage: node test-request.mjs <wasm> <wasm_exec.js>");
const read = (name) => fs.readFileSync(new URL("../web/workbench/" + name, import.meta.url), "utf8");
const uiSource = read("ui.js");
const source = read("request.js");
const keepSource = read("request-keep.js");
const html = read("request.html");
for (const forbidden of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "fetch(", "XMLHttpRequest", "localStorage", "sessionStorage", "indexedDB"]) {
  assert.ok(!source.includes(forbidden), `request.js must not use ${forbidden}`);
}
// The script that sends the typed names reads no file and asks only for the
// list's count and a new request.
for (const forbidden of [".files", "arrayBuffer", "FileReader", "readAs", "Uint8Array", "Worker(", "import(", "innerHTML", "document",
  "localStorage", "sessionStorage", "indexedDB", "eval(", "new Function", "http"]) {
  assert.ok(!keepSource.includes(forbidden), `request-keep.js must not use ${forbidden}`);
}
assert.deepEqual([...keepSource.matchAll(/send\("([^"]+)"/g)].map((m) => m[1]), ["/api/inventory", "/api/requests/create"]);
assert.match(html, /<a class="nav-item" href="\/request" aria-current="page">/);
for (const script of ["/wasm_exec.js", "/wasm-loader.js", "/ui.js", "/csr-worker-client.js", "/request-keep.js", "/request.js"]) {
  assert.ok(html.includes(`<script src="${script}" defer></script>`), `request.html loads ${script}`);
}
assert.doesNotMatch(html, /style="|demo|example\.com|request-secret/i, "no inline style, no demo material, no key password");
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

// ── A stand-in for Rootwell's list count and request API ─────────────────
// It signs a real request with the engine, as rootwelld does with the same
// Go code, and answers like the server: 409 for a stale count, a refusal
// header when it says no.
const api = { generation: 4, calls: [], staleOnce: false, refuse: null };
const reply = (status, body, headers = {}) => new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
async function fetch(url, options) {
  const body = options.body ? JSON.parse(options.body) : null;
  api.calls.push({ url, method: options.method, body });
  assert.equal(options.credentials, "same-origin");
  assert.equal(options.redirect, "error");
  assert.equal(options.headers["X-Rootwell-Request"], "1");
  if (url === "/api/inventory") return reply(200, { generation: api.generation, records: [], requests: [] });
  assert.equal(url, "/api/requests/create");
  assert.equal(options.method, "POST");
  assert.deepEqual(Object.keys(body).filter((k) => !["algorithm", "dns_names", "ip_addresses", "organization", "locality", "province", "country", "expected_generation"].includes(k)), []);
  if (api.refuse) return reply(api.refuse.status, "no", api.refuse.refusal ? { "X-Rootwell-Refusal": api.refuse.refusal } : {});
  if (api.staleOnce) { api.staleOnce = false; api.generation++; return reply(409, "inventory changed"); }
  if (body.expected_generation !== api.generation) return reply(409, "inventory changed");
  const params = { dns_names: body.dns_names, ip_addresses: body.ip_addresses, common_name: "", organization: body.organization || "",
    organizational_unit: "", country: body.country || "", locality: body.locality || "", province: body.province || "" };
  const made = rootwellCSROperate("generate", new Uint8Array(), new Uint8Array(), new TextEncoder().encode("a-throwaway-password-for-tests"),
    JSON.stringify({ algorithm: body.algorithm, params, format: "" }));
  assert.equal(made.ok, true);
  api.generation++;
  const summary = JSON.parse(made.result.summary);
  return reply(201, { generation: api.generation, request: { public_fingerprint: summary.public_fingerprint, created_at: "2026-11-27T10:00:00Z",
    csr: text(made.result.csr), subject: summary.subject, dns_names: summary.dns_names, ip_addresses: summary.ip_addresses,
    key_type: body.algorithm === "rsa-2048" ? "RSA 2048" : "ECDSA P-256" } });
}

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
const inputs = new Set(["request-name", "request-own-file", "request-own-password", "request-organization", "request-city", "request-state", "request-country"]);
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
const copied = [];
const navigator_ = { clipboard: { writeText: async (value) => { copied.push(value); } } };
const load = (src, filename) => vm.runInThisContext("(function (globalThis, document, setTimeout, clearTimeout, navigator, URL, fetch) {" + src + "\n})", { filename })(
  win, document, (fn, ms) => { timers.push({ fn, ms }); return timers.length; }, () => {}, navigator_, TestURL, fetch);
load(uiSource, "ui.js");
load(keepSource, "request-keep.js");
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
// The result is three steps; the first holds the request's buttons.
const steps = () => $("request-files").children.map((li) => li.children[0].children[0].textContent);
const stepButtons = () => $("request-files").children[0].children[0].children[1].children;

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

// A new key: Rootwell makes and keeps it. Only the names and details go to
// it, with the list's count; the page never holds the key.
assert.equal($("request-own").hidden, true);
$("request-country").value = "Germany";
await submit();
assert.match(statusText(), /two letters/);
assert.equal(api.calls.length, 0);
$("request-country").value = "de";
$("request-organization").value = "  Synthetic Shop  ";
api.staleOnce = true;
await submit();
assert.equal(statusText(), "");
assert.equal(calls.length, 0, "no worker makes a key in the browser");
const creates = api.calls.filter((c) => c.url === "/api/requests/create");
assert.equal(creates.length, 2, "a list that changed in between is read once more");
assert.deepEqual(creates.at(-1).body, { algorithm: "ec-p256", dns_names: ["shop.test", "www.shop.test"], ip_addresses: ["192.0.2.10"],
  organization: "Synthetic Shop", country: "DE", expected_generation: 5 });
assert.equal($("request-result").hidden, false);
assert.equal($("request-result-title").textContent, "Request ready for shop.test");
assert.match($("request-facts").text(), /Works for shop\.test, www\.shop\.test, 192\.0\.2\.10 Key ECDSA P-256, kept in Rootwell/);
assert.deepEqual(steps(), ["Download the request", "Give it to your certificate provider", "Add the certificate in Certificates"]);
assert.match($("request-files").children[2].text(), /Rootwell puts it with the key it keeps/);
assert.equal(stepButtons()[0].text(), "shop.test.csr");
stepButtons()[0].listeners.click();
await stepButtons()[1].listeners.click();
assert.deepEqual(downloads.map((d) => d.name + " " + d.blob.type), ["shop.test.csr application/pkcs10"]);
{
  const csr = new Uint8Array(await downloads[0].blob.arrayBuffer());
  assert.match(text(csr), /^-----BEGIN CERTIFICATE REQUEST-----\n/);
  assert.equal(copied.at(-1), text(csr), "Copy puts the request's text on the clipboard");
  assert.doesNotMatch(text(csr), /PRIVATE/);
  const summary = inspectCSR(csr);
  assert.deepEqual(summary.dns_names, ["shop.test", "www.shop.test"]);
  assert.deepEqual(summary.ip_addresses, ["192.0.2.10"]);
  assert.match(summary.subject, /O=Synthetic Shop/);
  assert.match(summary.subject, /C=DE/);
}
// Refusals in plain words, with nothing old left on the page.
for (const [refuse, words] of [[{ status: 409, refusal: "requests-full" }, /50 requests are waiting/], [{ status: 401 }, /session has ended/],
  [{ status: 400 }, /cannot go into a request/], [{ status: 503 }, /busy/]]) {
  api.refuse = refuse;
  await submit();
  assert.match(statusText(), words);
  assert.equal($("request-result").hidden, true);
}
api.refuse = null;

// Your own key: protected keys need their password; only the request comes
// out, and nothing goes to Rootwell.
pickKey("own");
assert.equal($("request-own").hidden, false);
const sent = api.calls.length;
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
assert.equal(api.calls.length, sent, "your own key's request is made in the browser only");
assert.equal(calls.at(-1).operation, "key");
assert.equal(calls.at(-1).option.format, "pem");
assert.match($("request-facts").text(), /Key /);
assert.doesNotMatch($("request-facts").text(), /kept in Rootwell/);
assert.match($("request-files").children[2].text(), /Add your key with it/);
stepButtons()[0].listeners.click();
{
  const csr = new Uint8Array(await downloads.at(-1).blob.arrayBuffer());
  const keyFingerprint = JSON.parse(rootwellPrivateInspect(bytesOf("locked_key"), new TextEncoder().encode(fixture.key_password))).result.public_fingerprint;
  assert.equal(inspectCSR(csr).public_fingerprint, keyFingerprint, "the request carries the person's own key");
}

// Nothing to name yet.
for (let i = 0; i < 5; i++) key("Backspace");
await submit();
assert.match(statusText(), /Add the name the certificate is for/);

// Ten idle minutes, or leaving the page, forget the request.
type("shop.test");
pickKey("ec-p256");
await submit();
assert.equal($("request-result").hidden, false);
timers.filter((t) => t.ms === 10 * 60 * 1000).pop().fn();
assert.equal($("request-result").hidden, true);
assert.match(statusText(), /cleared from this page after ten idle minutes/);
await submit();
win.listeners.pagehide();
assert.equal($("request-result").hidden, true);
assert.equal($("request-files").children.length, 0);

console.log("Request makes a CSR whose new key Rootwell keeps, or one with the person's own key, with the real engine.");
