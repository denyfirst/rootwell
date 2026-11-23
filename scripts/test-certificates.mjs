import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { X509Certificate, createPrivateKey } from "node:crypto";
import fs from "node:fs";
import vm from "node:vm";

// Certificates, driven against a stand-in for the inventory API: the list and
// its filters, one certificate in the sheet (places, owner, downloads, a key
// added later, delete), and adding certificates from files, a protected key
// or a PFX. The browser engine is the real one; the API stand-in parses the
// certificates it receives with Node's own X.509 code.
const [wasmPath, runtimePath] = process.argv.slice(2);
if (!wasmPath || !runtimePath) throw new Error("usage: node test-certificates.mjs <wasm> <wasm_exec.js>");
const read = (name) => fs.readFileSync(new URL("../web/workbench/" + name, import.meta.url), "utf8");
const uiSource = read("ui.js");
const source = read("certificates.js");
const html = read("certificates.html");
for (const forbidden of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "localStorage", "sessionStorage", "indexedDB"]) {
  assert.ok(!source.includes(forbidden), `certificates.js must not use ${forbidden}`);
}
assert.deepEqual([...new Set([...source.matchAll(/call\("([^"]+)"/g)].map((m) => m[1]))].sort(), [
  "/api/certificates/check", "/api/certificates/download", "/api/certificates/key/check", "/api/certificates/key/save",
  "/api/certificates/save", "/api/inventory", "/api/inventory/delete"]);
assert.match(source, /edit\("\/api\/inventory\/owner"/);
assert.match(source, /edit\("\/api\/inventory\/locations"/);
assert.match(source, /edit\("\/api\/inventory\/locations\/change"/);
assert.match(html, /<a class="nav-item" href="\/certificates" aria-current="page">/);
for (const script of ["/wasm_exec.js", "/wasm-loader.js", "/ui.js", "/certificate-pfx.js", "/certificates.js"]) {
  assert.ok(html.includes(`<script src="${script}" defer></script>`), `certificates.html loads ${script}`);
}
assert.doesNotMatch(html, /style="|demo|example\.com/i, "no inline style and no demo material");

vm.runInThisContext(fs.readFileSync(runtimePath, "utf8"), { filename: runtimePath });
let started;
const ready = new Promise((resolve) => { started = resolve; });
globalThis.rootwellWasmReady = started;
const runtime = new Go();
const instance = await WebAssembly.instantiate(fs.readFileSync(wasmPath), runtime.importObject);
runtime.run(instance.instance);
await Promise.race([ready, new Promise((_, reject) => setTimeout(() => reject(new Error("WASM timeout")), 10000))]);
const engine = Object.freeze({ explore: rootwellExplore, analyze: rootwellAnalyze, exportPublic: rootwellExport, module: {} });
const fixture = JSON.parse(execFileSync("go", ["run", "./scripts/generate-convert-fixture.go"], { encoding: "utf8" }));
const bytesOf = (name) => Uint8Array.from(Buffer.from(fixture[name], "base64"));

// ── A stand-in for the inventory API ─────────────────────────────────────
const day = 86400000;
const iso = (t) => new Date(Math.floor(t / 1000) * 1000).toISOString().replace(".000", "");
const hexFingerprint = (n) => Array.from({ length: 32 }, (_, i) => ((n * 29 + i * 7) % 256).toString(16).padStart(2, "0").toUpperCase()).join(":");
const record = (n, name, days, extra = {}) => ({ fingerprint: hexFingerprint(n), subject: "CN=" + name, issuer: "CN=Synthetic CA " + n,
  dns_names: [name], not_before: iso(Date.now() - 30 * day), not_after: iso(Date.now() + days * day), owner: "", location: "", locations: [],
  import_generation: 1, imported_at: iso(Date.now() - 2 * day), has_private_key: false, key_status: "not-added", bundle_count: 0,
  expiry: { status: "valid" }, ...extra });
const api = { generation: 1, records: [], requests: [], selection: false, password: "the-rootwell-password" };
const pemBlocks = (text) => text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
function parse(body) {
  const bytes = Buffer.from(body.certificate, "base64");
  const blocks = pemBlocks(bytes.toString("latin1"));
  const certificates = blocks.length ? blocks.map((b) => new X509Certificate(b)) : [new X509Certificate(bytes)];
  const chosen = body.primary_fingerprint ? certificates.find((c) => c.fingerprint256 === body.primary_fingerprint) : certificates[0];
  const toRecord = (c) => ({ fingerprint: c.fingerprint256, subject: c.subject.replace(/\n/g, ","), issuer: c.issuer.replace(/\n/g, ","),
    dns_names: (c.subjectAltName || "").split(", ").filter((s) => s.startsWith("DNS:")).map((s) => s.slice(4)),
    not_before: iso(Date.parse(c.validFrom)), not_after: iso(Date.parse(c.validTo)), owner: "", location: body.location || "",
    locations: body.location ? [body.location] : [], import_generation: api.generation + 1, imported_at: iso(Date.now()),
    has_private_key: false, key_status: "not-added", bundle_count: certificates.length - 1, expiry: { status: "valid" } });
  return { chosen, certificates, toRecord };
}
function keyStatus(certificate, body) {
  const key = Buffer.from(body.private_key || "", "base64");
  if (!key.length) return "not-added";
  try {
    const privateKey = createPrivateKey({ key, passphrase: Buffer.from(body.key_password || "", "base64") });
    return certificate.checkPrivateKey(privateKey) ? "matched" : "mismatch";
  } catch {
    return "locked";
  }
}
const reply = (status, body, headers = {}) => new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
const listing = (records) => ({ generation: api.generation, records, verification: "not-performed" });
async function fetch(url, options) {
  const body = options.body ? JSON.parse(options.body) : null;
  api.requests.push({ url, body, headers: options.headers });
  assert.equal(options.headers["X-Rootwell-Request"], "1");
  assert.equal(options.credentials, "same-origin");
  if (url === "/api/inventory") return reply(200, listing(api.records));
  if (body.expected_generation !== api.generation) return reply(409, "stale generation");
  const target = api.records.find((r) => r.fingerprint === body.fingerprint);
  const change = () => { api.generation++; return reply(200, listing([target])); };
  switch (url) {
    case "/api/inventory/owner": target.owner = body.owner; return change();
    case "/api/inventory/locations": target.locations.push(body.location); target.location ||= body.location; return change();
    case "/api/inventory/locations/change": target.locations = target.locations.filter((l) => l !== body.old_location); target.location = target.locations[0] || ""; return change();
    case "/api/inventory/delete":
      assert.equal(body.typed_fingerprint, body.fingerprint);
      assert.equal(body.confirmation, "delete-public-record");
      api.records = api.records.filter((r) => r !== target);
      api.generation++;
      return reply(200, { fingerprint: body.fingerprint, generation: api.generation, deleted: true });
    case "/api/certificates/download":
      if ((body.pair || body.key_only) && body.password !== api.password) return reply(401, "password not accepted");
      return new Response(body.pair ? "zip-bytes" : "-----BEGIN CERTIFICATE-----\n", { status: 200 });
    case "/api/certificates/key/check":
    case "/api/certificates/key/save": {
      if (url.endsWith("save") && body.password !== api.password) return reply(401, "password not accepted");
      const status = Buffer.from(body.private_key, "base64").toString().includes("synthetic-mismatch") ? "mismatch" : "matched";
      if (url.endsWith("save")) { target.has_private_key = true; target.key_status = status; api.generation++; }
      return reply(200, listing([{ ...target, has_private_key: true, key_status: status }]));
    }
    default: {
      const { chosen, certificates, toRecord } = parse(body);
      if (api.selection && !body.primary_fingerprint) return reply(200, listing(certificates.map(toRecord)), { "X-Rootwell-Selection": "required" });
      const status = keyStatus(chosen, body);
      if (status === "locked") return reply(422, "enter the key password");
      const result = { ...toRecord(chosen), has_private_key: status !== "not-added", key_status: status };
      if (api.records.some((r) => r.fingerprint === result.fingerprint)) return reply(409, "duplicate", { "X-Rootwell-Refusal": "duplicate-certificate" });
      if (url === "/api/certificates/check") return reply(200, listing([result]));
      assert.equal(body.fingerprint, result.fingerprint);
      assert.equal(body.allow_mismatch, false);
      api.records.push(result);
      api.generation++;
      return reply(201, listing([result]));
    }
  }
}

// ── A small DOM ──────────────────────────────────────────────────────────
class Node {
  constructor(tag) {
    Object.assign(this, { tag, children: [], textContent: "", className: "", attributes: {}, hidden: false, disabled: false, value: "",
      type: "", checked: false, name: "", placeholder: "", files: null, listeners: {}, download: "", href: "", title: "", id: "", style: {} });
    this.classList = { add: (c) => { this.className = (this.className + " " + c).trim(); }, remove() {} };
  }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  focus() {}
  remove() {}
  scrollIntoView() {}
  click() { if (this.tag === "a" && this.download) downloads.push({ name: this.download, blob: lastBlob }); else this.listeners.click?.(); }
  all() { return [this, ...this.children.flatMap((c) => c.all())]; }
  querySelector(selector) { return selector === "input:checked" ? this.all().find((n) => n.tag === "input" && n.checked) || null : this.all().find((n) => n.tag === selector) || null; }
  text() { return [this.textContent, ...this.children.map((c) => c.text())].join(" ").replace(/\s+/g, " ").trim(); }
}
const ids = {};
const $ = (id) => (ids[id] ??= new Node(/file$|password|place$|owner$|search|key-auth/.test(id) ? "input" : "div"));
const document = { getElementById: $, createElement: (tag) => new Node(tag), createElementNS: (_, tag) => new Node(tag), body: new Node("body"),
  activeElement: null, listeners: {}, addEventListener(name, fn) { this.listeners[name] = fn; } };
const downloads = [];
let lastBlob = null;
class TestURL extends URL {
  static createObjectURL(blob) { lastBlob = blob; return "blob:test"; }
  static revokeObjectURL() {}
}
const location_ = { hash: "", pathname: "/certificates" };
const history_ = { replaceState(_, __, url) { location_.hash = url.includes("#") ? url.slice(url.indexOf("#")) : ""; } };
const win = {
  rootwellWorkbenchReady: Promise.resolve(engine),
  rootwellCertificatePFX: { run: async (module, input, password) => {
    const answer = rootwellPFXImport(input.slice(), password.slice());
    if (!answer || answer.ok !== true) throw new Error("PFX preparation failed");
    return answer.result;
  } },
  listeners: {},
  addEventListener(name, fn) { this.listeners[name] = fn; },
};
const load = (src, filename) => vm.runInThisContext("(function (globalThis, document, setTimeout, clearTimeout, navigator, URL, fetch, location, history) {" + src + "\n})", { filename })(
  win, document, () => 0, () => {}, { clipboard: { writeText: async () => {} } }, TestURL, fetch, location_, history_);
const settle = async () => { for (let i = 0; i < 60; i++) await new Promise((r) => setImmediate(r)); };
const rows = () => $("list").children.filter((n) => n.className === "row");
const rowText = (r) => r.children[0].text();
const go = async (record) => { location_.hash = "#" + record.fingerprint.replace(/:/g, "").toLowerCase(); win.listeners.hashchange(); await settle(); };
const lastRequest = (url) => api.requests.filter((r) => r.url === url).at(-1);
const status = () => $("sheet-status").text();

// An empty list invites the first certificate.
load(uiSource, "ui.js");
load(source, "certificates.js");
await settle();
assert.equal($("empty").hidden, false);
assert.equal($("stats").hidden, true);
assert.equal($("list").hidden, true);

// A list: counted, sorted by what ends first, filtered by a press.
api.records = [record(1, "shop.test", 80, { has_private_key: true, key_status: "matched", locations: ["nginx on web-1"], location: "nginx on web-1", owner: "Web team", bundle_count: 1 }),
  record(2, "mail.test", 12), record(3, "old.test", -3, { has_private_key: true, key_status: "matched" }), record(4, "api.test", 300)];
api.generation = 2;
// A fresh page reads the longer list.
for (const key of Object.keys(ids)) delete ids[key];
load(source, "certificates.js");
await settle();
assert.equal($("empty").hidden, true);
assert.deepEqual($("stats").children.map((s) => s.text()), ["4 All", "2 Good", "1 Expiring soon", "1 Expired"]);
assert.deepEqual(rows().map(rowText), ["old.test Synthetic CA 3", "mail.test Synthetic CA 2", "shop.test Synthetic CA 1", "api.test Synthetic CA 4"]);
assert.match(rows()[2].text(), /nginx on web-1 .*days left Saved/);
assert.match(rows()[1].text(), /12 days left Not saved/);
assert.equal($("search-row").hidden, true, "search appears only for longer lists");
$("stats").children[3].listeners.click();
assert.deepEqual(rows().map(rowText), ["old.test Synthetic CA 3"]);
assert.equal($("stats").children[3].attributes["aria-pressed"], "true");
$("stats").children[3].listeners.click();
assert.equal(rows().length, 4);

// One certificate: names, key, places, owner and the website link.
const shop = api.records[0];
await go(shop);
assert.equal($("sheet").hidden, false);
assert.match($("sheet-hero").text(), /^shop\.test Issued by Synthetic CA 1/);
assert.equal($("sheet-names").text(), "shop.test");
assert.match($("sheet-facts").text(), /^Private key Saved Fingerprint .+ Added /);
assert.equal($("sheet-website").href, "/website-check#shop.test");
assert.equal($("sheet-owner").value, "Web team");
$("sheet-owner").value = "Platform team";
$("sheet-owner").listeners.input();
assert.equal($("sheet-owner-save").hidden, false);
await $("sheet-owner-save").listeners.click();
await settle();
assert.deepEqual(lastRequest("/api/inventory/owner").body, { fingerprint: shop.fingerprint, expected_generation: 2, owner: "Platform team" });
assert.match(status(), /Owner saved/);
assert.equal($("sheet-owner-save").hidden, true);
$("sheet-place").value = "IIS on win-2";
$("sheet-place").listeners.keydown({ key: "Enter", preventDefault() {} });
await settle();
assert.deepEqual(lastRequest("/api/inventory/locations").body, { fingerprint: shop.fingerprint, expected_generation: 3, location: "IIS on win-2" });
assert.deepEqual($("sheet-places").children.filter((n) => n.className === "chip").map((n) => n.textContent), ["nginx on web-1", "IIS on win-2"]);
await $("sheet-places").children[0].children[0].listeners.click();
await settle();
assert.deepEqual(lastRequest("/api/inventory/locations/change").body, { fingerprint: shop.fingerprint, expected_generation: 4, old_location: "nginx on web-1", action: "remove" });
assert.match(rows().find((r) => rowText(r).startsWith("shop.test")).text(), /IIS on win-2/);

// One change at a time: a quick second click sends nothing more, and a place
// typed while a save runs stays in its field instead of being lost.
const ownerSaves = () => api.requests.filter((r) => r.url === "/api/inventory/owner").length;
const ownerSavesBefore = ownerSaves();
$("sheet-owner").value = "Ops team";
$("sheet-owner").listeners.input();
const firstSave = $("sheet-owner-save").listeners.click();
assert.equal($("sheet-owner-save").disabled, true, "Save is disabled while the owner is being saved");
$("sheet-place").value = "IIS on win-3";
$("sheet-place").listeners.keydown({ key: "Enter", preventDefault() {} });
assert.equal($("sheet-place").value, "IIS on win-3", "a place typed while saving is kept");
await $("sheet-owner-save").listeners.click();
await firstSave;
await settle();
assert.equal(ownerSaves(), ownerSavesBefore + 1, "a double click saves the owner once");
assert.match(status(), /Owner saved/);
assert.equal($("sheet-owner-save").disabled, false);
$("sheet-place").value = "";
// An owner that has not changed is not sent again.
$("sheet-owner-save").listeners.click();
await settle();
assert.equal(ownerSaves(), ownerSavesBefore + 1, "an unchanged owner is not sent");
assert.equal($("sheet-owner-save").hidden, true);
assert.match(status(), /Owner saved/);

// Downloads: the certificate plainly, the key only with both passwords.
$("sheet-download").listeners.click();
assert.deepEqual($("download-choices").children.map((c) => c.children[1].textContent), ["Certificate", "Full chain", "Certificate and key", "Key only"]);
await $("download-go").listeners.click();
await settle();
assert.deepEqual(lastRequest("/api/certificates/download").body, { fingerprint: shop.fingerprint, expected_generation: 6, pair: false });
assert.equal(downloads.at(-1).name, "shop.test.pem");
const choose = (container, value) => {
  for (const label of container.children) label.children[0].checked = label.children[0].value === value;
  container.children.find((l) => l.children[0].value === value).children[0].listeners.change();
};
choose($("download-choices"), "pair");
assert.equal($("download-secret").hidden, false);
assert.equal($("download-go-name").textContent, "Download shop.test.zip");
await $("download-go").listeners.click();
assert.match(status(), /Enter your Rootwell password/);
$("download-password").value = "the-rootwell-password";
$("download-key-password").value = "short";
await $("download-go").listeners.click();
assert.match(status(), /20 to 128/);
$("download-generate").listeners.click();
const keyPassword = $("download-key-password").value;
$("download-password").value = "not-the-password";
await $("download-go").listeners.click();
await settle();
assert.match(status(), /That Rootwell password is not right/);
assert.equal($("download-password").value, "", "the Rootwell password field is emptied after each try");
$("download-password").value = "the-rootwell-password";
await $("download-go").listeners.click();
await settle();
assert.deepEqual(lastRequest("/api/certificates/download").body, { fingerprint: shop.fingerprint, expected_generation: 6, pair: true,
  password: "the-rootwell-password", output_password: Buffer.from(keyPassword).toString("base64") });
assert.equal(downloads.at(-1).name, "shop.test.zip");
assert.equal(downloads.at(-1).blob.type, "application/zip");

// A certificate without a key: the key is checked, then saved with the password.
const mail = api.records[1];
await go(mail);
assert.match($("sheet-facts").text(), /Private key Not saved Add the key/);
$("sheet-facts").children[0].children[2].listeners.click();
assert.equal($("key-panel").hidden, false);
$("key-file").files = [new File(["synthetic-mismatch key"], "wrong.key")];
$("key-auth").value = "the-rootwell-password";
await $("key-save").listeners.click();
await settle();
assert.match(status(), /does not belong to the certificate/);
assert.equal(mail.has_private_key, false);
// Closing the sheet while the key is checked saves nothing; closing empties
// the password field, so a save then would go out without the password.
const saves = () => api.requests.filter((r) => r.url === "/api/certificates/key/save").length;
const savesBefore = saves();
$("key-file").files = [new File(["synthetic key"], "mail.key")];
$("key-auth").value = "the-rootwell-password";
const closedMidway = $("key-save").listeners.click();
$("sheet-close").listeners.click();
await closedMidway;
await settle();
assert.equal(saves(), savesBefore, "no key is saved after the sheet was closed");
assert.equal(mail.has_private_key, false);
await go(mail);
$("sheet-facts").children[0].children[2].listeners.click();
$("key-file").files = [new File(["synthetic key"], "mail.key")];
$("key-auth").value = "the-rootwell-password";
await $("key-save").listeners.click();
await settle();
assert.equal(lastRequest("/api/certificates/key/save").body.password, "the-rootwell-password");
assert.match(status(), /The key is saved/);
assert.equal($("key-auth").value, "");
assert.match($("sheet-facts").text(), /Private key Saved/);

// Delete asks first, then the list and the sheet let it go.
await go(api.records.find((r) => r.subject === "CN=old.test"));
$("sheet-delete").listeners.click();
assert.equal($("delete-dialog").hidden, false);
assert.equal($("delete-text").textContent, "old.test and its saved key leave Rootwell. Servers that use it are not changed.");
$("delete-cancel").listeners.click();
assert.equal($("delete-dialog").hidden, true);
$("sheet-delete").listeners.click();
await $("delete-go").listeners.click();
await settle();
assert.equal($("sheet").hidden, true);
assert.equal(location_.hash, "");
assert.match($("page-status").text(), /Deleted old\.test/);
assert.equal(rows().length, 3);

// Adding: several files become one bundle, leaf first, with the key.
const dropAdd = async (...files) => { $("add-start").listeners.click(); $("add-file").files = files; $("add-file").listeners.change(); await settle(); };
await dropAdd(new File([bytesOf("issuer")], "chain.pem"), new File([bytesOf("leaf")], "cert.pem"), new File([bytesOf("key")], "shop.key"));
{
  const sent = lastRequest("/api/certificates/check").body;
  const blocks = pemBlocks(Buffer.from(sent.certificate, "base64").toString());
  assert.deepEqual(blocks.map((b) => new X509Certificate(b).subject), ["CN=shop.test", "CN=Synthetic Convert Issuing CA"]);
  assert.ok(Buffer.from(sent.private_key, "base64").toString().startsWith("-----BEGIN PRIVATE KEY-----"));
  assert.equal(sent.key_password, "");
}
assert.match($("add-preview").text(), /shop\.test Synthetic Convert Issuing CA · until .+ Key matches/);
assert.equal($("add-save").disabled, false);
$("add-place").value = "Caddy on edge-3";
await $("add-save").listeners.click();
await settle();
assert.equal($("add-dialog").hidden, true);
assert.match($("page-status").text(), /Saved shop\.test/);
assert.equal(lastRequest("/api/certificates/save").body.location, "Caddy on edge-3");
assert.equal(rows().length, 4);

// The same certificate again is refused plainly.
await dropAdd(new File([bytesOf("leaf")], "cert.pem"));
assert.match($("add-status").text(), /already saved/);
$("add-close").listeners.click();

// A protected key asks for its password, then checks again.
api.records = api.records.filter((r) => r.subject !== "CN=shop.test");
await dropAdd(new File([bytesOf("leaf")], "cert.pem"), new File([bytesOf("locked_key")], "locked.key"));
assert.equal($("add-password-field").hidden, false);
assert.equal($("add-password-label").textContent, "Key password");
assert.match($("add-status").text(), /protected/);
$("add-password").value = fixture.key_password;
await $("add-unlock").listeners.click();
await settle();
assert.equal(lastRequest("/api/certificates/check").body.key_password, Buffer.from(fixture.key_password).toString("base64"));
assert.match($("add-preview").text(), /Key matches/);
$("add-close").listeners.click();

// A key that belongs elsewhere cannot be saved with the certificate.
await dropAdd(new File([bytesOf("leaf")], "cert.pem"), new File([bytesOf("other_key")], "other.key"));
assert.match($("add-status").text(), /does not belong to the certificate/);
assert.equal($("add-save").disabled, true);
$("add-close").listeners.click();

// Files with more than one certificate ask which one to keep.
api.selection = true;
await dropAdd(new File([bytesOf("leaf"), bytesOf("issuer")], "bundle.pem"));
assert.equal($("add-pick").hidden, false);
assert.deepEqual($("add-choices").children.map((c) => c.children[1].textContent), ["shop.test", "Synthetic Convert Issuing CA"]);
const leafChoice = $("add-choices").children[0].children[0];
leafChoice.checked = true;
await leafChoice.listeners.change();
await settle();
assert.equal(lastRequest("/api/certificates/check").body.primary_fingerprint, leafChoice.value);
assert.equal($("add-pick").hidden, true);
assert.equal($("add-save").disabled, false);
api.selection = false;
$("add-close").listeners.click();

// A PFX opens with its password; its key travels locked.
await dropAdd(new File([bytesOf("pfx")], "shop.pfx"));
assert.equal($("add-password-label").textContent, "PFX password");
$("add-password").value = "not-the-password";
await $("add-unlock").listeners.click();
await settle();
assert.match($("add-status").text(), /does not open this PFX/);
$("add-password").value = fixture.pfx_password;
await $("add-unlock").listeners.click();
await settle();
{
  const sent = lastRequest("/api/certificates/check").body;
  assert.ok(Buffer.from(sent.private_key, "base64").toString().startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
  assert.ok(sent.key_password.length > 0);
}
assert.match($("add-preview").text(), /shop\.test .* Key matches/);
assert.equal($("add-save").disabled, false);

// Escape closes the dialog; leaving the page forgets what was chosen.
document.listeners.keydown({ key: "Escape" });
assert.equal($("add-dialog").hidden, true);
win.listeners.pagehide();
assert.equal($("download-password").value, "");

console.log("Certificates lists, filters, edits, downloads, deletes and adds certificates through the inventory API.");
