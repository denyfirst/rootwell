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
  "/api/certificates/save", "/api/inventory", "/api/inventory/delete", "/api/requests/create", "/api/requests/delete"]);
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
const engine = Object.freeze({ explore: rootwellExplore, analyze: rootwellAnalyze, exportPublic: rootwellExport, readFile: rootwellReadFile, unlockKey: rootwellUnlockKey, module: {} });
const fixture = JSON.parse(execFileSync("go", ["run", "./scripts/generate-convert-fixture.go"], { encoding: "utf8" }));
const bytesOf = (name) => Uint8Array.from(Buffer.from(fixture[name], "base64"));

// ── A stand-in for the inventory API ─────────────────────────────────────
const day = 86400000;
const iso = (t) => new Date(Math.floor(t / 1000) * 1000).toISOString().replace(".000", "");
const hexFingerprint = (n) => Array.from({ length: 32 }, (_, i) => ((n * 29 + i * 7) % 256).toString(16).padStart(2, "0").toUpperCase()).join(":");
const record = (n, name, days, extra = {}) => ({ fingerprint: hexFingerprint(n), subject: "CN=" + name, issuer: "CN=Synthetic CA " + n,
  dns_names: [name], not_before: iso(Date.now() - 30 * day), not_after: iso(Date.now() + days * day), owner: "", location: "", locations: [],
  import_generation: 1, imported_at: iso(Date.now() - 2 * day), has_private_key: false, key_status: "not-added", bundle_count: 0,
  ip_addresses: [], key_type: "ECDSA P-256", chain: [], expiry: { status: "valid" }, ...extra });
// fresh: a phone code was entered in the last ten minutes. freshAnswer is what
// the page's code dialog does when Rootwell asks for one.
// waiting: requests whose key Rootwell keeps. plan: what the next check says
// a save would do (finish a request, renew or replace a saved certificate).
const api = { generation: 1, records: [], requests: [], waiting: [], plan: null, selection: false, fresh: true, freshAnswer: true, freshAsked: 0 };
const csrText = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBsynthetic\n-----END CERTIFICATE REQUEST-----\n";
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
  const passphrase = Buffer.from(body.key_password || "", "base64");
  try {
    const privateKey = createPrivateKey({ key, passphrase });
    return certificate.checkPrivateKey(privateKey) ? "matched" : "mismatch";
  } catch {
    return passphrase.length ? "wrong" : "locked";
  }
}
const reply = (status, body, headers = {}) => new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
const listing = (records) => ({ generation: api.generation, records, requests: api.waiting, verification: "not-performed" });
async function fetch(url, options) {
  const body = options.body ? JSON.parse(options.body) : null;
  api.requests.push({ url, body, headers: options.headers });
  assert.equal(options.headers["X-Rootwell-Request"], "1");
  assert.equal(options.credentials, "same-origin");
  // holdList keeps the list from coming back until the test lets it.
  if (url === "/api/inventory") return api.holdList ? api.holdList.then(() => reply(200, listing(api.records))) : reply(200, listing(api.records));
  if (body.expected_generation !== api.generation) return reply(409, "stale generation");
  const target = api.records.find((r) => r.fingerprint === body.fingerprint);
  const change = () => { api.generation++; return reply(200, listing([target])); };
  switch (url) {
    case "/api/inventory/owner": target.owner = body.owner; return change();
    case "/api/inventory/locations": target.locations.push(body.location); target.location ||= body.location; return change();
    case "/api/inventory/locations/change": target.locations = target.locations.filter((l) => l !== body.old_location); target.location = target.locations[0] || ""; return change();
    case "/api/inventory/delete":
      if (target.has_private_key && !api.fresh) return reply(428, "Enter a code from your phone first.");
      assert.equal(body.typed_fingerprint, body.fingerprint);
      assert.equal(body.confirmation, "delete-public-record");
      api.records = api.records.filter((r) => r !== target);
      api.generation++;
      return reply(200, { fingerprint: body.fingerprint, generation: api.generation, deleted: true });
    case "/api/requests/create": {
      const renewed = api.records.find((r) => r.fingerprint === body.renews);
      if (body.renews && !renewed) return reply(404, "not found");
      if (renewed && api.waiting.some((q) => q.renews === body.renews)) return reply(409, "waiting", { "X-Rootwell-Refusal": "renewal-waiting" });
      const request = { public_fingerprint: hexFingerprint(90 + api.waiting.length), created_at: iso(Date.now()), csr: csrText, subject: "CN=x",
        dns_names: renewed ? renewed.dns_names : body.dns_names, ip_addresses: [], key_type: body.algorithm === "rsa-2048" ? "RSA 2048" : "ECDSA P-256", renews: body.renews };
      api.waiting.push(request);
      api.generation++;
      return reply(201, { generation: api.generation, request });
    }
    case "/api/requests/delete":
      if (!api.fresh) return reply(428, "Enter a code from your phone first.");
      api.waiting = api.waiting.filter((q) => q.public_fingerprint !== body.public_fingerprint);
      api.generation++;
      return reply(200, { generation: api.generation, deleted: true });
    case "/api/certificates/download":
      assert.equal("password" in body, false, "no Rootwell password is sent");
      if ((body.pair || body.key_only) && !api.fresh) return reply(428, "Enter a code from your phone first.");
      return new Response(body.pair ? "zip-bytes" : "-----BEGIN CERTIFICATE-----\n", { status: 200 });
    case "/api/certificates/key/check":
    case "/api/certificates/key/save": {
      assert.equal("password" in body, false, "no Rootwell password is sent");
      const status = Buffer.from(body.private_key, "base64").toString().includes("synthetic-mismatch") ? "mismatch" : "matched";
      if (url.endsWith("save")) { target.has_private_key = true; target.key_status = status; api.generation++; }
      return reply(200, listing([{ ...target, has_private_key: true, key_status: status }]));
    }
    default: {
      const { chosen, certificates, toRecord } = parse(body);
      if (api.selection && !body.primary_fingerprint) return reply(200, listing(certificates.map(toRecord)), { "X-Rootwell-Selection": "required" });
      const status = keyStatus(chosen, body);
      if (status === "locked") return reply(422, "enter the key password");
      if (status === "wrong") return reply(422, "That password does not open the key.", { "X-Rootwell-Refusal": "key-password-wrong" });
      const result = { ...toRecord(chosen), has_private_key: status !== "not-added", key_status: status };
      if (api.records.some((r) => r.fingerprint === result.fingerprint)) return reply(409, "duplicate", { "X-Rootwell-Refusal": "duplicate-certificate" });
      const plan = api.plan || {};
      if (url === "/api/certificates/check") return reply(200, listing([{ ...result, ...plan }]));
      assert.equal(body.fingerprint, result.fingerprint);
      assert.equal(body.allow_mismatch, false);
      if (plan.finishes_request) Object.assign(result, { has_private_key: true, key_status: "matched" });
      const older = api.records.find((r) => r.fingerprint === (plan.renews || body.replaces));
      if (older) {
        older.replaced_by = result.fingerprint;
        older.replaced_at = iso(Date.now());
        Object.assign(result, { replaces: older.fingerprint, owner: result.owner || older.owner, locations: [...older.locations, ...result.locations] });
      }
      if (plan.renews) api.waiting = api.waiting.filter((q) => q.renews !== plan.renews);
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
  querySelectorAll(selector) { return this.all().filter((n) => n !== this && n.tag === selector); }
  text() { return [this.textContent, ...this.children.map((c) => c.text())].join(" ").replace(/\s+/g, " ").trim(); }
}
const ids = {};
// Dialogs and their scrims start hidden, as certificates.html has them.
const $ = (id) => (ids[id] ??= Object.assign(new Node(/file$|password|place$|owner$|search|^add-replace$/.test(id) ? "input" : "div"),
  /-(dialog|scrim)$/.test(id) ? { hidden: true } : {}));
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
    if (!answer || answer.ok !== true) throw Object.assign(new Error("PFX preparation failed"), { code: answer && answer.error });
    return answer.result;
  } },
  rootwellFresh: async () => { api.freshAsked++; api.fresh = api.freshAnswer; return api.freshAnswer; },
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
assert.match($("sheet-facts").text(), /^Private key Saved Key type ECDSA P-256 Fingerprint .+ Added /);
// No issuer was saved with it: the chain says where it stops.
assert.equal($("sheet-chain").text(), "shop.test This certificate 80 days left Synthetic CA 1 Not saved with this certificate");
assert.deepEqual($("sheet-chain").children.map((n) => n.className), ["link ok", "link gap"], "an issuer not saved is a quiet gap, not an error");
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

// Downloads: the certificate plainly; the key locked with its own password, and
// only after a code from the phone in the last ten minutes.
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
$("download-key-password").value = "short";
await $("download-go").listeners.click();
assert.match(status(), /20 to 128/);
$("download-generate").listeners.click();
const keyPassword = $("download-key-password").value;
api.fresh = false;
api.freshAnswer = false;
const downloadsBefore = downloads.length;
await $("download-go").listeners.click();
await settle();
assert.equal(api.freshAsked, 1, "the page asks for a phone code");
assert.match(status(), /Nothing changed. That needs a code from your phone/);
assert.equal(downloads.length, downloadsBefore, "nothing is downloaded without the code");
api.freshAnswer = true;
await $("download-go").listeners.click();
await settle();
assert.equal(api.freshAsked, 2);
assert.deepEqual(lastRequest("/api/certificates/download").body, { fingerprint: shop.fingerprint, expected_generation: 6, pair: true,
  output_password: Buffer.from(keyPassword).toString("base64") });
assert.equal(downloads.at(-1).name, "shop.test.zip");
assert.equal(downloads.at(-1).blob.type, "application/zip");

// A certificate without a key: the key is checked, then saved.
const mail = api.records[1];
await go(mail);
assert.match($("sheet-facts").text(), /Private key Not saved Add the key/);
$("sheet-facts").children[0].children[2].listeners.click();
assert.equal($("key-panel").hidden, false);
$("key-file").files = [new File(["synthetic-mismatch key"], "wrong.key")];
await $("key-save").listeners.click();
await settle();
assert.match(status(), /does not belong to the certificate/);
assert.equal(mail.has_private_key, false);
// Closing the sheet while the key is checked saves nothing.
const saves = () => api.requests.filter((r) => r.url === "/api/certificates/key/save").length;
const savesBefore = saves();
$("key-file").files = [new File(["synthetic key"], "mail.key")];
const closedMidway = $("key-save").listeners.click();
$("sheet-close").listeners.click();
await closedMidway;
await settle();
assert.equal(saves(), savesBefore, "no key is saved after the sheet was closed");
assert.equal(mail.has_private_key, false);
await go(mail);
$("sheet-facts").children[0].children[2].listeners.click();
$("key-file").files = [new File(["synthetic key"], "mail.key")];
await $("key-save").listeners.click();
await settle();
assert.equal(lastRequest("/api/certificates/key/save").body.allow_mismatch, false);
assert.match(status(), /The key is saved/);
// A key added later is read like one in Add: an old-style locked key asks
// for its password and goes opened; a key after EC PARAMETERS goes alone.
{
  const later = api.records.find((r) => r.subject === "CN=api.test");
  const keySent = () => Buffer.from(lastRequest("/api/certificates/key/check").body.private_key, "base64").toString();
  await go(later);
  $("sheet-facts").children[0].children[2].listeners.click();
  const checksBefore = api.requests.filter((r) => r.url === "/api/certificates/key/check").length;
  $("key-file").files = [new File([bytesOf("old_key")], "old.key")];
  await $("key-save").listeners.click();
  await settle();
  assert.equal(status(), "This key is locked. Enter its password.");
  assert.equal($("key-password-field").hidden, false);
  $("key-password").value = "not-the-key-password";
  await $("key-save").listeners.click();
  await settle();
  assert.equal(status(), "That password does not open the key.");
  assert.equal(api.requests.filter((r) => r.url === "/api/certificates/key/check").length, checksBefore, "a locked old-style key never reaches the server");
  $("key-password").value = fixture.key_password;
  await $("key-save").listeners.click();
  await settle();
  assert.ok(keySent().startsWith("-----BEGIN EC PRIVATE KEY-----\n") && !keySent().includes("Proc-Type"));
  assert.equal(lastRequest("/api/certificates/key/check").body.key_password, "");
  $("key-password").value = "";
  $("key-file").files = [new File([bytesOf("ec_params_key")], "params.key")];
  await $("key-save").listeners.click();
  await settle();
  assert.ok(!keySent().includes("EC PARAMETERS") && keySent().includes("PRIVATE KEY"));
  $("sheet-close").listeners.click();
}
assert.match($("sheet-facts").text(), /Private key Saved/);

// Delete asks first, then the list and the sheet let it go.
await go(api.records.find((r) => r.subject === "CN=old.test"));
$("sheet-delete").listeners.click();
assert.equal($("delete-dialog").hidden, false);
assert.equal($("delete-text").textContent, "old.test and its saved key leave Rootwell. Servers that use it are not changed.");
$("delete-cancel").listeners.click();
assert.equal($("delete-dialog").hidden, true);
// The dialog belongs to the certificate it named: another sheet closes it,
// and its button then deletes nothing.
{
  const deletes = () => api.requests.filter((r) => r.url === "/api/inventory/delete").length;
  const before = deletes();
  $("sheet-delete").listeners.click();
  await go(mail);
  assert.equal($("delete-dialog").hidden, true, "another sheet closes the delete dialog");
  await $("delete-go").listeners.click();
  await settle();
  assert.equal(deletes(), before, "a closed delete dialog deletes nothing");
  await go(api.records.find((r) => r.subject === "CN=old.test"));
}
// It has a saved key, so deleting it needs a phone code too.
api.fresh = false;
api.freshAnswer = false;
$("sheet-delete").listeners.click();
await $("delete-go").listeners.click();
await settle();
assert.match(status(), /Nothing changed. That needs a code from your phone/);
assert.equal(rows().length, 4, "nothing was deleted");
api.freshAnswer = true;
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
// The list is slow to come back after the save: the page says Saved at once,
// and the next change already names the count the save answered with.
let releaseList;
api.holdList = new Promise((resolve) => { releaseList = resolve; });
const saving = $("add-save").listeners.click();
await settle();
assert.equal($("add-dialog").hidden, true);
assert.match($("page-status").text(), /Saved shop\.test/, "Saved shows before the list comes back");
assert.equal(lastRequest("/api/certificates/save").body.location, "Caddy on edge-3");

// The same certificate again is refused plainly, even before the list is back.
await dropAdd(new File([bytesOf("leaf")], "cert.pem"));
assert.equal(lastRequest("/api/certificates/check").body.expected_generation, api.generation, "the check names the new count");
assert.match($("add-status").text(), /already saved/);
api.holdList = null;
releaseList();
await saving;
await settle();
assert.equal(rows().length, 4);
$("add-close").listeners.click();

// A protected key asks for its password, then checks again.
api.records = api.records.filter((r) => r.subject !== "CN=shop.test");
await dropAdd(new File([bytesOf("leaf")], "cert.pem"), new File([bytesOf("locked_key")], "locked.key"));
assert.equal($("add-password-field").hidden, false);
assert.equal($("add-password-label").textContent, "Key password");
assert.match($("add-status").text(), /protected/);
// A wrong password is named as wrong, and the field stays.
$("add-password").value = "not-the-key-password";
await $("add-unlock").listeners.click();
await settle();
assert.equal($("add-status").text(), "That password does not open the key.");
assert.equal($("add-password-field").hidden, false);
$("add-password").value = fixture.key_password;
await $("add-unlock").listeners.click();
await settle();
assert.equal(lastRequest("/api/certificates/check").body.key_password, Buffer.from(fixture.key_password).toString("base64"));
assert.match($("add-preview").text(), /Key matches/);
assert.equal($("add-password-field").hidden, true, "the password field goes once the key opened");
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
$("add-close").listeners.click();

// Files are read by what they hold, not by their names.
const checked = () => lastRequest("/api/certificates/check").body;
const sentBlocks = () => pemBlocks(Buffer.from(checked().certificate, "base64").toString());
const sentKey = () => Buffer.from(checked().private_key, "base64").toString();
// A Windows-style 3DES PFX with another name.
await dropAdd(new File([bytesOf("pfx_legacy")], "shop-export.bin"));
assert.equal($("add-chip-info").textContent, "PFX");
assert.equal($("add-password-label").textContent, "PFX password");
$("add-password").value = fixture.pfx_password;
await $("add-unlock").listeners.click();
await settle();
assert.match($("add-preview").text(), /shop\.test .* Key matches/);
assert.equal($("add-password-field").hidden, true);
$("add-close").listeners.click();
// A PFX saved without a password opens with the field left empty.
await dropAdd(new File([bytesOf("pfx_empty")], "nas.pfx"));
assert.equal($("add-password").placeholder, "Leave empty if it has none");
await $("add-unlock").listeners.click();
await settle();
assert.match($("add-preview").text(), /Key matches/);
$("add-close").listeners.click();
// An empty password on a locked PFX asks for it; a protection Rootwell does
// not read says so, never that the password is wrong.
await dropAdd(new File([bytesOf("pfx_rc2")], "mail.p12"));
await $("add-unlock").listeners.click();
await settle();
assert.equal($("add-status").text(), "This PFX has a password. Enter it.");
$("add-close").listeners.click();
await dropAdd(new File([bytesOf("pfx_unsupported")], "newest.pfx"));
$("add-password").value = fixture.pfx_password;
await $("add-unlock").listeners.click();
await settle();
assert.equal($("add-status").text(), "This PFX uses a protection Rootwell cannot read. Export it again with AES-256 or TripleDES.");
$("add-close").listeners.click();
// One PEM with the certificate, its key and its chain is split.
for (const name of ["combined", "nodes"]) {
  await dropAdd(new File([bytesOf(name)], name + ".pem"));
  assert.equal($("add-chip-info").textContent, "Certificate and private key");
  assert.deepEqual(sentBlocks().map((b) => new X509Certificate(b).subject), ["CN=shop.test", "CN=Synthetic Convert Issuing CA"]);
  assert.ok(sentKey().startsWith("-----BEGIN PRIVATE KEY-----") && !sentKey().includes("Attributes"), name + " key is sent alone");
  assert.match($("add-preview").text(), /Key matches/);
  $("add-close").listeners.click();
}
// A P7B with an EC key after its parameters; a certificate after a byte order mark.
await dropAdd(new File([bytesOf("p7b")], "chain.p7b"), new File([bytesOf("ec_params_key")], "shop.key"));
assert.equal(sentBlocks().length, 2);
assert.ok(sentKey().startsWith("-----BEGIN EC PRIVATE KEY-----") && !sentKey().includes("EC PARAMETERS"));
assert.match($("add-preview").text(), /Key matches/);
$("add-close").listeners.click();
await dropAdd(new File([bytesOf("bom_leaf")], "notepad.crt"));
assert.equal(sentBlocks().length, 1);
assert.equal($("add-save").disabled, false);
$("add-close").listeners.click();
// An old-style locked key asks for its password at once and is opened here.
await dropAdd(new File([bytesOf("leaf")], "cert.pem"), new File([bytesOf("old_key")], "old.key"));
assert.equal($("add-password-field").hidden, false);
assert.equal($("add-password-label").textContent, "Key password");
assert.equal($("add-status").text(), "This key is locked. Enter its password.");
$("add-password").value = "not-the-key-password";
await $("add-unlock").listeners.click();
await settle();
assert.equal($("add-status").text(), "That password does not open the key.");
$("add-password").value = fixture.key_password;
await $("add-unlock").listeners.click();
await settle();
assert.ok(sentKey().startsWith("-----BEGIN EC PRIVATE KEY-----\n") && !sentKey().includes("Proc-Type"));
assert.equal(checked().key_password, "");
assert.equal($("add-password-field").hidden, true);
assert.match($("add-preview").text(), /Key matches/);
$("add-close").listeners.click();
// The file that is wrong is the one named.
await dropAdd(new File([bytesOf("leaf")], "cert.pem"), new File(["just some notes\n"], "notes.txt"));
assert.equal($("add-status").text(), "notes.txt is not a certificate, key or PFX file Rootwell can read.");
await dropAdd(new File([bytesOf("csr")], "request.pem"));
assert.equal($("add-status").text(), "request.pem is a certificate request, not a certificate. Send it to your certificate provider.");

// Escape closes the dialog; leaving the page forgets what was chosen.
document.listeners.keydown({ key: "Escape" });
assert.equal($("add-dialog").hidden, true);
win.listeners.pagehide();
assert.equal($("download-key-password").value, "", "the key file password is forgotten");

// Renewal: a request for the same names, with a new key Rootwell keeps; the
// certificate that comes back takes the older one's place.
{
  api.records = [record(20, "shop.test", 10, { has_private_key: true, key_status: "matched", key_type: "RSA 2048", locations: ["web-1"], location: "web-1", owner: "Web team" }),
    record(21, "root.test", 3000, { dns_names: [] })];
  api.waiting = [];
  api.generation = 30;
  api.fresh = true;
  for (const key of Object.keys(ids)) delete ids[key];
  for (const value of ["ec-p256", "rsa-2048"]) {
    const radio = new Node("input");
    Object.assign(radio, { type: "radio", value });
    $("renew-keys").appendChild(new Node("label")).appendChild(radio);
  }
  load(source, "certificates.js");
  await settle();
  assert.equal($("waiting").hidden, true, "no request waits yet");
  const old = api.records[0];
  await go(old);
  assert.equal($("sheet-renew").hidden, false);
  assert.equal($("sheet-note").hidden, true);
  $("sheet-renew").listeners.click();
  assert.equal($("renew-dialog").hidden, false);
  assert.equal($("renew-title").textContent, "Renew shop.test");
  assert.equal($("renew-names").text(), "shop.test");
  assert.equal($("renew-keys").querySelector("input:checked").value, "rsa-2048", "an RSA certificate is renewed with RSA unless the person picks otherwise");
  await $("renew-go").listeners.click();
  await settle();
  assert.deepEqual(lastRequest("/api/requests/create").body, { expected_generation: 30, algorithm: "rsa-2048", renews: old.fingerprint });
  assert.equal($("renew-form").hidden, true);
  assert.equal($("renew-steps").hidden, false);
  assert.equal($("renew-go").hidden, true);
  assert.equal($("renew-cancel").textContent, "Done");
  assert.equal($("renew-file").textContent, "shop.test.csr");
  $("renew-download").listeners.click();
  assert.equal(downloads.at(-1).name, "shop.test.csr");
  assert.equal(downloads.at(-1).blob.type, "application/pkcs10");
  assert.equal(await downloads.at(-1).blob.text(), csrText);
  // The list shows the request waiting; the sheet says a renewal waits, and
  // offers no second one.
  assert.equal($("waiting").hidden, false);
  assert.equal($("waiting-count").textContent, "1 request");
  assert.match($("waiting-rows").text(), /^shop\.test Requested .+ · RSA 2048 · renews shop\.test Download Cancel$/);
  assert.equal($("sheet-renew").hidden, true, "one renewal at a time");
  assert.match($("sheet-note").text(), /^A renewal is waiting for its certificate, requested .+\. Download request$/);
  $("renew-cancel").listeners.click();
  assert.equal($("renew-dialog").hidden, true);
  // A certificate that names nothing, such as a root, has no Renew.
  await go(api.records[1]);
  assert.equal($("sheet-renew").hidden, true);
  $("sheet-close").listeners.click();

  // The certificate comes back: Add says it is the renewal, its key comes
  // from the request, and saving it replaces the older one by itself.
  api.plan = { finishes_request: true, renews: old.fingerprint };
  await dropAdd(new File([bytesOf("leaf")], "renewed.pem"));
  assert.match($("add-preview").text(), /Key from your request/);
  assert.equal($("add-renews").hidden, false);
  assert.equal($("add-renews").textContent, "This is the renewal of shop.test. It takes that one's place.");
  assert.equal($("add-replace-field").hidden, true, "a renewal is not asked about");
  await $("add-save").listeners.click();
  await settle();
  api.plan = null;
  assert.equal("replaces" in lastRequest("/api/certificates/save").body, false, "a renewal replaces by itself");
  assert.match($("page-status").text(), /^Saved shop\.test\. Its key came from your request\. It took the place of shop\.test\.$/);
  assert.equal($("waiting").hidden, true, "the finished request no longer waits");
  const tiles = $("stats").children.map((t) => t.text());
  assert.equal(tiles[0], "2 All", "a replaced certificate no longer counts");
  assert.equal(tiles.at(-1), "1 Replaced");
  assert.ok(!rows().some((r) => /Replaced/.test(r.text())), "a replaced certificate leaves the main list");
  $("stats").children.at(-1).listeners.click();
  assert.deepEqual(rows().map(rowText), ["shop.test Synthetic CA 20"]);
  assert.match(rows()[0].text(), /Replaced/);
  await go(old);
  assert.equal($("sheet-pill").text(), "Replaced");
  assert.match($("sheet-note").text(), /^Replaced on .+ by shop\.test, which lasts until .+\. Open it$/);
  assert.equal($("sheet-renew").hidden, true);
  const newer = api.records.find((r) => r.replaces === old.fingerprint);
  assert.equal($("sheet-note").children[0].children.at(-1).href, "#" + newer.fingerprint.replace(/:/g, "").toLowerCase());
  await go(newer);
  assert.match($("sheet-facts").text(), /Replaces shop\.test, until /);
  assert.deepEqual(newer.locations, ["web-1"], "the renewal keeps where the older one is used");
  $("sheet-close").listeners.click();
  $("stats").children.at(-1).listeners.click();

  // Another newer certificate for the same names may take the place, if the
  // person keeps the box ticked.
  api.plan = { replaces: api.records[1].fingerprint };
  await dropAdd(new File([bytesOf("issuer")], "issuer.pem"));
  assert.equal($("add-renews").hidden, true);
  assert.equal($("add-replace-field").hidden, false);
  assert.match($("add-replace-text").textContent, /^Take the place of root\.test, which ends .+\. It keeps where that one is used and who looks after it\.$/);
  $("add-replace").checked = false;
  await $("add-save").listeners.click();
  await settle();
  assert.equal("replaces" in lastRequest("/api/certificates/save").body, false, "an unticked box replaces nothing");
  api.records.pop();
  await dropAdd(new File([bytesOf("issuer")], "issuer.pem"));
  assert.equal($("add-replace").checked, true, "the box starts ticked");
  await $("add-save").listeners.click();
  await settle();
  api.plan = null;
  assert.equal(lastRequest("/api/certificates/save").body.replaces, api.records[1].fingerprint);

  // Giving up a request deletes its new key, so it asks first and needs a
  // phone code.
  api.waiting = [{ public_fingerprint: hexFingerprint(95), created_at: iso(Date.now()), csr: csrText, subject: "CN=new.test",
    dns_names: ["new.test"], ip_addresses: [], key_type: "ECDSA P-256" }];
  for (const key of Object.keys(ids)) delete ids[key];
  load(source, "certificates.js");
  await settle();
  assert.match($("waiting-rows").text(), /^new\.test Requested .+ · ECDSA P-256 Download Cancel$/);
  $("waiting-rows").children[0].children[3].listeners.click();
  assert.equal($("cancel-dialog").hidden, false);
  assert.equal($("cancel-text").textContent, "The request for new.test and its new key leave Rootwell. A certificate made from this request will then have no key.");
  $("cancel-keep").listeners.click();
  assert.equal($("cancel-dialog").hidden, true);
  assert.equal(api.waiting.length, 1);
  api.fresh = false;
  api.freshAnswer = false;
  $("waiting-rows").children[0].children[3].listeners.click();
  await $("cancel-go").listeners.click();
  await settle();
  assert.match($("page-status").text(), /Nothing changed. That needs a code from your phone/);
  assert.equal(api.waiting.length, 1, "nothing was given up without the code");
  api.freshAnswer = true;
  $("waiting-rows").children[0].children[3].listeners.click();
  await $("cancel-go").listeners.click();
  await settle();
  assert.deepEqual(lastRequest("/api/requests/delete").body, { expected_generation: api.generation - 1, public_fingerprint: hexFingerprint(95) });
  assert.match($("page-status").text(), /Cancelled the request for new\.test\./);
  assert.equal($("waiting").hidden, true);
  // A refusal the server names is said in its words: here a renewal another
  // page asked for meanwhile.
  const current = api.records.find((r) => r.fingerprint === newer.fingerprint);
  await go(current);
  assert.equal($("sheet-renew").hidden, false);
  api.waiting = [{ public_fingerprint: hexFingerprint(96), created_at: iso(Date.now()), csr: csrText, dns_names: ["shop.test"], ip_addresses: [], key_type: "ECDSA P-256", renews: current.fingerprint }];
  $("sheet-renew").listeners.click();
  await $("renew-go").listeners.click();
  await settle();
  assert.equal($("renew-status").text(), "A renewal of this certificate is waiting already.");
  assert.equal($("renew-form").hidden, false);
  $("renew-close").listeners.click();
  api.waiting = [];
}

// Names as people know them: the issuer's organization, a name in its own
// letters, an address; search finds each of them, and the sheet draws the chain.
{
  const leChain = [{ subject: "CN=YE2,O=Let's Encrypt,C=US", issuer: "CN=ISRG Root X2,O=Internet Security Research Group,C=US", not_after: iso(Date.now() + 500 * day), root: false },
    { subject: "CN=ISRG Root X2,O=Internet Security Research Group,C=US", issuer: "CN=ISRG Root X2,O=Internet Security Research Group,C=US", not_after: iso(Date.now() + 3000 * day), root: true }];
  api.records = [record(10, "xn--bak-lua.lab.az", 60, { issuer: "CN=YE2,O=Let's Encrypt,C=US", chain: leChain }),
    record(11, "nas", 90, { dns_names: [], ip_addresses: ["10.0.0.5", "fd00::5"], key_type: "RSA 2048" }),
    ...[12, 13, 14, 15, 16, 17].map((n) => record(n, "host" + n + ".test", 100 + n))];
  for (const key of Object.keys(ids)) delete ids[key];
  load(source, "certificates.js");
  await settle();
  assert.equal(rowText(rows()[0]), "bak\u0131.lab.az Let's Encrypt");
  assert.equal(rowText(rows()[1]), "nas Synthetic CA 11");
  const find = (query) => { $("search").value = query; $("search").listeners.input(); return rows().map((r) => r.children[0].children[1].children[0].textContent); };
  assert.deepEqual(find("10.0.0.5"), ["nas"]);
  assert.deepEqual(find("let's encrypt"), ["bak\u0131.lab.az"]);
  assert.deepEqual(find("bak\u0131"), ["bak\u0131.lab.az"]);
  assert.deepEqual(find("xn--bak"), ["bak\u0131.lab.az"]);
  assert.deepEqual(find("ye2"), ["bak\u0131.lab.az"]);
  find("");
  await go(api.records[0]);
  assert.match($("sheet-hero").text(), /^bak\u0131\.lab\.az Issued by Let's Encrypt \u00b7 YE2/);
  assert.equal($("sheet-names").text(), "bak\u0131.lab.az (xn--bak-lua.lab.az)");
  assert.match($("sheet-chain").text(), /^bak\u0131\.lab\.az This certificate .* YE2 Intermediate .* ISRG Root X2 Root /);
  assert.equal($("sheet-chain").children.filter((n) => /gap/.test(n.className)).length, 0, "a chain that reaches its root has no gap");
  await go(api.records[1]);
  assert.equal($("sheet-names").text(), "10.0.0.5 fd00::5");
  assert.equal($("sheet-website").href, "/website-check#10.0.0.5");
  assert.equal($("sheet-website").hidden, false);
  assert.match($("sheet-facts").text(), /Key type RSA 2048/);
}

console.log("Certificates lists, filters, edits, downloads, deletes and adds certificates through the inventory API.");
