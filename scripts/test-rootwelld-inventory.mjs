import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import { TextEncoder } from "node:util";

const source = fs.readFileSync(new URL("../cmd/rootwelld/auth/inventory.js", import.meta.url), "utf8");
assert.doesNotMatch(source, /innerHTML|localStorage|sessionStorage|console\./);
assert.doesNotMatch(source, /createObjectURL|selectedForExport|public-inventory-export/, "Inventory must not offer metadata download");
const html = fs.readFileSync(new URL("../cmd/rootwelld/auth/inventory.html", import.meta.url), "utf8");
assert.match(html, /<meta name="referrer" content="same-origin">/);
assert.doesNotMatch(html, /Export selected records|preview-export-button|download-export-button/);
assert.match(html, /<body class="workspace inventory-workspace">/);
assert.match(html, /<link rel="stylesheet" href="\/style.css">[\s\S]*<link rel="stylesheet" href="\/inventory.css">/);
assert.match(html, /<a class="rail-item" href="\/index.html">[\s\S]*?Workbench<\/a>/);
assert.match(html, /<a class="rail-item" href="\/certificates" aria-current="page">/);
assert.equal((html.match(/aria-current="page"/g) || []).length, 1);
assert.match(html, /<details class="card import-card">\s*<summary><h2 id="save-heading">Advanced<\/h2><span>Import many unrelated public certificates/,
  "bulk importing must stay under collapsed Advanced");
assert.match(html, /<div id="monitor-summary"[^>]*role="status"/);
assert.match(html, /<strong>Background checks and history<\/strong><p id="background-status"/,
  "worker failures must not be hidden inside details");
assert.match(html, /<aside class="storage-note" aria-label="Storage boundary">/,
  "the narrow-screen Workbench boundary rule must not hide Inventory's upload notice");
assert.match(html, /Saved encrypted on your own Rootwell[\s\S]*Check sends your selected certificate and optional key/);
assert.doesNotMatch(html, /No certificate uploads|src="\/(?:app|private-key|pfx|csr)\.js"/,
  "shared appearance must not misrepresent Inventory as offline or run Workbench processors");
assert.match(html, /id="save-button" type="submit" disabled/);
const inventoryCSS = fs.readFileSync(new URL("../cmd/rootwelld/auth/inventory.css", import.meta.url), "utf8");
assert.doesNotMatch(inventoryCSS, /:root|color-scheme:|\.storage-note[^{}]*\{[^}]*display:\s*none/);
assert.match(inventoryCSS, /\.inventory-workspace \.filters \{ display: grid/);
assert.match(inventoryCSS, /@media \(max-width: 64rem\) \{\s*\.inventory-workspace \.filters \{ grid-template-columns: minmax\(0, 1fr\)/,
  "filters must stack before the desktop sidebar makes their labels cramped");

// The only persisted preference is the existing, non-secret light/dark choice.
// Shared appearance must not add certificate/notes/session persistence.
const themeSource = fs.readFileSync(new URL("../web/workbench/theme.js", import.meta.url), "utf8");
assert.match(html, /<script src="\/theme.js"><\/script>/);
function themeFixture(stored, broken = false) {
  const writes = [], listeners = {}, button = { hidden: true, setAttribute() {}, addEventListener(name, fn) { listeners[name] = fn; } };
  const root = { dataset: {} };
  const storage = { getItem(key) { assert.equal(key, "rootwell-workbench-theme"); if (broken) throw new Error(); return stored; },
    setItem(key, value) { assert.equal(key, "rootwell-workbench-theme"); assert.ok(["light", "dark"].includes(value)); if (broken) throw new Error(); stored = value; writes.push([key, value]); } };
  vm.runInNewContext(themeSource, { document: { documentElement: root, getElementById(id) { assert.equal(id, "theme-toggle"); return button; },
    addEventListener(name, fn) { assert.equal(name, "DOMContentLoaded"); fn(); } }, window: { localStorage: storage, matchMedia: () => ({ matches: false }) } });
  return { root, button, writes, click: () => listeners.click() };
}
const sharedTheme = themeFixture("dark");
assert.equal(sharedTheme.root.dataset.theme, "dark");
assert.equal(sharedTheme.button.hidden, false);
sharedTheme.click(); assert.deepEqual(sharedTheme.writes, [["rootwell-workbench-theme", "light"]]);
const malformedTheme = themeFixture("<secret-not-a-theme>");
assert.equal(malformedTheme.root.dataset.theme, undefined);
const blockedTheme = themeFixture(null, true); blockedTheme.click();
assert.equal(blockedTheme.root.dataset.theme, "dark"); assert.equal(blockedTheme.writes.length, 0);

class Element {
  constructor() { this.value = ""; this.textContent = ""; this.children = []; this.listeners = {}; this.disabled = false; this.checked = false; this.files = []; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  appendChild(node) { this.children.push(node); }
  replaceChildren() { this.children = []; }
  click() { this.clicked = true; }
  remove() { this.removed = true; }
}
function action(item, label) {
  const details = item.children.find(node => node.className === "record-details");
  assert.ok(details, "manage controls must be inside collapsed details");
  return details.children.find(node => node.textContent === label);
}

const ids = ["inventory-form", "certificate-file", "owner", "location", "save-button", "save-status", "refresh-button", "list-status", "counts", "records",
  "location-panel", "location-form", "location-target", "new-location", "location-button", "location-cancel", "location-status",
  "owner-panel", "owner-form", "owner-target", "new-owner", "owner-button", "owner-cancel", "owner-status"];
ids.push("location-manage-panel", "location-manage-form", "location-manage-target", "old-location", "replacement-location",
  "rename-location-button", "remove-location-button", "confirm-remove", "location-manage-cancel", "location-manage-status");
ids.push("clock-as-of", "expiry-filter", "inventory-search");
ids.push("delete-panel", "delete-form", "delete-target", "delete-fingerprint", "confirm-delete", "delete-button", "delete-cancel", "delete-status");
ids.push("monitor-summary", "warning-days", "auto-refresh");
ids.push("preview-button", "import-preview", "preview-summary", "preview-records");
const elements = Object.fromEntries(ids.map(id => [id, new Element()]));
elements["expiry-filter"].value = "all";
elements["warning-days"].value = "30";
elements["auto-refresh"].checked = true;
const requests = [];
let fileReads = 0;
const publicFile = new Uint8Array(Buffer.from("-----BEGIN CERTIFICATE-----\nAQ==\n-----END CERTIFICATE-----\n"));
elements["certificate-file"].files = [{ size: publicFile.length, async arrayBuffer() { fileReads++; return publicFile.slice().buffer; } }];
elements.owner.value = "Platform";
elements.location.value = "production/nginx";

const response = { generation: 2, verification: "not-performed", records: [{
  fingerprint: "ab:cd", subject: "<untrusted subject>", issuer: "Issuer", dns_names: [],
  not_before: "2026-01-01T00:00:00Z", not_after: "2026-12-01T00:00:00Z",
  owner: "Platform", location: "production/nginx", locations: ["production/nginx"], import_generation: 2, imported_at: "2026-09-28T01:00:00Z",
}] };
let currentResponse = response;
let rejectAssociation = false;
let rejectOwner = false;
let rejectDelete = false;
let malformedDeleteResult = false;
let overrideGET = null;
let delayJSON = null;
let serverTime = "2026-09-28T00:00:00Z";
const monitorResponse = data => ({ ...data, monitoring: { checked_at: serverTime, clock_source: "server-clock", refresh_after_seconds: 60 },
  records: data.records.map(record => {
    const start = Date.parse(record.not_before), end = Date.parse(record.not_after), now = Date.parse(serverTime);
    const seconds = (end - now) / 1000;
    const invalid = !Number.isFinite(start) || !Number.isFinite(end) || start >= end;
    const status = invalid ? "invalid" : now >= end ? "expired" : now < start ? "future" : seconds <= 30*86400 ? "soon" : seconds <= 90*86400 ? "medium" : "later";
    return { ...record, expiry: { status, ...(invalid ? {} : { days_left: seconds > 0 ? Math.ceil(seconds/86400) : Math.trunc(seconds/86400) }) } };
  }) });
const fetchImpl = async (url, options) => {
  requests.push({ url, options });
  if (options.method === "GET") {
    if (overrideGET) return overrideGET(options);
    if (delayJSON) await delayJSON;
    return new Response(JSON.stringify(monitorResponse(currentResponse)));
  }
  if (url === "/api/inventory") return new Response(JSON.stringify({ generation: 3, verification: "not-performed", records: [{ fingerprint: "new-public" }] }), { status: 201 });
  if (url === "/api/inventory/delete") {
    if (rejectDelete) return { ok: false, async text() { return "inventory changed; refresh before deletion"; } };
    const body = JSON.parse(options.body);
    if (malformedDeleteResult) return { ok: true, async json() { return { fingerprint: body.fingerprint,
      generation: currentResponse.generation, deleted: false, verification: "not-performed" }; } };
    currentResponse = { ...currentResponse, generation: currentResponse.generation + 1,
      records: currentResponse.records.filter(record => record.fingerprint !== body.fingerprint) };
    return { ok: true, async json() { return { fingerprint: body.fingerprint, generation: currentResponse.generation,
      deleted: true, verification: "not-performed" }; } };
  }
  if (url === "/api/inventory/locations") {
    if (rejectAssociation) return { ok: false, async text() { return "inventory changed; refresh before adding a location"; } };
    currentResponse = { ...response, generation: 3, records: [{ ...response.records[0], locations: ["production/nginx", "production/haproxy"] }] };
  }
  if (url === "/api/inventory/owner") {
    if (rejectOwner) return { ok: false, async text() { return "inventory changed; refresh before changing metadata"; } };
    const owner = JSON.parse(options.body).owner;
    currentResponse = { ...currentResponse, generation: currentResponse.generation + 1,
      records: [{ ...currentResponse.records[0], owner }] };
  }
  if (url === "/api/inventory/locations/change") {
    const body = JSON.parse(options.body);
    const locations = currentResponse.records[0].locations.slice();
    const index = locations.indexOf(body.old_location);
    assert.ok(index >= 0);
    if (body.action === "rename") locations[index] = body.new_location;
    else locations.splice(index, 1);
    currentResponse = { ...currentResponse, generation: currentResponse.generation + 1,
      records: [{ ...currentResponse.records[0], location: locations[0] || "", locations }] };
  }
  return { ok: true, async json() { return currentResponse; } };
};
let wallNow = Date.parse("2026-09-28T00:00:00Z");
let monotonicNow = 0;
const timers = new Map();
let timerID = 0;
const documentListeners = {}, windowListeners = {};
let recordDetailsOpen = false;
let comparisonOpen = false;
const mockDocument = { hidden: false, addEventListener(name, fn) { documentListeners[name] = fn; },
  querySelector() {return recordDetailsOpen ? {} : null;},
  getElementById(id) { return elements[id]; }, createElement() { return new Element(); } };
class FixedDate extends Date { static now() { return wallNow; } }
vm.runInNewContext(source, {
  document: mockDocument, window: { addEventListener(name, fn) { windowListeners[name] = fn; } },
  performance: { now: () => monotonicNow },
  setTimeout(fn, delay) { const id = ++timerID; timers.set(id,{fn,delay}); return id; }, clearTimeout(id) { timers.delete(id); },
  fetch: fetchImpl, TextEncoder, TextDecoder, AbortController, Uint8Array, Date: FixedDate, btoa: value => Buffer.from(value, "binary").toString("base64"),
  rootwellInventoryLifecycle: {invalidate(){comparisonOpen=false;},refreshActivity(){},isOpen:()=>comparisonOpen},
  rootwellInventoryImport: {
    async preview(files) { fileReads++; return [{ subject: "New public", sha256: "new-public", source: "File 1", not_after: "2035-01-01T00:00:00Z" }]; },
    async prepare(files) { fileReads++; return new Uint8Array(await files[0].arrayBuffer()); }
  },
}, { filename: "inventory.js" });

await new Promise(resolve => setImmediate(resolve));
assert.equal(fileReads, 0, "page load must not read a selected file");
assert.equal(requests[0].url, "/api/inventory");
assert.equal(requests[0].options.method, "GET");
assert.equal(requests[0].options.headers["X-Rootwell-Request"], "1");
assert.equal(elements.records.children.length, 1);
assert.equal(elements.records.children[0].children[0].textContent, "<untrusted subject>");
const firstDetails = elements.records.children[0].children.find(node => node.className === "record-details");
assert.ok(firstDetails.children.some(node => node.textContent.includes("Owner: Platform")));
assert.ok(firstDetails.children.some(node => node.textContent.includes("Saved at (server clock)")));
assert.ok(firstDetails.children.some(node => node.textContent.includes("SHA-256: ab:cd")));
assert.ok(!elements.records.children[0].children.some(node => node.textContent.includes("SHA-256:")), "fingerprint must not crowd the card");
const workbenchForm = firstDetails.children.find(node => node.className === "workbench-actions");
assert.equal(workbenchForm.action,"/workbench");
assert.equal(workbenchForm.method,"post");
assert.deepEqual(workbenchForm.children.map(node=>[node.name,node.value]),
  [["fingerprint","ab:cd"],["expected_generation","2"],["tool","inspect"],["tool","verify"]]);
let stoppedNavigation=false;
workbenchForm.listeners.submit({preventDefault(){stoppedNavigation=true;}});
assert.equal(stoppedNavigation,false,"current explicit form may navigate");
mockDocument.hidden=true;
workbenchForm.listeners.submit({preventDefault(){stoppedNavigation=true;}});
assert.equal(stoppedNavigation,true,"hidden view cannot navigate with retained snapshot");
mockDocument.hidden=false;
assert.match(elements["clock-as-of"].textContent, /2026-09-28T00:00:00.000Z.*server clock.*no automatic renewal/);

const addLocation = action(elements.records.children[0], "Add server note");
assert.ok(addLocation);
addLocation.listeners.click();
assert.equal(elements["location-panel"].hidden, false);
assert.equal(fileReads, 0, "association must not reread the certificate");
elements["new-location"].value = "production/haproxy";
await elements["location-form"].listeners.submit({ preventDefault() {} });
const association = requests.find(request => request.url === "/api/inventory/locations");
assert.ok(association);
assert.equal(association.options.credentials, "same-origin");
assert.equal(association.options.headers["X-Rootwell-Request"], "1");
assert.deepEqual(JSON.parse(association.options.body), {
  fingerprint: "ab:cd", location: "production/haproxy", expected_generation: 2,
});
assert.doesNotMatch(association.options.body, /certificate|PRIVATE KEY/i);
assert.equal(elements["location-panel"].hidden, true);
assert.match(elements["list-status"].textContent, /backup is not automatic/i);
assert.equal(fileReads, 0);

const beforeBadLocation = requests.length;
action(elements.records.children[0], "Add server note").listeners.click();
elements["new-location"].value = "bad\nlocation";
await elements["location-form"].listeners.submit({ preventDefault() {} });
assert.equal(requests.length, beforeBadLocation, "invalid location was transmitted");
elements["location-cancel"].listeners.click();

action(elements.records.children[0], "Add server note").listeners.click();
elements["new-location"].value = "staging/nginx";
rejectAssociation = true;
await elements["location-form"].listeners.submit({ preventDefault() {} });
assert.match(elements["location-status"].textContent, /refresh before adding a location/i);
assert.equal(elements["location-panel"].hidden, false);
rejectAssociation = false;
elements["location-cancel"].listeners.click();

const correctOwner = action(elements.records.children[0], "Change owner");
assert.ok(correctOwner);
correctOwner.listeners.click();
assert.equal(elements["owner-panel"].hidden, false);
assert.equal(elements["new-owner"].value, "Platform");
assert.equal(fileReads, 0, "owner correction must not reread the certificate");
elements["new-owner"].value = "Security";
await elements["owner-form"].listeners.submit({ preventDefault() {} });
const ownerChange = requests.find(request => request.url === "/api/inventory/owner");
assert.ok(ownerChange);
assert.equal(ownerChange.options.credentials, "same-origin");
assert.equal(ownerChange.options.headers["X-Rootwell-Request"], "1");
assert.deepEqual(JSON.parse(ownerChange.options.body), { fingerprint: "ab:cd", owner: "Security", expected_generation: 3 });
assert.doesNotMatch(ownerChange.options.body, /certificate|PRIVATE KEY/i);
assert.equal(elements["owner-panel"].hidden, true);
assert.match(elements["list-status"].textContent, /backup is not automatic/i);
assert.equal(fileReads, 0);

action(elements.records.children[0], "Change owner").listeners.click();
const beforeBadOwner = requests.length;
elements["new-owner"].value = "bad\nowner";
await elements["owner-form"].listeners.submit({ preventDefault() {} });
assert.equal(requests.length, beforeBadOwner, "invalid owner was transmitted");
elements["new-owner"].value = "Security";
await elements["owner-form"].listeners.submit({ preventDefault() {} });
assert.equal(requests.length, beforeBadOwner, "unchanged owner was transmitted");
elements["new-owner"].value = "Operations";
rejectOwner = true;
await elements["owner-form"].listeners.submit({ preventDefault() {} });
assert.match(elements["owner-status"].textContent, /refresh before changing metadata/i);
assert.equal(elements["owner-panel"].hidden, false);
rejectOwner = false;
elements["owner-cancel"].listeners.click();

action(elements.records.children[0], "Change owner").listeners.click();
elements["new-owner"].value = "";
await elements["owner-form"].listeners.submit({ preventDefault() {} });
const clearOwner = requests.filter(request => request.url === "/api/inventory/owner").at(-1);
assert.deepEqual(JSON.parse(clearOwner.options.body), { fingerprint: "ab:cd", owner: "", expected_generation: 4 });
assert.ok(!action(elements.records.children[0], "Owner: Platform"), "cleared owner must not survive inside details");
assert.equal(fileReads, 0, "clearing an owner must not reread the certificate");

action(elements.records.children[0], "Change server notes").listeners.click();
assert.equal(elements["location-manage-panel"].hidden, false);
assert.equal(elements["old-location"].value, "production/nginx");
elements["replacement-location"].value = "prod/nginx";
await elements["location-manage-form"].listeners.submit({ preventDefault() {} });
const renamedLocation = requests.find(request => request.url === "/api/inventory/locations/change");
assert.deepEqual(JSON.parse(renamedLocation.options.body), {
  fingerprint: "ab:cd", old_location: "production/nginx", new_location: "prod/nginx", action: "rename", expected_generation: 5,
});
assert.doesNotMatch(renamedLocation.options.body, /certificate|PRIVATE KEY/i);
assert.equal(renamedLocation.options.headers["X-Rootwell-Request"], "1");
assert.equal(elements["location-manage-panel"].hidden, true);
assert.equal(fileReads, 0);

action(elements.records.children[0], "Change server notes").listeners.click();
const beforeUnconfirmedRemove = requests.length;
await elements["remove-location-button"].listeners.click();
assert.equal(requests.length, beforeUnconfirmedRemove, "unconfirmed note removal was transmitted");
elements["confirm-remove"].checked = true;
await elements["remove-location-button"].listeners.click();
const removedLocation = requests.filter(request => request.url === "/api/inventory/locations/change").at(-1);
assert.deepEqual(JSON.parse(removedLocation.options.body), {
  fingerprint: "ab:cd", old_location: "prod/nginx", action: "remove", expected_generation: 6,
});
assert.equal(fileReads, 0);
action(elements.records.children[0], "Change server notes").listeners.click();
elements["confirm-remove"].checked = true;
await elements["remove-location-button"].listeners.click();
assert.ok(action(elements.records.children[0], "Service notes: None — add one if useful"));
assert.equal(action(elements.records.children[0], "Change server notes").disabled, true);

currentResponse = { ...response, records: [{ ...response.records[0], locations: ["production/nginx", "production/nginx"] }] };
await elements["refresh-button"].listeners.click();
assert.equal(elements.records.children.length, 0, "inconsistent duplicate locations were rendered");
currentResponse = response;
await elements["refresh-button"].listeners.click();
assert.equal(elements.records.children.length, 1);

const beforePreviewSave = requests.length;
await elements["inventory-form"].listeners.submit({ preventDefault() {} });
assert.equal(requests.length, beforePreviewSave, "save without preview must not upload");
await elements["preview-button"].listeners.click();
assert.equal(fileReads, 1);
assert.equal(requests.length, beforePreviewSave, "preview must not upload");
await elements["inventory-form"].listeners.submit({ preventDefault() {} });
assert.equal(fileReads, 3);
const save = requests.find(request => request.options.method === "POST" && request.url === "/api/inventory");
assert.ok(save);
assert.equal(save.url, "/api/inventory");
assert.equal(save.options.credentials, "same-origin");
assert.equal(save.options.headers["X-Rootwell-Request"], "1");
const saved = JSON.parse(save.options.body);
assert.equal(saved.certificate, Buffer.from(publicFile).toString("base64"));
assert.equal(saved.owner, "Platform");
assert.equal(saved.location, "production/nginx");
assert.match(elements["save-status"].textContent, /backup is not automatic/i);

const before = requests.length;
elements.owner.value = "bad\nlabel";
await elements["inventory-form"].listeners.submit({ preventDefault() {} });
assert.equal(requests.length, before, "invalid label was uploaded");
elements.owner.value = "Platform";
elements["certificate-file"].files = [{ size: 16 * 1024 * 1024 + 1, async arrayBuffer() { throw new Error("oversized file read"); } }];
await elements["inventory-form"].listeners.submit({ preventDefault() {} });
assert.equal(requests.length, before, "oversized file was uploaded");

const makeRecord = (fingerprint, notAfter, extra = {}) => ({ ...response.records[0], fingerprint,
  subject: fingerprint, not_after: notAfter, ...extra });
currentResponse = { generation: 8, verification: "not-performed", records: [
  makeRecord("later", "2027-01-01T00:00:00Z"),
  makeRecord("medium", "2026-10-29T00:00:00Z"),
  makeRecord("soon", "2026-10-28T00:00:00Z"),
  makeRecord("expired", "2026-09-28T00:00:00Z", { owner: "", location: "", locations: [] }),
  makeRecord("future", "2027-01-01T00:00:00Z", { not_before: "2026-10-01T00:00:00Z" }),
  makeRecord("invalid", "2025-01-01T00:00:00Z"),
] };
await elements["refresh-button"].listeners.click();
assert.deepEqual(elements.records.children.map(node => node.children[0].textContent),
  ["invalid", "expired", "soon", "medium", "future", "later"], "priority and exact expiry boundary");
assert.ok(!elements.counts.children.some(node => /No owner|No server/.test(node.textContent)), "optional notes must not look like unfinished tasks");
assert.ok(elements.counts.children.some(node => node.textContent === "Needs attention: 4"));
assert.ok(elements.records.children.find(node => node.children[0].textContent === "expired").children.find(node => node.className === "record-details").children.some(node => /not renewed automatically/.test(node.textContent)));
const beforeView = requests.length;
elements["expiry-filter"].value = "attention";
elements["expiry-filter"].listeners.change();
assert.deepEqual(elements.records.children.map(node => node.children[0].textContent), ["invalid", "expired", "soon", "future"]);
elements["expiry-filter"].value = "missing-owner";
elements["expiry-filter"].listeners.change();
assert.deepEqual(elements.records.children.map(node => node.children[0].textContent), ["expired"]);
elements["expiry-filter"].value = "missing-location";
elements["expiry-filter"].listeners.change();
assert.deepEqual(elements.records.children.map(node => node.children[0].textContent), ["expired"]);
elements["expiry-filter"].value = "all";
elements["inventory-search"].value = "MeDiUm";
elements["inventory-search"].listeners.input();
assert.deepEqual(elements.records.children.map(node => node.children[0].textContent), ["medium"]);
assert.equal(requests.length, beforeView, "filter and search must not transmit inventory notes");
assert.equal(fileReads, 3, "filter and search must not reread selected files");
elements["inventory-search"].value = "";
elements["inventory-search"].listeners.input();
assert.equal(elements.records.children.length, 6);
assert.equal(requests.length, beforeView, "view changes must remain local");
currentResponse = { ...currentResponse, records: [{ ...currentResponse.records[0], not_after: "not a date" }] };
await elements["refresh-button"].listeners.click();
assert.equal(elements.records.children.length, 1);
assert.match(elements.records.children[0].children[1].textContent, /Check certificate dates/);
currentResponse = { ...currentResponse, records: [{ ...currentResponse.records[0], not_after: null }] };
await elements["refresh-button"].listeners.click();
assert.equal(elements.records.children.length, 0, "malformed date type was rendered");

currentResponse = response;
await elements["refresh-button"].listeners.click();
action(elements.records.children[0], "Remove from saved list").listeners.click();
assert.equal(elements["delete-panel"].hidden, false);
assert.match(elements["delete-target"].textContent, /ab:cd/);
const beforeDelete = requests.length;
await elements["delete-form"].listeners.submit({ preventDefault() {} });
assert.equal(requests.length, beforeDelete, "unconfirmed deletion was transmitted");
elements["delete-fingerprint"].value = "wrong";
elements["confirm-delete"].checked = true;
await elements["delete-form"].listeners.submit({ preventDefault() {} });
assert.equal(requests.length, beforeDelete, "wrong fingerprint deletion was transmitted");
elements["delete-fingerprint"].value = "ab:cd";
rejectDelete = true;
await elements["delete-form"].listeners.submit({ preventDefault() {} });
assert.match(elements["delete-status"].textContent, /refresh before deletion/);
assert.equal(elements["delete-panel"].hidden, false);
rejectDelete = false;
await elements["refresh-button"].listeners.click();
action(elements.records.children[0], "Remove from saved list").listeners.click();
elements["delete-fingerprint"].value = "ab:cd";
elements["confirm-delete"].checked = true;
malformedDeleteResult = true;
await elements["delete-form"].listeners.submit({ preventDefault() {} });
assert.match(elements["delete-status"].textContent, /could not be confirmed/);
assert.equal(elements.records.children.length, 1);
malformedDeleteResult = false;
await elements["refresh-button"].listeners.click();
action(elements.records.children[0], "Remove from saved list").listeners.click();
elements["delete-fingerprint"].value = "ab:cd";
elements["confirm-delete"].checked = true;
await elements["delete-form"].listeners.submit({ preventDefault() {} });
const deletion = requests.filter(request => request.url === "/api/inventory/delete").at(-1);
assert.deepEqual(JSON.parse(deletion.options.body), { fingerprint: "ab:cd", typed_fingerprint: "ab:cd",
  confirmation: "delete-public-record", expected_generation: 2 });
assert.equal(deletion.options.credentials, "same-origin");
assert.equal(deletion.options.headers["X-Rootwell-Request"], "1");
assert.doesNotMatch(deletion.options.body, /certificate|PRIVATE KEY|AQ==/i);
assert.equal(elements.records.children.length, 0, "deleted record stayed visible");
assert.match(elements["list-status"].textContent, /Older snapshots may still contain it/);
assert.equal(fileReads, 3, "deletion must not reread selected files");

// The production page uses the same server observation for every card. The
// browser clock never changes certificate classification, only clock warnings.
currentResponse = { ...response, generation: 8, records: [
  makeRecord("seven", "2026-10-05T00:00:00Z"),
  makeRecord("seven-plus", "2026-10-05T00:00:01Z"),
  makeRecord("fourteen", "2026-10-12T00:00:00Z"),
  makeRecord("thirty", "2026-10-28T00:00:00Z"),
  makeRecord("ninety", "2026-12-27T00:00:00Z"),
] };
await elements["refresh-button"].listeners.click();
assert.match(elements["monitor-summary"].textContent, /^4 certificate/);
assert.equal(elements.records.children[0].children[1].textContent,"7 days left");
const beforeThreshold = requests.length;
elements["warning-days"].value = "7";
elements["warning-days"].listeners.change();
assert.match(elements["monitor-summary"].textContent,/^1 certificate/);
elements["expiry-filter"].value = "attention";
elements["expiry-filter"].listeners.change();
assert.deepEqual(elements.records.children.map(node => node.children[0].textContent),["seven"]);
elements["warning-days"].value = "14";
elements["warning-days"].listeners.change();
assert.equal(elements.records.children.length,3);
elements["warning-days"].value = "90";
elements["warning-days"].listeners.change();
assert.equal(elements.records.children.length,5);
assert.equal(requests.length,beforeThreshold,"reminder selection uploaded preferences");
wallNow += 365*86400000;
elements["expiry-filter"].value = "all";
elements["expiry-filter"].listeners.change();
assert.equal(elements.records.children[0].children[1].textContent,"7 days left","browser clock controlled expiry");
assert.match(elements["clock-as-of"].textContent,/times differ by over 5 minutes/);
assert.match(elements["monitor-summary"].textContent,/out of date/);
wallNow = Date.parse(serverTime);
elements["warning-days"].value = "bad";
elements["warning-days"].listeners.change();
assert.equal(elements["warning-days"].value,"30");

function runTick() { const entry = [...timers.entries()].find(([,timer]) => timer.delay === 15000); assert.ok(entry); timers.delete(entry[0]); entry[1].fn(); }
monotonicNow = 61000;
const beforeTick = requests.length;
runTick();
await new Promise(resolve => setImmediate(resolve));
assert.equal(requests.length,beforeTick+1,"visible monitoring did not refresh");
assert.equal(requests.at(-1).options.method,"GET");
assert.equal(fileReads,3,"automatic check read a selected file");
elements["auto-refresh"].checked = false;
monotonicNow += 121000;
runTick();
assert.equal(requests.length,beforeTick+1,"disabled auto refresh still read inventory");
assert.match(elements["monitor-summary"].textContent,/out of date/);
await elements["refresh-button"].listeners.click();
elements["auto-refresh"].checked = true;
action(elements.records.children[0],"Change owner").listeners.click();
monotonicNow += 61000;
const beforeEditTick = requests.length;
runTick();
assert.equal(requests.length,beforeEditTick,"automatic refresh interrupted a correction panel");
elements["owner-cancel"].listeners.click();
recordDetailsOpen = true;
runTick();
assert.equal(requests.length,beforeEditTick,"automatic refresh interrupted reading expanded details");
recordDetailsOpen = false;
comparisonOpen = true;
runTick();
assert.equal(requests.length,beforeEditTick,"automatic refresh interrupted the comparison panel");
comparisonOpen = false;

for (const mutate of [
  data => { delete data.monitoring; },
  data => { data.monitoring.clock_source = "browser-clock"; },
  data => { data.monitoring.checked_at = "2026-02-30T00:00:00Z"; },
  data => { data.monitoring.refresh_after_seconds = 0; },
  data => { data.records[0].expiry.status = "later"; },
  data => { data.records[0].expiry.days_left = 0; },
  data => { data.records[0].expiry.days_left = null; },
]) {
  const data = monitorResponse(currentResponse); mutate(data);
  overrideGET = () => new Response(JSON.stringify(data));
  await elements["refresh-button"].listeners.click();
  assert.equal(elements.records.children.length,0,"malformed monitoring retained cards");
  assert.match(elements["monitor-summary"].textContent,/unavailable/);
}
overrideGET = () => new Response("sign in first",{status:401});
await elements["refresh-button"].listeners.click();
monotonicNow += 60000;
const afterUnauthorized = requests.length;
runTick();
assert.equal(requests.length,afterUnauthorized,"failed session caused an automatic retry loop");
assert.equal(elements.records.children.length,0);
overrideGET = null;
await elements["refresh-button"].listeners.click();

// Streaming bound accepts exactly 4 MiB and refuses a single extra byte.
const json = JSON.stringify(monitorResponse(currentResponse));
overrideGET = () => new Response(json + " ".repeat(4*1024*1024-Buffer.byteLength(json)));
await elements["refresh-button"].listeners.click();
assert.equal(elements.records.children.length,5);
overrideGET = () => new Response(json + " ".repeat(4*1024*1024-Buffer.byteLength(json)+1));
await elements["refresh-button"].listeners.click();
assert.equal(elements.records.children.length,0);
assert.match(elements["list-status"].textContent,/page limit/);
overrideGET = () => new Response('{"password":"do-not-echo-invalid-json"');
await elements["refresh-button"].listeners.click();
assert.doesNotMatch(elements["list-status"].textContent,/do-not-echo/);

// A hidden or BFCache page clears metadata and cannot accept late responses.
overrideGET = null;
let finish;
delayJSON = new Promise(resolve => {finish=resolve;});
const pending = elements["refresh-button"].listeners.click();
mockDocument.hidden = true;
documentListeners.visibilitychange();
assert.equal(requests.at(-1).options.signal.aborted,true);
assert.equal(elements["owner-target"].textContent,"");
assert.equal(elements["new-owner"].value,"");
finish(); await pending; delayJSON = null;
assert.equal(elements.records.children.length,0,"hidden page accepted late response");
assert.match(elements["monitor-summary"].textContent,/paused/);
const hiddenRequests = requests.length;
assert.equal(timers.size,0,"hidden page retained refresh timer");
mockDocument.hidden = false;
documentListeners.visibilitychange();
await new Promise(resolve => setImmediate(resolve));
assert.equal(requests.length,hiddenRequests+1);
assert.equal(elements.records.children.length,5);
windowListeners.pagehide();
assert.equal(elements.records.children.length,0,"pagehide retained inventory metadata");
windowListeners.pageshow({persisted:true});
await new Promise(resolve => setImmediate(resolve));
assert.equal(elements.records.children.length,5,"BFCache restore did not reauthenticate");

overrideGET = options => new Promise((resolve,reject) => options.signal.addEventListener("abort", () => reject(new Error("timeout"))));
const timeoutPending = elements["refresh-button"].listeners.click();
const deadlineEntry = [...timers.entries()].find(([,timer]) => timer.delay === 10000);
assert.ok(deadlineEntry); deadlineEntry[1].fn(); await timeoutPending;
assert.equal(elements.records.children.length,0);
assert.match(elements["monitor-summary"].textContent,/unavailable/);
windowListeners.pagehide();
assert.equal(timers.size,0);

// Hiding during an already-started body read also discards late data.
let finishStream;
overrideGET = () => new Response(new ReadableStream({ start(controller) { finishStream = () => {
  controller.enqueue(new TextEncoder().encode(JSON.stringify(monitorResponse(currentResponse)))); controller.close();
}; } }));
const lateBody = elements["refresh-button"].listeners.click();
await new Promise(resolve => setImmediate(resolve));
mockDocument.hidden = true;
documentListeners.visibilitychange();
finishStream(); await lateBody;
assert.equal(elements.records.children.length,0,"hidden page accepted a late body read");
assert.match(elements["monitor-summary"].textContent,/paused/);
console.log("Rootwell inventory, server-clock monitoring, bounded refresh and refusal paths passed.");
