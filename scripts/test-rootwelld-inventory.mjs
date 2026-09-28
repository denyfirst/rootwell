import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import { TextEncoder } from "node:util";

const source = fs.readFileSync(new URL("../cmd/rootwelld/auth/inventory.js", import.meta.url), "utf8");
assert.doesNotMatch(source, /innerHTML|localStorage|sessionStorage|console\./);

class Element {
  constructor() { this.value = ""; this.textContent = ""; this.children = []; this.listeners = {}; this.disabled = false; this.checked = false; this.files = []; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  appendChild(node) { this.children.push(node); }
  replaceChildren() { this.children = []; }
}

const ids = ["inventory-form", "certificate-file", "owner", "location", "save-button", "save-status", "refresh-button", "list-status", "counts", "records",
  "location-panel", "location-form", "location-target", "new-location", "location-button", "location-cancel", "location-status",
  "owner-panel", "owner-form", "owner-target", "new-owner", "owner-button", "owner-cancel", "owner-status"];
ids.push("location-manage-panel", "location-manage-form", "location-manage-target", "old-location", "replacement-location",
  "rename-location-button", "remove-location-button", "confirm-remove", "location-manage-cancel", "location-manage-status");
const elements = Object.fromEntries(ids.map(id => [id, new Element()]));
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
const fetchImpl = async (url, options) => {
  requests.push({ url, options });
  if (options.method === "GET") return { ok: true, async json() { return currentResponse; } };
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
vm.runInNewContext(source, {
  document: { getElementById(id) { return elements[id]; }, createElement() { return new Element(); } },
  fetch: fetchImpl, TextEncoder, Uint8Array, Date, btoa: value => Buffer.from(value, "binary").toString("base64"),
}, { filename: "inventory.js" });

await new Promise(resolve => setImmediate(resolve));
assert.equal(fileReads, 0, "page load must not read a selected file");
assert.equal(requests[0].url, "/api/inventory");
assert.equal(requests[0].options.method, "GET");
assert.equal(requests[0].options.headers["X-Rootwell-Request"], "1");
assert.equal(elements.records.children.length, 1);
assert.equal(elements.records.children[0].children[0].textContent, "<untrusted subject>");
assert.ok(elements.records.children[0].children.some(node => node.textContent.includes("Saved at (server clock)")));
assert.ok(elements.records.children[0].children.some(node => node.textContent.includes("Deployment at these locations has not been checked")));

const addLocation = elements.records.children[0].children.find(node => node.textContent === "Add another location");
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
elements.records.children[0].children.find(node => node.textContent === "Add another location").listeners.click();
elements["new-location"].value = "bad\nlocation";
await elements["location-form"].listeners.submit({ preventDefault() {} });
assert.equal(requests.length, beforeBadLocation, "invalid location was transmitted");
elements["location-cancel"].listeners.click();

elements.records.children[0].children.find(node => node.textContent === "Add another location").listeners.click();
elements["new-location"].value = "staging/nginx";
rejectAssociation = true;
await elements["location-form"].listeners.submit({ preventDefault() {} });
assert.match(elements["location-status"].textContent, /refresh before adding a location/i);
assert.equal(elements["location-panel"].hidden, false);
rejectAssociation = false;
elements["location-cancel"].listeners.click();

const correctOwner = elements.records.children[0].children.find(node => node.textContent === "Correct owner note");
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

elements.records.children[0].children.find(node => node.textContent === "Correct owner note").listeners.click();
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

elements.records.children[0].children.find(node => node.textContent === "Correct owner note").listeners.click();
elements["new-owner"].value = "";
await elements["owner-form"].listeners.submit({ preventDefault() {} });
const clearOwner = requests.filter(request => request.url === "/api/inventory/owner").at(-1);
assert.deepEqual(JSON.parse(clearOwner.options.body), { fingerprint: "ab:cd", owner: "", expected_generation: 4 });
assert.ok(elements.records.children[0].children.some(node => node.textContent.includes("Owner: Unknown")));
assert.equal(fileReads, 0, "clearing an owner must not reread the certificate");

elements.records.children[0].children.find(node => node.textContent === "Correct location notes").listeners.click();
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

elements.records.children[0].children.find(node => node.textContent === "Correct location notes").listeners.click();
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
elements.records.children[0].children.find(node => node.textContent === "Correct location notes").listeners.click();
elements["confirm-remove"].checked = true;
await elements["remove-location-button"].listeners.click();
assert.ok(elements.records.children[0].children.some(node => node.textContent.includes("Manually listed locations: Unknown")));
assert.equal(elements.records.children[0].children.find(node => node.textContent === "Correct location notes").disabled, true);

currentResponse = { ...response, records: [{ ...response.records[0], locations: ["production/nginx", "production/nginx"] }] };
await elements["refresh-button"].listeners.click();
assert.equal(elements.records.children.length, 0, "inconsistent duplicate locations were rendered");
currentResponse = response;
await elements["refresh-button"].listeners.click();
assert.equal(elements.records.children.length, 1);

await elements["inventory-form"].listeners.submit({ preventDefault() {} });
assert.equal(fileReads, 1);
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

console.log("Rootwell public inventory UI boundary and explicit-save behavior passed.");
