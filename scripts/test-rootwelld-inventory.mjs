import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import { TextEncoder } from "node:util";

const source = fs.readFileSync(new URL("../cmd/rootwelld/auth/inventory.js", import.meta.url), "utf8");
assert.doesNotMatch(source, /innerHTML|localStorage|sessionStorage|console\./);

class Element {
  constructor() { this.value = ""; this.textContent = ""; this.children = []; this.listeners = {}; this.disabled = false; this.files = []; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  appendChild(node) { this.children.push(node); }
  replaceChildren() { this.children = []; }
}

const ids = ["inventory-form", "certificate-file", "owner", "location", "save-button", "save-status", "refresh-button", "list-status", "counts", "records"];
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
  owner: "Platform", location: "production/nginx", import_generation: 2, imported_at: "2026-09-28T01:00:00Z",
}] };
const fetchImpl = async (url, options) => {
  requests.push({ url, options });
  if (options.method === "GET") return { ok: true, async json() { return response; } };
  return { ok: true, async json() { return response; } };
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

await elements["inventory-form"].listeners.submit({ preventDefault() {} });
assert.equal(fileReads, 1);
const save = requests.find(request => request.options.method === "POST");
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
