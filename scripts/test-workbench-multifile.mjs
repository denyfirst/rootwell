import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

class Element {
  constructor() {
    this.children = [];
    this.listeners = {};
    this.hidden = false;
    this.disabled = false;
    this.files = [];
    this.textContent = "";
  }
  addEventListener(name, listener) { this.listeners[name] = listener; }
  setAttribute() {}
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
  querySelectorAll() { return []; }
  scrollIntoView() {}
}

const elements = new Map();
function element(id) {
  if (!elements.has(id)) elements.set(id, new Element());
  return elements.get(id);
}
const document = {
  getElementById: element,
  querySelectorAll: () => [],
  createElement: () => new Element()
};
const certificate = (number) => ({
  subject: `CN=public-${number}.invalid`,
  issuer: "CN=non-production-demo.invalid",
  is_ca: false,
  not_after: "2030-01-01T00:00:00Z",
  encoding: "pem",
  sha256: Array(32).fill(number.toString(16).toUpperCase().padStart(2, "0")).join(":")
});
const success = (certificates) => JSON.stringify({
  schema_version: "rootwell.browser.explore.v1",
  ok: true,
  error: null,
  result: {
    count: certificates.length,
    verification: "not-performed",
    trust_anchor: "not-selected",
    certificates
  }
});
const failure = JSON.stringify({
  schema_version: "rootwell.browser.explore.v1",
  ok: false,
  result: null,
  error: { code: "invalid-certificate", message: "The file contains an invalid X.509 certificate." }
});
let calls = 0;
const engine = {
  maxBytes: 16 * 1024 * 1024,
  inspect: () => { throw new Error("Inspect should not be called"); },
  explore: (bytes) => {
    calls++;
    if (bytes[0] === 88) return failure;
    if (bytes[0] === 77) return success(Array.from({ length: 64 }, (_, index) => certificate(index)));
    if (bytes[0] === 85 || bytes[0] === 86) {
      const longName = certificate(bytes[0]);
      longName.subject = "€".repeat(200000);
      return success([longName]);
    }
    return success([certificate(bytes[0])]);
  },
  exportPublic: () => { throw new Error("Export should not be called"); }
};
const context = vm.createContext({ document, TextEncoder, rootwellWorkbenchReady: Promise.resolve(engine) });
vm.runInContext(fs.readFileSync("web/workbench/app.js", "utf8"), context, { filename: "app.js" });
await new Promise((resolve) => setImmediate(resolve));

function file(marker, size = 1) {
  return {
    name: `public-${marker}.crt`,
    size,
    arrayBuffer: async () => Uint8Array.of(marker.charCodeAt(0)).buffer
  };
}
function select(files) {
  element("explore-file").files = files;
  element("explore-file").listeners.change();
}
async function explore() {
  assert.equal(element("explore-button").disabled, false);
  await element("explore-button").listeners.click();
}

select([file("A"), file("B")]);
await explore();
assert.equal(element("explore-result").hidden, false);
assert.equal(element("explore-result-count").textContent, "2 certificates found");
assert.equal(element("explore-certificates").children.length, 2);
assert.equal(element("explore-error").hidden, true);

select([file("A"), file("A")]);
await explore();
assert.equal(element("explore-result").hidden, true);
assert.equal(element("explore-certificates").children.length, 0);
assert.match(element("explore-error").textContent, /duplicate certificate/);

select([file("A"), file("X")]);
await explore();
assert.equal(element("explore-result").hidden, true);
assert.equal(element("explore-certificates").children.length, 0);
assert.equal(element("explore-error").textContent, "The file contains an invalid X.509 certificate.");

select([file("M"), file("B")]);
await explore();
assert.equal(element("explore-result").hidden, true);
assert.equal(element("explore-certificates").children.length, 0);
assert.equal(element("explore-error").textContent, "The bundle exceeds 64 certificates.");

select([file("U"), file("V")]);
await explore();
assert.equal(element("explore-result").hidden, true);
assert.equal(element("explore-certificates").children.length, 0);
assert.equal(element("explore-error").textContent, "Certificate metadata exceeds the display limit.");

let finishDelayedRead;
const delayed = {
  name: "old-selection.crt",
  size: 1,
  arrayBuffer: () => new Promise((resolve) => { finishDelayedRead = resolve; })
};
select([delayed]);
const pendingExplore = element("explore-button").listeners.click();
select([file("B")]);
finishDelayedRead(Uint8Array.of(65).buffer);
await pendingExplore;
assert.equal(element("explore-result").hidden, true, "replaced selection must not render stale cards");
assert.equal(element("explore-certificates").children.length, 0);
assert.equal(element("explore-button").disabled, false, "new selection remains ready");

const callsBeforeSelectionRefusal = calls;
select(Array.from({ length: 9 }, (_, index) => file(String.fromCharCode(65 + index))));
assert.equal(element("explore-button").disabled, true);
assert.equal(element("explore-file-state").textContent, "Choose at most 8 public certificate files");
select([file("A", 9 * 1024 * 1024), file("B", 9 * 1024 * 1024)]);
assert.equal(element("explore-button").disabled, true);
assert.equal(element("explore-file-state").textContent, "Selected files exceed the 16 MiB combined limit");
assert.equal(calls, callsBeforeSelectionRefusal, "rejected selections must not reach the engine");

console.log("Rootwell multi-file Workbench behavior passed.");
