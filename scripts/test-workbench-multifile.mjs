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
  click() { this.clicked = true; }
  remove() {}
}

const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    const created = new Element();
    if (id === "verify-source-files") {
      Object.defineProperty(created, "value", {
        get() { return this._value || ""; },
        set(value) { this._value = value; if (value === "") this.files = []; }
      });
    }
    elements.set(id, created);
  }
  return elements.get(id);
}
const document = {
  getElementById: element,
  querySelectorAll: () => [],
  createElement: () => new Element(),
  body: new Element()
};
let downloadedName = "";
const objectURLs = { createObjectURL: () => "blob:rootwell-test", revokeObjectURL: () => {} };
const certificate = (number) => ({
  subject: `CN=public-${number}.invalid`,
  issuer: "CN=non-production-demo.invalid",
  is_ca: false,
  not_before: "2020-01-01T00:00:00Z",
  not_after: "2030-01-01T00:00:00Z",
  encoding: "pem",
  sha256: Array(32).fill(number.toString(16).toUpperCase().padStart(2, "0")).join(":")
});
const timelineCertificates = [
  { not_before: "2026-01-02T00:00:00Z", not_after: "2026-01-01T00:00:00Z" },
  { not_before: "2020-01-01T00:00:00Z", not_after: "2026-09-25T11:59:59Z" },
  { not_before: "2026-09-26T00:00:00Z", not_after: "2027-01-01T00:00:00Z" },
  { not_before: "2020-01-01T00:00:00Z", not_after: "2026-10-25T12:00:00Z" },
  { not_before: "2020-01-01T00:00:00Z", not_after: "2026-12-24T12:00:00Z" },
  { not_before: "2020-01-01T00:00:00Z", not_after: "2026-12-24T12:00:01Z" },
  { not_before: "2026-09-25T12:00:00Z", not_after: "2026-09-25T12:00:00Z" }
].map((dates, index) => ({ ...certificate(index + 1), ...dates, is_ca: index === 5 }));
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
const duplicateFailure = JSON.stringify({
  schema_version: "rootwell.browser.explore.v1",
  ok: false,
  result: null,
  error: { code: "duplicate-certificate", message: "The bundle contains a duplicate certificate." }
});
let calls = 0;
let exportedCertificates = [];
const engine = {
  maxBytes: 16 * 1024 * 1024,
  inspect: () => { throw new Error("Inspect should not be called"); },
  explore: (bytes) => {
    calls++;
    if (bytes[0] === 88) return failure;
    if (bytes[0] === 80) return success(exportedCertificates);
    if (bytes[0] === 68) return duplicateFailure;
    if (bytes[0] === 67) return success([{ ...certificate(67), is_ca: true }]);
    if (bytes[0] === 84) return success(timelineCertificates);
    if (bytes[0] === 90) return success([{ ...certificate(90), not_after: "2026-02-30T00:00:00Z" }]);
    if (bytes[0] === 77) return success(Array.from({ length: 64 }, (_, index) => certificate(index)));
    if (bytes[0] === 85 || bytes[0] === 86) {
      const longName = certificate(bytes[0]);
      longName.subject = "€".repeat(200000);
      return success([longName]);
    }
    return success([certificate(bytes[0])]);
  },
  analyze: (inputs) => JSON.stringify({
    schema_version: "rootwell.browser.chain.v1",
    ok: true,
    error: "",
    result: {
      verification: "not-performed",
      trust_anchor: "not-selected",
      certificates: inputs.flatMap((bytes) =>
        (bytes[0] === 77 ? Array.from({ length: 64 }, (_, index) => certificate(index)) :
          bytes[0] === 84 ? timelineCertificates : [certificate(bytes[0])])
          .map((item) => ({ sha256: item.sha256,
            parents: inputs.length === 2 && inputs[0][0] === 65 && inputs[1][0] === 66 && item.sha256 === certificate(65).sha256 ? [1] : [],
            self_signed: inputs.length === 2 && inputs[0][0] === 65 && inputs[1][0] === 66 && item.sha256 === certificate(66).sha256 })))
    }
  }),
  exportBundle: (_inputs, _expected, selected) => {
    exportedCertificates = selected.map((fingerprint) => {
      for (const marker of [65, 66]) {
        if (certificate(marker).sha256 === fingerprint) return certificate(marker);
      }
      throw new Error("unexpected selected fingerprint");
    });
    return { schema_version: "rootwell.browser.bundle-export.v1", ok: true, error: null,
      result: { fingerprints: selected, filename: "rootwell-public-bundle-" + "a".repeat(32) + ".pem", bytes: Uint8Array.of(80) } };
  },
  verifySimple: () => { throw new Error("Verify should not be called by Explore tests"); },
  verifyExplicit: () => { throw new Error("Verify should not be called by Explore tests"); },
  exportVerifiedSimple: () => { throw new Error("Verified export should not be called by Explore tests"); },
  exportVerifiedExplicit: () => { throw new Error("Verified export should not be called by Explore tests"); },
  exportPublic: () => { throw new Error("Export should not be called"); }
};
let clock = Date.parse("2026-09-25T12:00:00Z");
class FixedDate extends Date {
  static now() { return clock; }
}
const context = vm.createContext({ document, TextEncoder, Uint8Array, Blob, Date: FixedDate, URL: objectURLs, setTimeout: () => 0,
  rootwellWorkbenchReady: Promise.resolve(engine) });
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
function allText(node) {
  return node.textContent + node.children.map(allText).join(" ");
}

select([file("A"), file("B")]);
await explore();
assert.equal(element("explore-result").hidden, false);
assert.equal(element("explore-result-count").textContent, "2 certificates found");
assert.equal(element("explore-certificates").children.length, 2);
assert.equal(element("explore-error").hidden, true);
assert.match(allText(element("explore-certificates")), /certificate #2 · issuer signature matches, not a trust verdict/);
assert.match(allText(element("explore-certificates")), /Self-signed CA candidate · not automatically trusted/);
assert.match(element("explore-expiry-summary").textContent, /Expires after 90 days: 2/);
assert.match(element("explore-expiry-note").textContent, /2026-09-25T12:00:00.000Z \(browser clock\)/);
assert.equal(element("explore-expiry-list").children.length, 2);
assert.match(element("explore-health-summary").textContent, /2 possible website certificates/);
assert.match(element("explore-health-summary").textContent, /1 possible signing link/);
assert.match(element("explore-health-next").textContent, /will not guess/);
assert.equal(element("explore-verify-button").textContent, "Review Verify options");

select([file("T")]);
await explore();
assert.equal(element("explore-result").hidden, false);
assert.equal(element("explore-expiry-list").children.length, 7);
for (const label of ["Invalid date range", "Expired", "Not yet valid", "Expires in 31–90 days", "Expires after 90 days"]) {
  assert.ok(element("explore-expiry-summary").textContent.includes(label + ": 1"));
}
assert.ok(element("explore-expiry-summary").textContent.includes("Expires within 30 days: 2"));
assert.match(allText(element("explore-expiry-list")), /#4 · Expires within 30 days/);
assert.match(allText(element("explore-expiry-list")), /#5 · Expires in 31–90 days/);
assert.match(allText(element("explore-expiry-list")), /#6 · Expires after 90 days/);
assert.match(allText(element("explore-expiry-list")), /CA flag set · not trusted/);
assert.match(allText(element("explore-expiry-list")), /#7 · Expires within 30 days/);
assert.match(element("explore-expiry-list").children[0].textContent, /#1 · Invalid date range/);

select([file("Z")]);
await explore();
assert.equal(element("explore-result").hidden, true, "non-canonical date must fail closed");
assert.equal(element("explore-expiry-list").children.length, 0);
assert.equal(element("explore-expiry-summary").textContent, "");
assert.equal(element("explore-health-summary").textContent, "");

clock = 1e16;
select([file("A")]);
await explore();
assert.equal(element("explore-result").hidden, true, "unrepresentable browser time must fail closed");
assert.match(element("explore-error").textContent, /browser clock is unavailable/);
assert.equal(element("explore-expiry-list").children.length, 0);
clock = Date.parse("2026-09-25T12:00:00Z");

select([file("A"), file("B")]);
await explore();
const firstSelection = element("explore-certificates").children[0].children[2].children[0];
assert.equal(element("export-bundle-button").disabled, true);
firstSelection.checked = true;
firstSelection.listeners.change();
assert.equal(element("export-bundle-button").disabled, false);
element("export-bundle-button").listeners.click();
await new Promise((resolve) => setImmediate(resolve));
assert.equal(document.body.children.length, 1);
downloadedName = document.body.children[0].download;
assert.match(downloadedName, /^rootwell-public-bundle-[0-9a-f]{32}\.pem$/);

const realAnalyze = engine.analyze;
engine.analyze = () => JSON.stringify({
  schema_version: "rootwell.browser.chain.v1", ok: true, error: "",
  result: { verification: "not-performed", trust_anchor: "not-selected", certificates: [
    { sha256: certificate(66).sha256, parents: [], self_signed: false },
    { sha256: certificate(65).sha256, parents: [], self_signed: false }
  ] }
});
select([file("A"), file("B")]);
await explore();
assert.equal(element("explore-result").hidden, true, "mismatched analysis must hide all cards");
assert.equal(element("explore-certificates").children.length, 0);
assert.equal(element("explore-expiry-list").children.length, 0);
engine.analyze = realAnalyze;

select([file("A"), file("A")]);
await explore();
assert.equal(element("explore-result").hidden, true);
assert.equal(element("explore-certificates").children.length, 0);
assert.match(element("explore-error").textContent, /Duplicate certificate/);
assert.match(element("explore-error").textContent, /File 1 \(public-A\.crt\).*File 2 \(public-A\.crt\)/);
assert.ok(element("explore-error").textContent.includes(certificate(65).sha256));
assert.match(element("explore-error").textContent, /No results were shown/);

select([file("A"), file("D")]);
await explore();
assert.equal(element("explore-result").hidden, true);
assert.equal(element("explore-certificates").children.length, 0);
assert.match(element("explore-error").textContent, /File 2 \(public-D\.crt\) contains a duplicate certificate/);
assert.match(element("explore-error").textContent, /No results were shown/);

const unsafeName = file("A");
unsafeName.name = "untrusted\u202ecert\n<script>.crt";
select([unsafeName, file("A")]);
await explore();
assert.equal(element("explore-result").hidden, true);
assert.equal(element("explore-certificates").children.length, 0);
assert.ok(!element("explore-error").textContent.includes("\u202e"));
assert.ok(!element("explore-error").textContent.includes("\n"));
assert.match(element("explore-error").textContent, /File 1 \(untrusted�cert�<script>\.crt\)/);

const overlongName = file("A");
overlongName.name = "a".repeat(200);
select([overlongName, file("A")]);
await explore();
assert.equal(element("explore-result").hidden, true);
assert.ok(element("explore-error").textContent.includes("File 1 (" + "a".repeat(120) + "…)"));
assert.ok(!element("explore-error").textContent.includes("a".repeat(121)));

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

select([file("A")]);
await explore();
assert.match(element("explore-health-summary").textContent, /1 possible website certificate/);
assert.match(element("explore-health-next").textContent, /One certificate could be the website certificate/);
assert.equal(element("explore-verify-button").textContent, "Continue to Verify with these files");
element("explore-verify-button").listeners.click();
assert.equal(element("verify-panel").hidden, false);
assert.equal(element("verify-simple-mode").checked, true);
assert.match(element("verify-guided-source").textContent, /Using 1 public file from Explore/);
assert.equal(element("verify-button").disabled, true, "guided source cannot bypass hostname and separate root");
element("verify-hostname").value = "verify.rootwell.invalid";
element("verify-hostname").listeners.input();
element("verify-trust-file").files = [file("R")];
element("verify-trust-file").listeners.change();
assert.equal(element("verify-button").disabled, false);
let guidedCalls = 0;
engine.verifySimple = (sources, trust) => {
  guidedCalls++;
  assert.equal(sources.length, 1);
  assert.equal(sources[0][0], 65);
  assert.equal(trust[0], 82);
  return JSON.stringify({ schema_version: "rootwell.browser.verify.v1", ok: false, result: null,
    error: { code: "unknown-authority" } });
};
await element("verify-button").listeners.click();
assert.equal(guidedCalls, 1);
assert.match(element("verify-next-step").textContent, /Do not trust a root merely because it came in the same bundle/);
assert.equal(element("verify-result").hidden, true);
element("verify-source-files").files = [file("S")];
element("verify-source-files").listeners.change();
assert.equal(element("verify-guided-source").hidden, true, "manual source choice replaces guided files");

select([file("A"), file("B")]);
await explore();
element("explore-verify-button").listeners.click();
assert.match(element("verify-guided-source").textContent, /Nothing was transferred to Simple Verify/);
assert.equal(element("verify-button").disabled, true, "ambiguous public files cannot inherit a previous source");

const changingGuidedFile = file("A");
select([changingGuidedFile]);
await explore();
element("explore-verify-button").listeners.click();
assert.equal(element("verify-button").disabled, false);
element("verify-simple-mode").checked = false;
element("verify-advanced-mode").checked = true;
element("verify-advanced-mode").listeners.change();
assert.equal(element("verify-guided-source").hidden, true, "Advanced cannot silently reuse Simple's handoff");
element("verify-simple-mode").checked = true;
element("verify-advanced-mode").checked = false;
element("verify-simple-mode").listeners.change();
assert.equal(element("verify-button").disabled, true, "switching back requires explicit source selection");
element("explore-verify-button").listeners.click();
assert.equal(element("verify-button").disabled, false);
changingGuidedFile.arrayBuffer = async () => Uint8Array.of(66).buffer;
await element("verify-button").listeners.click();
assert.equal(guidedCalls, 1, "changed guided source must not reach verification");
assert.match(element("verify-error").textContent, /Files changed since Explore/);
assert.equal(element("verify-result").hidden, true);
select([file("B")]);
assert.equal(element("verify-guided-source").hidden, true, "new Explore selection clears transferred files");
assert.equal(element("verify-button").disabled, true);

select([file("C")]);
await explore();
assert.match(element("explore-health-summary").textContent, /0 possible website certificates, 1 CA certificate/);
assert.match(element("explore-health-next").textContent, /root or bundle alone is not enough/);
element("explore-verify-button").listeners.click();
assert.match(element("verify-guided-source").textContent, /Nothing was transferred to Simple Verify/);
assert.equal(element("verify-button").disabled, true);

const verificationSuccess = JSON.stringify({
  schema_version: "rootwell.browser.verify.v1", ok: true, error: null,
  result: {
    profile: "tls-server", verification: "passed", hostname: "verify.rootwell.invalid",
    evaluated_at: "2026-09-25T09:00:00Z", trust_source: "explicit-file", root_pin: "not-provided",
    revocation: "not-checked", network: "disabled", ignored_source_roots: 1,
    chain: [
      { Subject: "CN=verify.rootwell.invalid", Issuer: "CN=Test Root", SHA256Fingerprint: certificate(65).sha256 },
      { Subject: "CN=Test Root", Issuer: "CN=Test Root", SHA256Fingerprint: certificate(66).sha256 }
    ]
  }
});
const verificationFailure = JSON.stringify({
  schema_version: "rootwell.browser.verify.v1", ok: false, result: null,
  error: { code: "unknown-authority" }
});
select([file("A")]);
await explore();
element("explore-verify-button").listeners.click();
assert.equal(element("verify-button").disabled, false);
engine.verifySimple = (sources, trust) => {
  assert.equal(sources.length, 1);
  assert.equal(sources[0][0], 65);
  assert.equal(trust[0], 82);
  return verificationSuccess;
};
await element("verify-button").listeners.click();
assert.equal(element("verify-result").hidden, false, "unchanged guided files can reach the existing verifier");
element("verify-source-files").files = [file("S")];
element("verify-source-files").listeners.change();
assert.equal(element("verify-result").hidden, true, "manual replacement invalidates guided verdict");
assert.equal(element("verify-guided-source").hidden, true);
let simpleVerifyCalls = 0;
engine.verifySimple = (sources, trust, hostname, _time, rootPin) => {
  simpleVerifyCalls++;
  assert.equal(sources.length, 1);
  assert.equal(trust[0], 82);
  assert.equal(hostname, "verify.rootwell.invalid");
  assert.equal(rootPin, "");
  return verificationSuccess;
};
element("verify-simple-mode").checked = true;
element("verify-advanced-mode").checked = false;
element("verify-hostname").value = "verify.rootwell.invalid";
element("verify-hostname").listeners.input();
element("verify-root-pin").value = "";
element("verify-trust-file").files = [file("R")];
element("verify-trust-file").listeners.change();
element("verify-source-files").files = [file("S")];
element("verify-source-files").listeners.change();
assert.equal(element("verify-button").disabled, false);
await element("verify-button").listeners.click();
assert.equal(simpleVerifyCalls, 1);
assert.equal(element("verify-result").hidden, false);
assert.equal(element("verify-next-step").hidden, true);
assert.equal(element("verify-chain").children.length, 2);
assert.match(element("verify-ignored-roots").textContent, /ignored as trust sources/);
assert.equal(element("verify-export-button").disabled, false);
let verifiedSimpleExportCalls = 0;
engine.exportVerifiedSimple = (sources, trust, hostname, evaluatedAt, expected) => {
  verifiedSimpleExportCalls++;
  assert.equal(sources.length, 1);
  assert.equal(trust[0], 82);
  assert.equal(hostname, "verify.rootwell.invalid");
  assert.equal(typeof evaluatedAt, "string");
  assert.deepEqual(Array.from(expected), [certificate(65).sha256, certificate(66).sha256]);
  exportedCertificates = [certificate(65)];
  return { schema_version: "rootwell.browser.verified-export.v1", ok: true, error: null,
    result: { fingerprints: [certificate(65).sha256], hostname,
      evaluated_at: "2026-09-25T09:00:00Z", trust_source: "explicit-file", root_included: false,
      filename: "rootwell-verified-fullchain-" + "b".repeat(32) + ".pem", bytes: Uint8Array.of(80) } };
};
await element("verify-export-button").listeners.click();
assert.equal(verifiedSimpleExportCalls, 1);
assert.equal(element("verify-result").hidden, false);
assert.equal(element("verify-export-button").disabled, false);
assert.match(document.body.children.at(-1).download, /^rootwell-verified-fullchain-[0-9a-f]{32}\.pem$/);
element("verify-root-pin").value = certificate(66).sha256;
element("verify-root-pin").listeners.input();
assert.equal(element("verify-result").hidden, true, "editing root pin must invalidate the old verdict");
assert.equal(element("verify-export-button").disabled, true);
const pinnedSuccess = JSON.parse(verificationSuccess);
pinnedSuccess.result.root_pin = "matched";
engine.verifySimple = (_sources, _trust, _hostname, _time, rootPin) => {
  assert.equal(rootPin, certificate(66).sha256);
  return JSON.stringify(pinnedSuccess);
};
await element("verify-button").listeners.click();
assert.equal(element("verify-result").hidden, false);
assert.match(element("verify-root-pin-status").textContent, /matches the expected full SHA-256/);
const forgedPinSuccess = JSON.parse(verificationSuccess);
forgedPinSuccess.result.root_pin = "matched";
forgedPinSuccess.result.chain[1].SHA256Fingerprint = certificate(67).sha256;
engine.verifySimple = () => JSON.stringify(forgedPinSuccess);
await element("verify-button").listeners.click();
assert.equal(element("verify-result").hidden, true, "a fabricated pin match must not render as verified");
assert.match(element("verify-error").textContent, /invalid response/);
element("verify-root-pin").value = "";
element("verify-root-pin").listeners.input();
assert.equal(element("verify-result").hidden, true);
engine.verifySimple = () => verificationSuccess;
await element("verify-button").listeners.click();
let finishDelayedVerifyRead;
const originalVerifyRead = element("verify-source-files").files[0].arrayBuffer;
element("verify-source-files").files[0].arrayBuffer = () => new Promise((resolve) => { finishDelayedVerifyRead = resolve; });
const pendingVerifiedExport = element("verify-export-button").listeners.click();
element("verify-trust-file").files = [];
element("verify-trust-file").listeners.change();
finishDelayedVerifyRead(Uint8Array.of(83).buffer);
await pendingVerifiedExport;
element("verify-source-files").files[0].arrayBuffer = originalVerifyRead;
assert.equal(verifiedSimpleExportCalls, 1, "stale selection must not reach verified export");
assert.equal(element("verify-result").hidden, true);
assert.equal(element("verify-chain").children.length, 0);
assert.equal(element("verify-button").disabled, true);
assert.equal(element("verify-export-button").disabled, true);

engine.verifySimple = () => verificationFailure;
element("verify-trust-file").files = [file("R")];
element("verify-trust-file").listeners.change();
await element("verify-button").listeners.click();
assert.equal(element("verify-result").hidden, true);
assert.equal(element("verify-chain").children.length, 0);
assert.match(element("verify-error").textContent, /No path reaches/);
assert.match(element("verify-next-step").textContent, /check whether the CA-provided intermediate is missing/);

engine.verifySimple = () => JSON.stringify({ schema_version: "rootwell.browser.verify.v1", ok: false,
  result: null, error: { code: "attacker-controlled", message: "<script>secret-marker</script>" } });
await element("verify-button").listeners.click();
assert.match(element("verify-error").textContent, /invalid response/);
assert.ok(!element("verify-error").textContent.includes("secret-marker"));
assert.ok(!element("verify-next-step").textContent.includes("secret-marker"));

const forgedVerification = JSON.parse(verificationSuccess);
forgedVerification.result.trust_source = "system-roots";
engine.verifySimple = () => JSON.stringify(forgedVerification);
await element("verify-button").listeners.click();
assert.equal(element("verify-result").hidden, true, "untrusted success metadata must not render as verified");
assert.equal(element("verify-chain").children.length, 0);
assert.match(element("verify-error").textContent, /invalid response/);

let advancedCalls = 0;
engine.verifyExplicit = (leaf, intermediates, trust, hostname, evaluatedAt) => {
  advancedCalls++;
  assert.equal(leaf[0], 76);
  assert.equal(intermediates[0], 73);
  assert.equal(trust[0], 82);
  assert.equal(hostname, "verify.rootwell.invalid");
  assert.equal(evaluatedAt, "2026-09-25T09:00:00Z");
  return verificationSuccess;
};
element("verify-simple-mode").checked = false;
element("verify-advanced-mode").checked = true;
element("verify-advanced-mode").listeners.change();
element("verify-leaf-file").files = [file("L")];
element("verify-leaf-file").listeners.change();
element("verify-intermediates-file").files = [file("I")];
element("verify-intermediates-file").listeners.change();
element("verify-time").value = "2026-09-25T09:00:00Z";
element("verify-time").listeners.input();
assert.equal(element("verify-button").disabled, false);
await element("verify-button").listeners.click();
assert.equal(advancedCalls, 1);
assert.equal(element("verify-result").hidden, false);
assert.equal(element("verify-chain").children.length, 2);
engine.exportVerifiedExplicit = () => ({ schema_version: "rootwell.browser.verified-export.v1", ok: true, error: null,
  result: { fingerprints: [certificate(65).sha256], hostname: "verify.rootwell.invalid",
    evaluated_at: "2026-09-25T09:00:00Z", trust_source: "explicit-file", root_included: true,
    filename: "rootwell-verified-fullchain-" + "c".repeat(32) + ".pem", bytes: Uint8Array.of(80) } });
await element("verify-export-button").listeners.click();
assert.equal(element("verify-result").hidden, true, "an invalid export response must invalidate Verified state");
assert.equal(element("verify-export-button").disabled, true);
assert.match(element("verify-error").textContent, /invalid response/);

console.log("Rootwell multi-file and Verify Workbench behavior passed.");
