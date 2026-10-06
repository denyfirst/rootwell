// Real Go WASM through the actual UI, with generated non-production public data.
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import { File } from "node:buffer";
import { X509Certificate, webcrypto } from "node:crypto";

const [wasmPath, runtimePath] = process.argv.slice(2);
if (!wasmPath || !runtimePath) throw new Error("usage: test-inventory-workbench.mjs <wasm> <wasm_exec.js>");
vm.runInThisContext(fs.readFileSync(runtimePath, "utf8"));
let resolveReady;
const ready = new Promise(resolve => { resolveReady = resolve; });
globalThis.rootwellWasmReady = resolveReady;
const go = new Go();
const module = await WebAssembly.instantiate(fs.readFileSync(wasmPath), go.importObject);
void go.run(module.instance);
await ready;
const engine = { maxBytes: 16<<20, inspect: rootwellInspect, explore: rootwellExplore, analyze: rootwellAnalyze,
  exportPublic: rootwellExport, exportBundle: rootwellExportBundle, verifySimple: rootwellVerifySimple,
  verifyExplicit: rootwellVerifyExplicit, exportVerifiedSimple: rootwellExportVerifiedSimple, exportVerifiedExplicit: rootwellExportVerifiedExplicit };
const publicCert = name => new X509Certificate(fs.readFileSync("web/workbench/rootwell-verify-demo-" + name + ".pem"));
const leaf = publicCert("leaf");
const source = { schema_version: "rootwell.inventory.workbench.v1", fingerprint: leaf.fingerprint256,
  der: leaf.raw.toString("base64"), tool: "verify" };
class Element {
  constructor() { this.children=[]; this.listeners={}; this.hidden=true; this.disabled=false; this.files=[]; this.textContent=""; this.value=""; this.checked=false; this.classList={add(){},remove(){}}; }
  addEventListener(name, fn) { this.listeners[name]=fn; }
  setAttribute() {}
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children=children; }
  querySelectorAll() { return []; }
  remove() { this.removed=true; }
  scrollIntoView() {}
  click() {}
}
const app = fs.readFileSync("web/workbench/app.js", "utf8");
assert.doesNotMatch(app, /fetch\(|localStorage|sessionStorage|postMessage|innerHTML|document\.write/);
function start(payload, readyEngine = Promise.resolve(engine)) {
  const elements = new Map();
  const element = id => { if(!elements.has(id)) elements.set(id,new Element()); return elements.get(id); };
  element("inventory-source").textContent = payload;
  element("verify-simple-mode").checked=true;
  const events={};
  let downloaded=null;
  vm.runInNewContext(app, { document: { getElementById:element, querySelectorAll:()=>[], createElement:()=>new Element(), body:new Element() },
    TextEncoder, Uint8Array, File, Blob, atob, Date, crypto:webcrypto, setTimeout:()=>0,
    URL:{createObjectURL(blob){downloaded=blob;return "blob:synthetic-public";},revokeObjectURL(){}},
    rootwellWorkbenchReady:readyEngine, addEventListener:(name,fn)=>{ events[name]=fn; } });
  return { element, events, downloaded:()=>downloaded };
}
const settle = async () => { for (let i=0;i<8;i++) await new Promise(resolve=>setImmediate(resolve)); };
const valid = start(JSON.stringify(source));
await settle();
assert.equal(valid.element("inventory-source").textContent, "");
assert.equal(valid.element("inventory-source").removed, true);
assert.equal(valid.element("explore-result").hidden, false);
assert.equal(valid.element("explore-certificates").children.length,1);
assert.equal(valid.element("verify-panel").hidden,false);
assert.equal(valid.element("verify-button").disabled,true,"no automatic hostname/trust");
assert.equal(valid.element("verify-trust-file").files.length,0);
assert.equal(valid.element("verify-extra-label").hidden,false);
assert.equal(valid.element("verify-simple-inputs").hidden,true,"do not ask to re-upload a loaded certificate");
assert.equal(valid.element("verify-replace-source").hidden,false);
valid.element("verify-hostname").value="verify.rootwell.invalid";
valid.element("verify-hostname").listeners.input();
valid.element("verify-trust-file").files=[new File([publicCert("root").toString()],"separate-root.pem")];
valid.element("verify-trust-file").listeners.change();
await valid.element("verify-button").listeners.click();
assert.equal(valid.element("verify-result").hidden,true,"missing intermediate cannot verify");
valid.element("verify-extra-files").files=[new File([publicCert("intermediate").toString()],"issuer.pem")];
valid.element("verify-extra-files").listeners.change();
await valid.element("verify-button").listeners.click();
assert.equal(valid.element("verify-result").hidden,false,"explicit issuer plus separate root must verify with real core");
await valid.element("verify-export-button").listeners.click();
assert.ok(valid.downloaded(),"guided source plus added issuer must support existing verified export");
assert.equal(await valid.downloaded().text(),publicCert("leaf").toString()+publicCert("intermediate").toString(),"output excludes root and keys");
valid.element("verify-extra-files").files=[new File([leaf.raw],"duplicate-leaf.der")];
valid.element("verify-extra-files").listeners.change();
assert.equal(valid.element("verify-result").hidden,true,"new issuer choice invalidates verdict");
await valid.element("verify-button").listeners.click();
assert.equal(valid.element("verify-result").hidden,true,"duplicate leaf refused");
valid.events.pagehide();
assert.equal(valid.element("explore-result").hidden,true);
assert.equal(valid.element("verify-result").hidden,true);
assert.equal(valid.element("verify-guided-source").hidden,true);
const inspect = start(JSON.stringify({...source,tool:"inspect"}));
await settle();
assert.equal(inspect.element("inspect-panel").hidden,false);
assert.equal(inspect.element("explore-result").hidden,false);
const replaced=start(JSON.stringify(source)); await settle();
replaced.element("verify-replace-source").listeners.click();
assert.equal(replaced.element("verify-simple-inputs").hidden,false);
assert.equal(replaced.element("verify-guided-source").hidden,true);
assert.equal(replaced.element("verify-extra-label").hidden,true);
assert.equal(replaced.element("verify-button").disabled,true);
const ca = publicCert("root");
const caView = start(JSON.stringify({...source,fingerprint:ca.fingerprint256,der:ca.raw.toString("base64")}));
await settle();
assert.equal(caView.element("verify-button").disabled,true);
assert.match(caView.element("verify-guided-source").textContent,/Nothing was transferred/);
for (const bad of ["not JSON", "null", JSON.stringify({...source,owner:"secret"}), JSON.stringify({...source,tool:"convert"}),
  JSON.stringify({...source,fingerprint:"00:".repeat(31)+"00"}), JSON.stringify({...source,der:"%%%"}),
  JSON.stringify({...source,der:Buffer.alloc(65537).toString("base64")}), JSON.stringify({...source,der:Buffer.from("PRIVATE KEY").toString("base64")}),
  JSON.stringify({...source,der:publicCert("root").raw.toString("base64")})]) {
  const state=start(bad); await settle();
  assert.equal(state.element("explore-result").hidden,true,"unsafe handoff must not render");
  assert.equal(state.element("verify-button").disabled,true);
  assert.equal(state.element("explore-error").hidden,false);
}
let wake;
const later=new Promise(resolve=>{wake=resolve;});
const changed=start(JSON.stringify(source),later);
changed.element("explore-file").files=[new File([leaf.raw],"manual.der")];
changed.element("explore-file").listeners.change();
wake(engine); await settle();
assert.equal(changed.element("explore-result").hidden,true,"late readiness cannot override manual selection");
assert.match(changed.element("explore-file-state").textContent,/manual.der/);
let show;
const hidden=start(JSON.stringify(source),new Promise(resolve=>{show=resolve;}));
hidden.events.pagehide(); show(engine); await settle();
assert.equal(hidden.element("explore-result").hidden,true,"late engine cannot revive left page");
console.log("Inventory → Workbench real WASM success, explicit trust, issuer addition, refusal and cancellation passed.");
process.exit(0);
