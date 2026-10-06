// Real Go WASM through public preparation and the actual Inventory UI.
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import { File } from "node:buffer";
import { X509Certificate } from "node:crypto";
const [wasmPath, runtimePath] = process.argv.slice(2);
if (!wasmPath || !runtimePath) throw new Error("usage: test-inventory-bulk.mjs <wasm> <runtime>");
vm.runInThisContext(fs.readFileSync(runtimePath, "utf8"));
let finish;
const ready = new Promise(resolve => { finish = resolve; });
globalThis.rootwellWasmReady = finish;
const go = new Go();
const module = await WebAssembly.instantiate(fs.readFileSync(wasmPath), go.importObject);
void go.run(module.instance);
await ready;
const engine = { explore: rootwellExplore, exportPublic: rootwellExport, exportBundle: rootwellExportBundle };
const helperSource = fs.readFileSync("cmd/rootwelld/auth/inventory-import.js", "utf8");
assert.doesNotMatch(helperSource, /fetch\(|localStorage|sessionStorage|innerHTML|postMessage|createObjectURL/);
const helperContext = { rootwellInventoryEngineReady: Promise.resolve(engine), TextEncoder, Uint8Array, Date, Error };
vm.runInNewContext(helperSource, helperContext);
const helper = helperContext.rootwellInventoryImport;
const loaderSource=fs.readFileSync("cmd/rootwelld/auth/inventory-engine.js","utf8");
let assetRequest=null;
const loader={rootwellExplore:engine.explore,rootwellExport:engine.exportPublic,rootwellExportBundle:engine.exportBundle,rootwellInspectMaxBytes:16*1024*1024,
  AbortController,setTimeout:()=>1,clearTimeout(){},fetch:async(url,options)=>{assetRequest={url,options};return {ok:true};},
  Go:class {constructor(){this.importObject={};}async run(){loader.rootwellWasmReady();}},WebAssembly:{async instantiateStreaming(){return {instance:{}};}}};
vm.runInNewContext(loaderSource,loader);
await loader.rootwellInventoryEngineReady;
assert.equal(assetRequest.url,"/rootwell.wasm");
assert.equal(assetRequest.options.credentials,"same-origin");
assert.equal(assetRequest.options.redirect,"error");
assert.equal(assetRequest.options.body,undefined,"asset loader has no file upload");
const unavailable={AbortController,setTimeout:()=>1,clearTimeout(){}};
vm.runInNewContext(loaderSource,unavailable);
await assert.rejects(unavailable.rootwellInventoryEngineReady,/unavailable/);
const cert = name => new X509Certificate(fs.readFileSync("web/workbench/rootwell-verify-demo-" + name + ".pem"));
const leaf = cert("leaf"), issuer = cert("intermediate"), root = cert("root");
const inputs = [new File([leaf.toString()], "leaf.crt"), new File([issuer.raw], "issuer.cer")];
const current = () => true;
const entries = await helper.preview(inputs, current);
assert.deepEqual(Array.from(entries, item => item.sha256), [leaf.fingerprint256, issuer.fingerprint256]);
const expected = entries.map(item => item.sha256);
const bytes = await helper.prepare(inputs, expected, current);
const parsed = JSON.parse(engine.explore(bytes));
assert.equal(parsed.ok, true);
assert.deepEqual(parsed.result.certificates.map(item => item.sha256), Array.from(expected));
assert.doesNotMatch(Buffer.from(bytes).toString(), /PRIVATE KEY/);
bytes.fill(0);
const bundle = new File([leaf.toString() + issuer.toString()], "bundle.pem");
assert.equal((await helper.preview([bundle], current)).length, 2);
// Distinct synthetic signatures exercise count bounds without generating or
// storing private keys; preview is parsing, never a trust verdict.
const many = Array.from({length:65}, (_, index) => {
  const der = Uint8Array.from(leaf.raw);
  der[der.length-1] = index;
  return new X509Certificate(der).toString();
});
assert.equal((await helper.preview([new File(many.slice(0,64), "64.pem")], current)).length,64);
await assert.rejects(helper.preview([new File(many, "65.pem")], current),/64 certificates/);
await assert.rejects(helper.preview([
  {size:9*1024*1024,arrayBuffer(){throw new Error("must not read oversized batch");}},
  {size:9*1024*1024,arrayBuffer(){throw new Error("must not read oversized batch");}}
],current),/16 MiB/);
for (const files of [[], Array(9).fill(inputs[0]), [new File([], "empty")],
  [new File(["garbage"], "broken.crt")], [new File(["-----BEGIN PRIVATE KEY-----\nAQ==\n-----END PRIVATE KEY-----"], "secret.pem")],
  [new File([leaf.toString() + "-----BEGIN PRIVATE KEY-----\nAQ==\n-----END PRIVATE KEY-----"], "mixed.pem")],
  [inputs[0], new File([leaf.raw], "same.der")],
  [new File([leaf.toString()+leaf.toString()], "duplicate-bundle.pem")],
  [{ size: 16*1024*1024+1, arrayBuffer(){ throw new Error("must not read oversized"); } }],
  [{ size: 1, async arrayBuffer(){ return Uint8Array.from(leaf.raw).buffer; } }]]) {
  await assert.rejects(helper.preview(files, current));
}
await assert.rejects(helper.prepare([new File([root.toString()], "changed.pem")], expected, current), /changed/);
await assert.rejects(helper.preview(inputs, () => false), /changed/);
let release;
const delayed = { size: leaf.raw.length, name:"late.der", arrayBuffer: () => new Promise(resolve => { release=resolve; }) };
let active=true;
const late=helper.preview([delayed],()=>active);
await new Promise(resolve=>setImmediate(resolve));
active=false;
release(Uint8Array.from(leaf.raw).buffer);
await assert.rejects(late,/changed/);
for (const badEngine of [
  {...engine, explore:()=>"null"},
  {...engine, exportPublic:(...args)=>{const output=engine.exportPublic(...args);output.result.fingerprint=root.fingerprint256;return output;}},
  {...engine, exportBundle:()=>({schema_version:"rootwell.browser.bundle-export.v1",ok:true,error:null,result:{fingerprints:expected,bytes:new Uint8Array(Buffer.from("private bytes"))}})}
]) {
  const bad = { rootwellInventoryEngineReady: Promise.resolve(badEngine), TextEncoder, Uint8Array, Date };
  vm.runInNewContext(helperSource,bad);
  await assert.rejects(badEngine.exportBundle!==engine.exportBundle ? bad.rootwellInventoryImport.prepare(inputs,expected,current) : bad.rootwellInventoryImport.preview(inputs,current));
}

class Element {
  constructor(){this.children=[];this.listeners={};this.value="";this.hidden=true;this.disabled=false;this.checked=false;this.files=[];this.dataset={};this.textContent="";}
  addEventListener(name,fn){this.listeners[name]=fn;}
  appendChild(node){this.children.push(node);}
  replaceChildren(){this.children=[];}
}
const source=fs.readFileSync("cmd/rootwelld/auth/inventory.js","utf8");
const settle=async()=>{for(let i=0;i<4;i++)await new Promise(resolve=>setImmediate(resolve));};
function start(){
  const elements=new Map(), element=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
  element("expiry-filter").value="all";element("warning-days").value="30";
  const documentEvents={},windowEvents={},requests=[];
  const record={fingerprint:root.fingerprint256,subject:root.subject,issuer:root.issuer,dns_names:[],not_before:"2020-01-01T00:00:00Z",not_after:"2035-01-01T00:00:00Z",owner:"",location:"",locations:[],import_generation:2};
  let records=[record], generation=2, mode="normal";
  const timers=new Map();let timerID=0;
  const document={hidden:false,getElementById:element,createElement:()=>new Element(),querySelector:()=>null,addEventListener:(name,fn)=>{documentEvents[name]=fn;}};
  vm.runInNewContext(source,{ document,window:{addEventListener:(name,fn)=>{windowEvents[name]=fn;}},
    rootwellInventoryImport:helper,TextEncoder,TextDecoder,AbortController,Uint8Array,Date,performance,Error,
    setTimeout(fn,ms){const id=++timerID;timers.set(id,{fn,ms});return id;},clearTimeout(id){timers.delete(id);},
    btoa:value=>Buffer.from(value,"binary").toString("base64"),
    fetch:async(url,options)=>{
      requests.push({url,options});
      if(options.method==="POST"){
        if(mode==="conflict")return new Response("conflict",{status:409});
        const payload=JSON.parse(options.body), content=Buffer.from(payload.certificate,"base64");
        const result=JSON.parse(engine.explore(new Uint8Array(content)));
        assert.equal(result.ok,true,"only public canonical bundle can be uploaded");
        const added=result.result.certificates.map(cert=>({...record,fingerprint:cert.sha256,subject:cert.subject,issuer:cert.issuer,owner:payload.owner,location:payload.location,locations:payload.location?[payload.location]:[],import_generation:generation+1}));
        records.push(...added);generation++;
        return new Response(JSON.stringify({generation,verification:"not-performed",records: mode==="wrong-result"?[]:added}),{status:201});
      }
      const checked=new Date().toISOString().slice(0,19)+"Z";
      return new Response(JSON.stringify({generation,verification:"not-performed",monitoring:{checked_at:checked,clock_source:"server-clock",refresh_after_seconds:60},records:records.map(r=>({...r,expiry:{status:"later",days_left:Math.ceil((Date.parse(r.not_after)-Date.parse(checked))/86400000)}}))}));
    }
  });
  const posts=()=>requests.filter(r=>r.options.method==="POST");
  const choose=files=>{element("certificate-file").files=files;element("certificate-file").value="synthetic";element("certificate-file").listeners.change();};
  return {element,choose,requests,posts,document,documentEvents,windowEvents,timers,setMode(value){mode=value;}};
}
const ui=start();await settle();
ui.choose(inputs);
await ui.element("inventory-form").listeners.submit({preventDefault(){}});
assert.equal(ui.posts().length,0,"no save without preview");
await ui.element("preview-button").listeners.click();
assert.equal(ui.posts().length,0,"preview has no upload");
assert.equal(ui.element("preview-records").children.length,2);
assert.equal(ui.element("save-button").disabled,false);
await ui.element("inventory-form").listeners.submit({preventDefault(){}});
assert.equal(ui.posts().length,1,"one request, not one request per file");
assert.match(ui.element("save-status").textContent,/2 public.*saved.*backup is not automatic/);
ui.choose(inputs);await ui.element("preview-button").listeners.click();
assert.match(ui.element("save-status").textContent,/2 certificate.*already saved/);
assert.equal(ui.element("save-button").disabled,true);
await ui.element("inventory-form").listeners.submit({preventDefault(){}});
assert.equal(ui.posts().length,1,"existing duplicates block every save");
const changed=start();await settle();changed.choose(inputs);await changed.element("preview-button").listeners.click();
changed.element("certificate-file").files=[new File([root.toString()],"replaced.pem")];
await changed.element("inventory-form").listeners.submit({preventDefault(){}});
assert.equal(changed.posts().length,0,"changed file selection must never upload");
const hidden=start();await settle();hidden.choose(inputs);await hidden.element("preview-button").listeners.click();
hidden.document.hidden=true;hidden.documentEvents.visibilitychange();
await hidden.element("inventory-form").listeners.submit({preventDefault(){}});
assert.equal(hidden.posts().length,0);assert.equal(hidden.element("import-preview").hidden,true);
const modified=start();await settle();let reads=0;
const mutable={name:"changed.der",size:leaf.raw.length,async arrayBuffer(){const data=Uint8Array.from(leaf.raw);if(++reads>1)data[data.length-1]^=1;return data.buffer;}};
modified.choose([mutable]);await modified.element("preview-button").listeners.click();assert.equal(modified.element("save-button").disabled,false,modified.element("save-status").textContent);await modified.element("inventory-form").listeners.submit({preventDefault(){}});
assert.equal(modified.posts().length,0,"changed bytes with same file and size must never upload");
assert.match(modified.element("save-status").textContent,/changed/);
const pending=start();await settle();let pendingRead=0,finishRead;
const pendingFile={name:"pending.der",size:leaf.raw.length,arrayBuffer(){if(++pendingRead>1)return new Promise(resolve=>{finishRead=resolve;});return Promise.resolve(Uint8Array.from(leaf.raw).buffer);}};
pending.choose([pendingFile]);await pending.element("preview-button").listeners.click();const pendingSave=pending.element("inventory-form").listeners.submit({preventDefault(){}});
await settle();pending.windowEvents.pagehide();finishRead(Uint8Array.from(leaf.raw).buffer);await pendingSave;
assert.equal(pending.posts().length,0,"page exit cancels a pending reread before POST");
const lateUI=start();await settle();let finishPreview;
lateUI.choose([{name:"late.der",size:leaf.raw.length,arrayBuffer:()=>new Promise(resolve=>{finishPreview=resolve;})}]);
const latePreview=lateUI.element("preview-button").listeners.click();await settle();lateUI.choose(inputs);finishPreview(Uint8Array.from(leaf.raw).buffer);await latePreview;
assert.equal(lateUI.element("import-preview").hidden,true,"late previous selection cannot populate preview");
assert.equal(lateUI.element("preview-records").children.length,0);
const timed=start();await settle();let finishTimed;
timed.choose([{name:"timed.der",size:leaf.raw.length,arrayBuffer:()=>new Promise(resolve=>{finishTimed=resolve;})}]);
const timedPreview=timed.element("preview-button").listeners.click();await settle();
Array.from(timed.timers.values()).find(timer=>timer.ms===20000).fn();
finishTimed(Uint8Array.from(leaf.raw).buffer);await timedPreview;
assert.equal(timed.element("import-preview").hidden,true,"timed-out preview cannot render late");
assert.equal(timed.element("save-button").disabled,true);
assert.match(timed.element("save-status").textContent,/timed out.*nothing was uploaded/);
for(const mode of ["conflict","wrong-result"]){const refusal=start();await settle();refusal.choose(inputs);await refusal.element("preview-button").listeners.click();refusal.setMode(mode);await refusal.element("inventory-form").listeners.submit({preventDefault(){}});assert.match(refusal.element("save-status").textContent,/could not be confirmed/);assert.doesNotMatch(refusal.element("save-status").textContent,/certificate\(s\) saved/);}
const readonly=start();await settle();readonly.element("inventory-form").dataset.readOnly="true";readonly.choose(inputs);await readonly.element("preview-button").listeners.click();assert.equal(readonly.element("save-button").disabled,true);await readonly.element("inventory-form").listeners.submit({preventDefault(){}});assert.equal(readonly.posts().length,0);
console.log("Inventory bulk preview and exact atomic Save with real Go WASM passed.");
process.exit(0);
