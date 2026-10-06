// Actual public Go WASM with the production lifecycle UI; HTTP is a fixture.
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import {File} from "node:buffer";
import {X509Certificate} from "node:crypto";
const [wasm,runtime]=process.argv.slice(2);
if(!wasm||!runtime)throw new Error("usage: test-inventory-lifecycle <wasm> <runtime>");
vm.runInThisContext(fs.readFileSync(runtime,"utf8"));
let ready;const pending=new Promise(resolve=>{ready=resolve;});globalThis.rootwellWasmReady=ready;
const go=new Go(),module=await WebAssembly.instantiate(fs.readFileSync(wasm),go.importObject);void go.run(module.instance);await pending;
const engine={explore:rootwellExplore,exportPublic:rootwellExport,exportBundle:rootwellExportBundle,compare:rootwellCompare};
for(const args of [[],[new Uint8Array()],["not bytes",new Uint8Array()],[new Uint8Array(),new Uint8Array(96*1024+1)],[new Uint8Array(),null]]){const reply=JSON.parse(rootwellCompare(...args));assert.equal(reply.ok,false);assert.equal(reply.result,null);assert.equal(reply.error,"Choose exactly one supported public certificate on each side.");}
const helperContext={rootwellInventoryEngineReady:Promise.resolve(engine),Uint8Array,TextEncoder,Error,Date};
vm.runInNewContext(fs.readFileSync("cmd/rootwelld/auth/inventory-import.js","utf8"),helperContext);
const leaf=new X509Certificate(fs.readFileSync("web/workbench/rootwell-verify-demo-leaf.pem")),other=new X509Certificate(fs.readFileSync("web/workbench/rootwell-demo-certificate.pem"));
const source=fs.readFileSync("cmd/rootwelld/auth/inventory-lifecycle.js","utf8");assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|createObjectURL|console\./);
class Element{constructor(){this.listeners={};this.children=[];this.textContent="";this.value="";this.files=[];this.hidden=true;this.disabled=false;}addEventListener(name,fn){this.listeners[name]=fn;}appendChild(node){this.children.push(node);}replaceChildren(){this.children=[];}}
const settle=async()=>{for(let i=0;i<4;i++)await new Promise(resolve=>setImmediate(resolve));};
function start(){
  const elements=new Map(),el=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
  const docEvents={},winEvents={},requests=[],timers=new Map();let timerID=0,mode="normal",delay=null;
  const document={hidden:false,getElementById:el,createElement:()=>new Element(),addEventListener:(name,fn)=>{docEvents[name]=fn;}};
  const context={document,window:{addEventListener:(name,fn)=>{winEvents[name]=fn;}},Uint8Array,TextEncoder,TextDecoder,AbortController,Date,Error,
    atob:v=>Buffer.from(v,"base64").toString("binary"),setTimeout(fn,ms){const id=++timerID;timers.set(id,{fn,ms});return id;},clearTimeout(id){timers.delete(id);},rootwellInventoryEngineReady:Promise.resolve(engine),rootwellInventoryImport:helperContext.rootwellInventoryImport,
    fetch:async(url,options)=>{
      requests.push({url,options});if(delay)await delay;
      if(mode==="failure")return new Response("secret-looking error",{status:503});
      if(url.endsWith("comparison-source")){
        assert.deepEqual(JSON.parse(options.body),{fingerprint:leaf.fingerprint256,expected_generation:5});
        assert.doesNotMatch(options.body,/CERTIFICATE|private|candidate|der/i,"candidate is never uploaded");
        return new Response(JSON.stringify({schema_version:"rootwell.inventory.comparison-source.v1",generation:mode==="stale"?6:5,fingerprint:leaf.fingerprint256,der:leaf.raw.toString("base64")}));
      }
      const now=new Date().toISOString().slice(0,19)+"Z",end=mode==="expired-monitor"?now:new Date(Date.now()+12*3600000).toISOString().slice(0,19)+"Z";
      const events=Array.from({length:55},(_,i)=>({generation:i+2,at:now,action:"owner-changed",fingerprints:[leaf.fingerprint256]}));
      if(mode==="bad-history")events[1].generation=999;
      return new Response(JSON.stringify({schema_version:"rootwell.inventory.activity.v1",generation:56,events,monitoring:{status:"ready",checked_at:now,expires_at:end,generation:56,attention:[]}}));
    }};
  vm.runInNewContext(source,context);
  const select=files=>{el("comparison-file").files=files;el("comparison-file").listeners.change();};
  return{api:context.rootwellInventoryLifecycle,el,select,requests,document,docEvents,winEvents,timers,setMode(v){mode=v;},setDelay(v){delay=v;}};
}
const record={fingerprint:leaf.fingerprint256,subject:"<not HTML>"},sameFile=new File([leaf.toString()],"same.crt"),otherFile=new File([other.toString()],"new.cer");
const ui=start();await ui.api.open(record,5);assert.match(ui.el("comparison-target").textContent,/<not HTML>/);ui.select([sameFile]);await ui.el("comparison-button").listeners.click();
assert.match(ui.el("comparison-result").children[0].textContent,/exactly the same/);assert.match(ui.el("comparison-status").textContent,/No save, replacement, trust/);assert.equal(ui.requests.length,1,"only saved public source request");
ui.select([otherFile]);await ui.el("comparison-button").listeners.click();assert.match(ui.el("comparison-result").children[1].textContent,/Public key changed/);assert.ok(ui.el("comparison-result").children.some(v=>v.textContent.includes("Removed names:")));assert.equal(ui.requests.length,1);
for(const files of [[new File(["-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"],"bad.pem")],[new File([leaf.toString()+other.toString()],"bundle.pem")],[new File(["broken"],"bad.der")],[sameFile,otherFile]]){ui.select(files);await ui.el("comparison-button").listeners.click();assert.equal(ui.el("comparison-result").children.length,0);assert.doesNotMatch(ui.el("comparison-status").textContent,/finished locally/);assert.equal(ui.requests.length,1);}
await ui.api.refreshActivity();assert.equal(ui.el("history-events").children.length,50);assert.match(ui.el("background-status").textContent,/Server checked.*without this page/);ui.el("history-next").listeners.click();assert.equal(ui.el("history-events").children.length,5);ui.el("history-previous").listeners.click();assert.equal(ui.el("history-events").children.length,50);
for(const mode of ["bad-history","expired-monitor"]){ui.setMode(mode);await ui.api.refreshActivity();assert.equal(ui.el("history-events").children.length,0);assert.match(ui.el("background-status").textContent,/could not be confirmed/);}
const stale=start();stale.setMode("stale");await stale.api.open(record,5);assert.match(stale.el("comparison-status").textContent,/unavailable or changed/);stale.select([sameFile]);await stale.el("comparison-button").listeners.click();assert.equal(stale.el("comparison-result").children.length,0);
const hidden=start();await hidden.api.open(record,5);let release;hidden.select([{size:leaf.raw.length,name:"late.der",arrayBuffer:()=>new Promise(resolve=>{release=resolve;})}]);const comparing=hidden.el("comparison-button").listeners.click();await settle();hidden.document.hidden=true;hidden.docEvents.visibilitychange();release(Uint8Array.from(leaf.raw).buffer);await comparing;assert.equal(hidden.el("comparison-result").children.length,0);assert.equal(hidden.el("comparison-panel").hidden,true);
const late=start();let finishSource;late.setDelay(new Promise(resolve=>{finishSource=resolve;}));const opening=late.api.open(record,5);await settle();late.api.invalidate();finishSource();await opening;assert.equal(late.el("comparison-target").textContent,"");assert.equal(late.el("comparison-panel").hidden,true);
const failed=start();failed.setMode("failure");await failed.api.refreshActivity();assert.doesNotMatch(failed.el("background-status").textContent,/secret-looking/);
console.log("Real WASM comparison, local-only candidate, complete history, pagination, stale/error/hidden/late refusal passed.");process.exit(0);
