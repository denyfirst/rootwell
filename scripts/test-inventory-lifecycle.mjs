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
      const events=Array.from({length:mode==="archived-history"?1025:mode==="oversize-archived-history"?5121:55},(_,i)=>({generation:i+2,at:now,action:"owner-changed",fingerprints:[leaf.fingerprint256]}));
      if(mode==="archived-history")events[events.length-1].action="history-archived";
      if(mode==="manual-dns-history"){const actions=["acme-order-started","acme-order-located","acme-dns-prepared","acme-dns-acknowledged"];for(let i=0;i<4;i++)events[events.length-4+i].action=actions[i];}
      if(mode==="certificate-request-history")events[events.length-1].action="acme-certificate-key-prepared";
      if(mode==="issuance-history"){events[events.length-2].action="acme-issuance-started";events[events.length-1].action="acme-issuance-observed";}
      if(mode==="completion-history")events[events.length-1].action="acme-certificate-saved";
      if(mode==="closed-history")events[events.length-1].action="acme-request-closed";
      if(mode==="dns-config-history"){events[events.length-2].action="dns-cloudflare-saved";events[events.length-1].action="dns-cloudflare-removed";}
      if(mode==="dns-plan-history"){events[events.length-3].action="acme-dns-plan-prepared";events[events.length-2].action="acme-dns-attempt-started";events[events.length-1].action="acme-dns-wait-saved";}
      if(mode==="dns-operation-history")events[events.length-1].action="acme-dns-result-saved";
      if(mode==="dns-recovery-history"){events[events.length-3].action="acme-dns-recovery-started";events[events.length-2].action="acme-dns-recovery-wait";events[events.length-1].action="acme-dns-recovery-result";}
      if(mode==="dns-maintenance-history"){events[events.length-3].action="acme-dns-maintenance-started";events[events.length-2].action="acme-dns-maintenance-wait";events[events.length-1].action="acme-dns-maintenance-result";}
	  if(mode==="timing-history"){const actions=["acme-timing-read-started","acme-timing-observed","acme-timing-wait-saved","acme-timing-interrupted"];for(let i=0;i<4;i++)events[events.length-4+i].action=actions[i];}
	  if(mode==="renewal-history")events[events.length-1].action="acme-renewal-started";
      if(mode==="unknown-history")events[events.length-1].action="acme-issuance-issued";
      if(mode==="bad-history")events[1].generation=999;
      const generation=events.length+1;
      return new Response(JSON.stringify({schema_version:"rootwell.inventory.activity.v1",generation,events,monitoring:{status:"ready",checked_at:now,expires_at:end,generation,attention:[]}}));
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
ui.setMode("archived-history");await ui.api.refreshActivity();assert.match(ui.el("history-status").textContent,/of 1025 recorded changes/);assert.match(ui.el("history-events").children[0].textContent,/all events retained.*History storage/);for(let page=0;page<20;page++)ui.el("history-next").listeners.click();assert.equal(ui.el("history-events").children.length,25);assert.match(ui.el("history-events").children[24].children[0].children[0].textContent,/generation 2/);
for(const mode of ["bad-history","expired-monitor","unknown-history","oversize-archived-history"]){ui.setMode(mode);await ui.api.refreshActivity();assert.equal(ui.el("history-events").children.length,0);assert.match(ui.el("background-status").textContent,/could not be confirmed/);}
ui.setMode("manual-dns-history");await ui.api.refreshActivity();assert.equal(ui.el("history-events").children.length,50);assert.match(ui.el("history-events").children[0].textContent,/acknowledgement saved.*not CA verification/);assert.match(ui.el("history-events").children[1].textContent,/DNS instructions saved/);
ui.setMode("certificate-request-history");await ui.api.refreshActivity();assert.equal(ui.el("history-events").children.length,50);assert.match(ui.el("history-events").children[0].textContent,/Certificate key prepared.*no certificate issued/);
assert.match(ui.el("history-events").children[0].textContent,/Certificate key$/);assert.doesNotMatch(ui.el("history-events").children[0].textContent,/Account key/);
ui.setMode("issuance-history");await ui.api.refreshActivity();assert.equal(ui.el("history-events").children.length,50);assert.match(ui.el("history-events").children[0].textContent,/checked.*no certificate saved.*Certificate key$/);assert.match(ui.el("history-events").children[1].textContent,/started.*outcome not confirmed.*Certificate key$/);
ui.setMode("completion-history");await ui.api.refreshActivity();assert.equal(ui.el("history-events").children.length,50);assert.match(ui.el("history-events").children[0].textContent,/Test certificate and matching key saved.*Certificate$/);assert.doesNotMatch(ui.el("history-events").children[0].textContent,/Account key|Certificate key|deployed|production trusted/);
ui.setMode("closed-history");await ui.api.refreshActivity();assert.equal(ui.el("history-events").children.length,50);assert.match(ui.el("history-events").children[0].textContent,/closed locally.*saved certificates kept.*Account key$/);
ui.setMode("dns-config-history");await ui.api.refreshActivity();assert.equal(ui.el("history-events").children.length,50);assert.match(ui.el("history-events").children[0].textContent,/removed locally.*not provider revocation.*DNS settings$/);assert.match(ui.el("history-events").children[1].textContent,/saved encrypted.*no DNS change.*DNS settings$/);assert.doesNotMatch(ui.el("history-events").children[0].textContent,/certificate\(s\)|Account key/);
ui.setMode("dns-plan-history");await ui.api.refreshActivity();assert.equal(ui.el("history-events").children.length,50);assert.match(ui.el("history-events").children[0].textContent,/wait saved.*no new DNS verdict.*DNS preparation$/);assert.match(ui.el("history-events").children[1].textContent,/intent saved.*outcome uncertain.*DNS preparation$/);assert.match(ui.el("history-events").children[2].textContent,/prepared locally.*no DNS change.*DNS preparation$/);
ui.setMode("dns-operation-history");await ui.api.refreshActivity();assert.match(ui.el("history-events").children[0].textContent,/observation saved.*not CA verification/);
ui.setMode("dns-recovery-history");await ui.api.refreshActivity();assert.equal(ui.el("history-events").children.length,50);assert.match(ui.el("history-events").children[0].textContent,/Read-only recovery observation saved.*not CA verification/);assert.match(ui.el("history-events").children[1].textContent,/Read-only recovery wait saved.*uncertain/);assert.match(ui.el("history-events").children[2].textContent,/Read-only DNS recovery started.*no create or deletion/);
ui.setMode("dns-maintenance-history");await ui.api.refreshActivity();assert.equal(ui.el("history-events").children.length,50);assert.match(ui.el("history-events").children[0].textContent,/Operator DNS observation saved.*not CA verification/);assert.match(ui.el("history-events").children[1].textContent,/Operator DNS observation wait saved/);assert.match(ui.el("history-events").children[2].textContent,/Operator DNS observation started.*no write/);
ui.setMode("renewal-history");await ui.api.refreshActivity();assert.equal(ui.el("history-events").children.length,50);assert.match(ui.el("history-events").children[0].textContent,/Test renewal requested.*original certificate kept.*Original certificate$/);
ui.setMode("timing-history");await ui.api.refreshActivity();assert.equal(ui.el("history-events").children.length,50);assert.match(ui.el("history-events").children[0].textContent,/retired locally.*retry wait kept.*Renewal timing$/);assert.match(ui.el("history-events").children[1].textContent,/retry wait saved.*no certificate renewed.*Renewal timing$/);assert.match(ui.el("history-events").children[2].textContent,/Renewal timing saved.*no certificate renewed.*Renewal timing$/);assert.match(ui.el("history-events").children[3].textContent,/check started.*result not confirmed.*Renewal timing$/);
const stale=start();stale.setMode("stale");await stale.api.open(record,5);assert.match(stale.el("comparison-status").textContent,/unavailable or changed/);stale.select([sameFile]);await stale.el("comparison-button").listeners.click();assert.equal(stale.el("comparison-result").children.length,0);
const hidden=start();await hidden.api.open(record,5);let release;hidden.select([{size:leaf.raw.length,name:"late.der",arrayBuffer:()=>new Promise(resolve=>{release=resolve;})}]);const comparing=hidden.el("comparison-button").listeners.click();await settle();hidden.document.hidden=true;hidden.docEvents.visibilitychange();release(Uint8Array.from(leaf.raw).buffer);await comparing;assert.equal(hidden.el("comparison-result").children.length,0);assert.equal(hidden.el("comparison-panel").hidden,true);
const late=start();let finishSource;late.setDelay(new Promise(resolve=>{finishSource=resolve;}));const opening=late.api.open(record,5);await settle();late.api.invalidate();finishSource();await opening;assert.equal(late.el("comparison-target").textContent,"");assert.equal(late.el("comparison-panel").hidden,true);
const failed=start();failed.setMode("failure");await failed.api.refreshActivity();assert.doesNotMatch(failed.el("background-status").textContent,/secret-looking/);
console.log("Real WASM comparison, local-only candidate, complete history, pagination, stale/error/hidden/late refusal passed.");process.exit(0);
