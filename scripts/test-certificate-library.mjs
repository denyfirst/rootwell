import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import { webcrypto } from "node:crypto";

const source = fs.readFileSync(new URL("../cmd/rootwelld/auth/certificate-library.js",import.meta.url),"utf8");
const html = fs.readFileSync(new URL("../cmd/rootwelld/auth/inventory.html",import.meta.url),"utf8");
assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|console\.|WebSocket|XMLHttpRequest|sendBeacon/);
assert.match(html,/Certificate <span>\(includes its public key\)/);
assert.match(html,/Private key <span>\(optional/);
assert.match(html,/id="pair-save" type="submit" disabled/);
assert.doesNotMatch(html,/>Vault</,"one visible library, not a second storage destination");
const home=fs.readFileSync(new URL("../web/workbench/index.html",import.meta.url),"utf8");
assert.match(home,/href="\/certificates"/); assert.doesNotMatch(home,/>\s*Vault\s*</);

class Element {
  constructor(id="") { this.id=id; this.value=""; this.files=[]; this.listeners={}; this.dataset={}; this.hidden=true; this.disabled=false; this.textContent=""; this.options=[{},{}]; }
  addEventListener(event,fn) { this.listeners[event]=fn; }
  click() { return this.listeners.click?.(); }
  remove() {} scrollIntoView() {}
}
const fingerprint=Array.from({length:32},()=>"AB").join(":");
function fixture(readOnly=false) {
  const elements={}; const byId=id=>elements[id]??=new Element(id);
  byId("certificate-pair-form").dataset.readOnly=String(readOnly);
  const listeners={}, windowListeners={}, requests=[], downloads=[], timers=new Map(); let timerId=0, next=null;
  const record={fingerprint,subject:"<certificate-name>",not_after:"2027-01-01T00:00:00Z",has_private_key:true,expiry:{days_left:45}};
  const document={hidden:false,getElementById:byId,addEventListener(e,f){listeners[e]=f;},createElement(){return new Element();},body:{appendChild(el){ downloads.push(el); }}};
  const context=vm.createContext({document,window:{addEventListener(e,f){windowListeners[e]=f;}},TextEncoder,TextDecoder,Uint8Array,AbortController,Blob,Date,crypto:webcrypto,
    btoa:s=>Buffer.from(s,"binary").toString("base64"),URL:{createObjectURL(){return "blob:fixture";},revokeObjectURL(){}},
    setTimeout(fn,ms){ const id=++timerId; timers.set(id,{fn,ms}); return id; },clearTimeout(id){timers.delete(id);},
    fetch:async(url,options)=>{
      assert.equal(options.method,"POST"); assert.equal(options.credentials,"same-origin"); assert.equal(options.cache,"no-store");
      assert.equal(options.headers["X-Rootwell-Request"],"1"); assert.ok(options.signal);
      const body=JSON.parse(options.body); requests.push({url,options,body});
      if(next) { const fn=next; next=null; return await fn(url,options); }
      if(url.endsWith("download")) return new Response("archive-fixture",{headers:{"cache-control":"no-store","content-type":"application/zip","content-disposition":'attachment; filename="rootwell-certificate-'+"a".repeat(32)+'.zip"'}});
      return new Response(JSON.stringify({verification:"not-performed",generation:body.expected_generation+(url.endsWith("save")?1:0),records:[{...record,has_private_key:Buffer.from(body.private_key,"base64").length>0}]}),{headers:{"cache-control":"no-store"}});
    }});
  vm.runInContext(source,context);
  const library=context.rootwellCertificateLibrary;
  library.snapshot(1);
  let reads=0;
  const file=bytes=>({size:bytes.length,arrayBuffer:async()=>{reads++;return Uint8Array.from(bytes).buffer;}});
  byId("pair-certificate").files=[file([1,2,3])];byId("pair-key").files=[file([4,5,6])];
  return {elements,byId,library,requests,downloads,listeners,windowListeners,document,timers,record,file,get reads(){return reads;},override(fn){next=fn;}};
}
const event={preventDefault(){}};
{
  const f=fixture();
  assert.equal(f.byId("pair-save").disabled,true);
  await f.byId("certificate-pair-form").listeners.submit(event);assert.equal(f.requests.length,0,"Save before Check read/uploaded files");
  await f.byId("pair-check").click();
  assert.equal(f.requests[0].url,"/api/certificates/check");assert.equal(f.byId("pair-save").disabled,false);
  assert.equal(f.byId("pair-name").textContent,"<certificate-name>","certificate name must remain text");
  assert.match(f.byId("pair-match").textContent,/matches/);
  f.byId("pair-note").value="Nginx";
  await f.byId("certificate-pair-form").listeners.submit(event);
  assert.equal(f.requests[1].url,"/api/certificates/save");assert.equal(f.requests[1].body.fingerprint,fingerprint);
  assert.equal(f.requests[1].body.location,"Nginx");assert.match(f.byId("pair-status").textContent,/Saved/);
  assert.equal(f.byId("pair-key-password").value,"");assert.equal(f.byId("pair-save").disabled,true);
}
{
  const f=fixture();f.byId("pair-key").files=[];
  await f.byId("pair-check").click();assert.match(f.byId("pair-match").textContent,/Certificate only/);
  await f.byId("certificate-pair-form").listeners.submit(event);assert.equal(f.requests[1].body.private_key,"");assert.equal(f.requests[1].body.location,"");
}
for(const reset of [f=>f.byId("pair-key").listeners.change(),f=>f.byId("pair-certificate").listeners.change(),f=>f.byId("pair-key-password").listeners.input(),f=>f.library.snapshot(2)]) {
  const f=fixture();await f.byId("pair-check").click();reset(f);
  assert.equal(f.byId("pair-save").disabled,true);await f.byId("certificate-pair-form").listeners.submit(event);assert.equal(f.requests.length,1,"changed selection kept Save authority");
}
{
  const f=fixture();await f.byId("pair-check").click();
  f.byId("pair-key").files=[f.file([9,9,9])];
  await f.byId("certificate-pair-form").listeners.submit(event);
  assert.equal(f.requests.length,1,"substituted key reached Save");assert.match(f.byId("pair-status").textContent,/changed/);
}
for(const response of [()=>new Response("secret-sentinel",{status:400}),()=>new Response('secret-sentinel',{headers:{"cache-control":"no-store"}}),()=>new Response('{"password":"secret-sentinel"',{headers:{"cache-control":"no-store"}}),()=>new Response("x".repeat(4*1024*1024+1),{headers:{"cache-control":"no-store"}})]) {
  const f=fixture();f.override(response);await f.byId("pair-check").click();
  assert.equal(f.byId("pair-save").disabled,true);assert.doesNotMatch(f.byId("pair-status").textContent,/secret-sentinel/);
}
{
  const f=fixture(true);await f.byId("pair-check").click();await f.byId("certificate-pair-form").listeners.submit(event);
  assert.equal(f.byId("pair-certificate").disabled,true); assert.equal(f.byId("pair-key").disabled,true);
  assert.equal(f.requests.length,0);assert.equal(f.reads,0,"read-only fixture read secrets");
  f.library.openDownload(f.record,1);assert.equal(f.byId("certificate-download").hidden,true);
}
{
  const f=fixture(); f.override(()=>new Response("untrusted secret-sentinel",{status:422}));
  await f.byId("pair-check").click(); assert.equal(f.byId("pair-save").disabled,true);
  assert.equal(f.byId("pair-password-options").open,true); assert.match(f.byId("pair-status").textContent,/current password/);
  f.byId("pair-key-password").value="current-key-password"; f.byId("pair-key-password").listeners.input();
  await f.byId("pair-check").click(); assert.equal(f.requests[1].body.key_password,Buffer.from("current-key-password").toString("base64"));
  assert.equal(f.byId("pair-save").disabled,false);
}
{
  const f=fixture(); f.override(()=>new Response("untrusted secret-sentinel",{status:409,headers:{"X-Rootwell-Refusal":"duplicate-certificate"}}));
  await f.byId("pair-check").click(); assert.match(f.byId("pair-status").textContent,/already saved/);
  assert.equal(f.byId("pair-save").disabled,true);
}
{
  const f=fixture();f.library.openDownload(f.record,1);f.byId("download-kind").value="pair";f.byId("download-kind").listeners.change();
  assert.equal(f.byId("download-private-options").hidden,false);
  await f.byId("certificate-download-form").listeners.submit(event);assert.equal(f.requests.length,0,"key download skipped reauthentication UI");
  f.byId("download-password").value="instance-password";f.byId("download-key-password").value="separate-key-password";f.byId("download-key-confirm").value="different-password";
  await f.byId("certificate-download-form").listeners.submit(event);assert.equal(f.requests.length,0,"mismatched output password requested download");
  f.byId("download-key-confirm").value="separate-key-password";
  await f.byId("certificate-download-form").listeners.submit(event);
  assert.equal(f.requests[0].body.password,"instance-password");assert.equal(f.requests[0].body.pair,true);assert.equal(f.downloads.length,1);
  assert.equal(f.byId("download-password").value,"");assert.equal(f.byId("download-key-password").value,"");
  assert.match(f.byId("download-status").textContent,/ZIP itself is not encrypted/);
}
{
  const f=fixture();let complete;
  f.override(()=>new Promise(resolve=>{complete=resolve;}));
  const pending=f.byId("pair-check").click();
  while(!complete) await new Promise(resolve=>setImmediate(resolve));
  f.byId("pair-key-password").value="secret-password";f.document.hidden=true;f.listeners.visibilitychange();
  assert.equal(f.requests[0].options.signal.aborted,true);assert.equal(f.byId("pair-key-password").value,"");
  complete(new Response(JSON.stringify({verification:"not-performed",generation:1,records:[f.record]}),{headers:{"cache-control":"no-store"}}));
  await pending;assert.equal(f.byId("pair-save").disabled,true);assert.equal(f.byId("pair-preview").hidden,true);
}
{
  const f=fixture(); f.byId("pair-certificate").files=[{size:3,arrayBuffer:async()=>{throw new Error("secret-sentinel filename");}}];
  await f.byId("pair-check").click(); assert.equal(f.requests.length,0);
  assert.doesNotMatch(f.byId("pair-status").textContent,/secret-sentinel/);
}
for (const select of [f=>{f.byId("pair-certificate").files=[{size:96*1024+1}];},f=>{f.byId("pair-key").files=[{size:64*1024+1}];},f=>{f.byId("pair-key-password").value="x".repeat(257);}]) {
  const f=fixture(); select(f); await f.byId("pair-check").click();
  assert.equal(f.requests.length,0); assert.equal(f.reads,0); assert.equal(f.byId("pair-save").disabled,true);
}
{
  const f=fixture(); let complete; f.override(()=>new Promise(resolve=>{complete=resolve;}));
  const checking=f.byId("pair-check").click(); while(!complete) await new Promise(resolve=>setImmediate(resolve));
  const deadline=[...f.timers.values()].find(timer=>timer.ms===30000); assert.ok(deadline); deadline.fn();
  complete(new Response(JSON.stringify({verification:"not-performed",generation:1,records:[f.record]}),{headers:{"cache-control":"no-store"}}));
  await checking; assert.equal(f.byId("pair-save").disabled,true); assert.equal(f.byId("pair-preview").hidden,true);
  assert.match(f.byId("pair-status").textContent,/timed out/);
}
for (const response of [
  ()=>new Response("secret-sentinel",{headers:{"content-type":"application/zip"}}),
  ()=>new Response("x",{headers:{"cache-control":"no-store","content-type":"application/zip","content-disposition":'attachment; filename="secret-sentinel.zip"'}}),
  ()=>new Response("x".repeat(512*1024+1),{headers:{"cache-control":"no-store"}}),
  ()=>{throw new Error("network-secret-sentinel");}
]) {
  const f=fixture(); f.library.openDownload(f.record,1); f.override(response);
  await f.byId("certificate-download-form").listeners.submit(event);
  assert.equal(f.downloads.length,0); assert.doesNotMatch(f.byId("download-status").textContent,/secret-sentinel/);
}
for (const output of ["x".repeat(19), "x".repeat(129), "with space password value", "x".repeat(20)+"ü"]) {
  const f=fixture(); f.library.openDownload(f.record,1); f.byId("download-kind").value="pair";
  f.byId("download-password").value="instance-password"; f.byId("download-key-password").value=output; f.byId("download-key-confirm").value=output;
  await f.byId("certificate-download-form").listeners.submit(event);
  assert.equal(f.requests.length,0,"UI accepted a password refused by the encrypted-export core");
}
for (const output of ["x".repeat(20), "x".repeat(128)]) {
  const f=fixture(); f.library.openDownload(f.record,1); f.byId("download-kind").value="pair";
  f.byId("download-password").value="instance-password"; f.byId("download-key-password").value=output; f.byId("download-key-confirm").value=output;
  await f.byId("certificate-download-form").listeners.submit(event);
  assert.equal(f.requests.length,1); assert.equal(f.downloads.length,1,"valid boundary output password refused");
}
{
  const f=fixture(); f.library.openDownload(f.record,1); let complete;
  f.override(()=>new Promise(resolve=>{complete=resolve;}));
  const downloading=f.byId("certificate-download-form").listeners.submit(event);
  while(!complete) await new Promise(resolve=>setImmediate(resolve));
  f.library.snapshot(2);
  complete(new Response("certificate-fixture",{headers:{"cache-control":"no-store","content-type":"application/x-pem-file","content-disposition":'attachment; filename="rootwell-certificate-'+"a".repeat(32)+'.pem"'}}));
  await downloading; assert.equal(f.downloads.length,0); assert.equal(f.byId("certificate-download").hidden,true);
}
console.log("Unified certificate library: check/save, optional key/note, stale/hidden/late/readonly, bounded responses and authenticated download UI passed.");
