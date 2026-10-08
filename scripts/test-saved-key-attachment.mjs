import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import {webcrypto} from "node:crypto";
const source = fs.readFileSync("cmd/rootwelld/auth/saved-key-attachment.js","utf8");
assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|console\.|createObjectURL|WebSocket|XMLHttpRequest|sendBeacon/);
const html = fs.readFileSync("cmd/rootwelld/auth/inventory.html","utf8");
assert.match(html,/src="\/saved-key-attachment.js"/);
assert.match(html,/id="saved-key-auth" type="password"[^>]*autocomplete="off" required/);
class Element {
  constructor() {this.value="";this.files=[];this.listeners={};this.dataset={};this.hidden=true;this.disabled=false;this.checked=false;this.textContent="";}
  addEventListener(name,fn){this.listeners[name]=fn;} click(){return this.listeners.click?.();} scrollIntoView(){}
}
const fingerprint="AB:".repeat(31)+"AB", event={preventDefault(){}};
function fixture(readOnly=false) {
  const elements={}, byId=id=>elements[id]??=new Element(); byId("certificate-pair-form").dataset.readOnly=String(readOnly);
  const events={}, windows={}, requests=[], timers=new Map(); let serial=0, reads=0, next=null, now=Date.now();
  class ClockDate extends Date { static now(){return now;} }
  const record={fingerprint,subject:"<untrusted certificate>",has_private_key:false};
  const document={hidden:false,getElementById:byId,addEventListener(name,fn){events[name]=fn;}};
  const context=vm.createContext({document,window:{addEventListener(name,fn){windows[name]=fn;}},TextEncoder,TextDecoder,Uint8Array,AbortController,Date:ClockDate,crypto:webcrypto,
    btoa:value=>Buffer.from(value,"binary").toString("base64"),setTimeout(fn,delay){const id=++serial;timers.set(id,{fn,delay});return id;},clearTimeout(id){timers.delete(id);},
    fetch:async(url,options)=>{ assert.match(url,/^\/api\/certificates\/key\/(check|save)$/);assert.equal(options.method,"POST");assert.equal(options.credentials,"same-origin");assert.equal(options.cache,"no-store");assert.ok(options.signal);assert.equal(options.headers["X-Rootwell-Request"],"1");
      const body=JSON.parse(options.body);requests.push({url,body,options}); if(next){const fn=next;next=null;return fn(url,options);}
      assert.equal(body.fingerprint,fingerprint);assert.equal(body.expected_generation,2);assert.equal(body.certificate,undefined);
      if(url.endsWith("check")) assert.equal(body.password,undefined);
      return new Response(JSON.stringify({verification:"not-performed",generation:url.endsWith("save")?3:2,records:[{...record,has_private_key:true,key_status:record.key_status||"matched"}]}),{headers:{"cache-control":"no-store"}});
    }});
  vm.runInContext(source,context);const module=context.rootwellSavedKey;module.snapshot(2);module.open(record,2);
  const file=bytes=>({size:bytes.length,async arrayBuffer(){reads++;return Uint8Array.from(bytes).buffer;}});
  byId("saved-key-file").files=[file([1,2,3])];byId("saved-key-file").listeners.change();
  return {byId,module,record,requests,events,windows,document,timers,file,get reads(){return reads;},advance(delta){now+=delta;},override(fn){next=fn;}};
}
{
  const f=fixture();assert.equal(f.byId("saved-key-name").textContent,"<untrusted certificate>");
  await f.byId("saved-key-check").click();assert.equal(f.requests.length,1);assert.match(f.byId("saved-key-status").textContent,/matches/);
  await f.byId("saved-key-form").listeners.submit(event);assert.equal(f.requests.length,1,"missing instance password reached Save");
  f.byId("saved-key-auth").value="fresh-instance-password";await f.byId("saved-key-form").listeners.submit(event);
  assert.equal(f.requests[1].body.password,"fresh-instance-password");assert.equal(f.requests[1].body.allow_mismatch,false);assert.equal(f.byId("saved-key-auth").value,"");assert.equal(f.byId("saved-key-file").value,"");assert.equal(f.byId("saved-key-panel").hidden,true);assert.match(f.byId("pair-status").textContent,/Key saved/);
}
{
  const f=fixture();f.byId("saved-key-auth").value="fresh-password";await f.byId("saved-key-form").listeners.submit(event);
  assert.equal(f.requests.length,2,"direct Save must validate first");assert.ok(f.requests[0].url.endsWith("check"));assert.ok(f.requests[1].url.endsWith("save"));
}
{
  const f=fixture();f.record.key_status="mismatch";f.byId("saved-key-auth").value="fresh-password";
  await f.byId("saved-key-form").listeners.submit(event);assert.equal(f.requests.length,1,"unacknowledged mismatch saved");assert.equal(f.byId("saved-key-warning").hidden,false);
  await f.byId("saved-key-form").listeners.submit(event);assert.equal(f.requests.length,1);
  f.byId("saved-key-consent").checked=true;await f.byId("saved-key-form").listeners.submit(event);assert.equal(f.requests[1].body.allow_mismatch,true);
}
for(const response of [()=>new Response("secret-sentinel",{status:422}),()=>new Response("secret-sentinel",{status:409}),()=>new Response("secret-sentinel",{status:503}),()=>new Response('{"password":"secret-sentinel"',{headers:{"cache-control":"no-store"}}),()=>new Response("x".repeat(256*1024+1),{headers:{"cache-control":"no-store"}})]) {
  const f=fixture();f.override(response);await f.byId("saved-key-check").click();assert.doesNotMatch(f.byId("saved-key-status").textContent,/secret-sentinel/);assert.equal(f.byId("saved-key-warning").hidden,true);
}
{
  const f=fixture();await f.byId("saved-key-check").click();f.byId("saved-key-auth").value="password";f.byId("saved-key-file").files=[f.file([9,9,9])];
  await f.byId("saved-key-form").listeners.submit(event);assert.equal(f.requests.length,1,"substituted file reached save");
}
for(const boundary of [f=>f.module.snapshot(3),f=>{f.document.hidden=true;f.events.visibilitychange();},f=>f.windows.pagehide(),f=>f.byId("saved-key-close").click(),f=>f.module.reset()]) {
  const f=fixture();let release;f.override(()=>new Promise(resolve=>{release=resolve;}));const work=f.byId("saved-key-check").click();
  while(!release) await new Promise(resolve=>setImmediate(resolve));f.byId("saved-key-auth").value="secret";boundary(f);
  release(new Response(JSON.stringify({verification:"not-performed",generation:2,records:[{...f.record,has_private_key:true,key_status:"matched"}]}),{headers:{"cache-control":"no-store"}}));await work;
  assert.equal(f.byId("saved-key-panel").hidden,true);assert.equal(f.byId("saved-key-auth").value,"");assert.doesNotMatch(f.byId("saved-key-status").textContent,/matches/);
}
{
  const f=fixture(true);await f.byId("saved-key-check").click();await f.byId("saved-key-form").listeners.submit(event);assert.equal(f.reads,0);assert.equal(f.requests.length,0);assert.equal(f.byId("saved-key-file").disabled,true);
}
{
  const f=fixture();f.module.reset();f.module.open({...f.record,has_private_key:true},2);assert.equal(f.byId("saved-key-panel").hidden,true,"existing key offered for replacement");
}
{
  const f=fixture();await f.byId("saved-key-check").click();f.byId("saved-key-auth").value="password";f.override(()=>{throw new Error("secret-sentinel");});
  await f.byId("saved-key-form").listeners.submit(event);assert.match(f.byId("saved-key-status").textContent,/may have completed/);assert.doesNotMatch(f.byId("saved-key-status").textContent,/secret-sentinel/);
}
for (const boundary of [f=>f.module.reset(),f=>f.module.snapshot(3),f=>{f.document.hidden=true;f.events.visibilitychange();},f=>f.windows.pagehide(),f=>[...f.timers.values()][0].fn()]) {
  const f=fixture();await f.byId("saved-key-check").click();f.byId("saved-key-auth").value="password";let release;
  f.override(()=>new Promise(resolve=>{release=resolve;}));const work=f.byId("saved-key-form").listeners.submit(event);
  while(!release) await new Promise(resolve=>setImmediate(resolve));boundary(f);
  release(new Response("{}",{headers:{"cache-control":"no-store"}}));await work;
  assert.match(f.byId("pair-status").textContent,/uncertain.*Refresh/);assert.equal(f.byId("saved-key-auth").value,"");assert.equal(f.byId("saved-key-panel").hidden,true);
}
{
  const f=fixture();const bytes=[1,2,3];f.byId("saved-key-file").files=[f.file(bytes)];await f.byId("saved-key-check").click();bytes[0]=9;
  f.byId("saved-key-auth").value="password";await f.byId("saved-key-form").listeners.submit(event);assert.equal(f.requests.length,1,"changed same-file bytes reached Save");
}
for(const value of [{verification:"not-performed",generation:3,records:[]},{verification:"verified",generation:2,records:[{fingerprint,has_private_key:true,key_status:"matched"}]},{verification:"not-performed",generation:2,records:[{fingerprint,has_private_key:"true",key_status:"matched"}]}]) {
  const f=fixture();f.override(()=>new Response(JSON.stringify(value),{headers:{"cache-control":"no-store"}}));await f.byId("saved-key-check").click();f.byId("saved-key-auth").value="password";
  assert.doesNotMatch(f.byId("saved-key-status").textContent,/Key matches/);assert.equal(f.byId("saved-key-warning").hidden,true);
}
for(const delta of [120000,-1]) {
  const f=fixture();await f.byId("saved-key-check").click();f.advance(delta);f.byId("saved-key-auth").value="password";
  await f.byId("saved-key-form").listeners.submit(event);assert.equal(f.requests.length,1,"expired/backward-clock preview reached Save");assert.equal(f.byId("saved-key-auth").value,"");
}
console.log("Saved-key attachment: optional Check/direct Save, fresh authentication, consent, no overwrite, readonly/stale/hidden/refusal boundaries passed.");
