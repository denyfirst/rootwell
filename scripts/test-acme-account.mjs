import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const source = fs.readFileSync("cmd/rootwelld/auth/acme-account.js", "utf8");
const html = fs.readFileSync("cmd/rootwelld/auth/acme.html", "utf8");
assert.doesNotMatch(source, /innerHTML|localStorage|sessionStorage|console\.|WebSocket|XMLHttpRequest|sendBeacon|https:\/\//);
assert.match(html, /not your certificate's private key/);
assert.match(html, /without contacting the provider or accepting its terms/);
assert.match(html, /complete backups, not access-only backups/);
const empty = {schema_version:"rootwell.acme.account-key.v1", provider:"letsencrypt-staging", generation:1, state:"not-prepared", fingerprint:"", prepared_at:"", saved:false, network_used:false, account_created:false, terms_accepted:false, can_issue:false};
const saved = {...empty, generation:2, state:"key-prepared", fingerprint:Array(32).fill("AB").join(":"), prepared_at:"2026-10-08T12:00:00Z", saved:true};
class Element {
  constructor() { this.value=""; this.checked=false; this.disabled=false; this.hidden=false; this.textContent=""; this.listeners={}; }
  addEventListener(n, f) { this.listeners[n]=f; }
}
function fixture() {
  const elements={}, el=id=>elements[id]??=new Element(), events={}, windows={}, timers=new Map(), requests=[];
  let next=null, id=0;
  el("acme-provider").value="letsencrypt-staging";
  const document={hidden:false, getElementById:el, addEventListener(n,f){events[n]=f;}};
  vm.runInNewContext(source, {document,window:{addEventListener(n,f){windows[n]=f;}},TextDecoder,Uint8Array,AbortController,Date,
    setTimeout(fn){const key=++id;timers.set(key,fn);return key;},clearTimeout(key){timers.delete(key);},
    fetch:async(url,options)=>{
      assert.ok(["/api/acme/account/status", "/api/acme/account/prepare"].includes(url));
      assert.equal(options.method,"POST"); assert.equal(options.credentials,"same-origin"); assert.equal(options.cache,"no-store");
      assert.equal(options.headers["X-Rootwell-Request"],"1");
      const input=JSON.parse(options.body); requests.push({url,input});
      if(url.endsWith("status")) assert.deepEqual(input,{provider:"letsencrypt-staging"});
      else assert.deepEqual(input,{provider:"letsencrypt-staging",expected_generation:1,password:"test-only password sentinel",confirm:true});
      assert.equal(el("acme-account-password").value,""); assert.equal(el("acme-account-consent").checked,false);
      if(next){const fn=next;next=null;return fn();}
      return reply(url.endsWith("prepare")?saved:empty,url.endsWith("prepare")?201:200);
    }});
  return {el,document,events,windows,timers,requests,override(fn){next=fn;},refresh(){return el("acme-account-refresh").listeners.click();},
    approve(){el("acme-account-password").value="test-only password sentinel";el("acme-account-password").listeners.input();el("acme-account-consent").checked=true;el("acme-account-consent").listeners.change();},
    prepare(){return el("acme-account-form").listeners.submit({preventDefault(){}});}};
}
const reply=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"cache-control":"no-store","content-type":"application/json"}});
{
  const f=fixture();await f.refresh();
  f.el("acme-account-password").value="test-only password sentinel";f.el("acme-account-password").listeners.input();
  await f.prepare();assert.equal(f.requests.length,1,"password alone must not generate a key");
  f.el("acme-account-password").value="";f.el("acme-account-password").listeners.input();
  f.el("acme-account-consent").checked=true;f.el("acme-account-consent").listeners.change();
  await f.prepare();assert.equal(f.requests.length,1,"consent alone must not generate a key");
}
{
  const f=fixture();assert.equal(f.requests.length,0);await f.prepare();assert.equal(f.requests.length,0);
  f.approve();await f.prepare();assert.equal(f.requests.length,0,"consent without generation cannot write");
  await f.refresh();assert.equal(f.el("acme-account-form").hidden,false);assert.equal(f.el("acme-account-prepare").disabled,true);
  await f.prepare();assert.equal(f.requests.length,1,"password and consent required");
  f.approve();assert.equal(f.el("acme-account-prepare").disabled,false);await f.prepare();
  assert.equal(f.requests.length,2);assert.match(f.el("acme-account-status").textContent,/saved encrypted.*complete backup/);
  assert.match(f.el("acme-account-status").textContent,/Not registered/);assert.equal(f.el("acme-account-form").hidden,true);
  f.approve();await f.prepare();assert.equal(f.requests.length,2,"no overwrite");
}
for(const response of [()=>new Response("secret-sentinel",{status:401}),()=>new Response("secret-sentinel",{status:403}),()=>new Response("secret-sentinel",{status:409}),()=>new Response("secret-sentinel",{status:429}),()=>new Response("secret-sentinel",{status:503}),()=>new Response("x".repeat(4097),{headers:{"cache-control":"no-store","content-type":"application/json"}}),()=>reply(null),()=>{throw new Error("secret-sentinel");},()=>reply({...saved,private_key:"secret-sentinel"}),()=>reply(saved,200),()=>reply({...saved,generation:7},201)]) {
  const f=fixture();await f.refresh();f.approve();f.override(response);await f.prepare();
  assert.doesNotMatch(f.el("acme-account-status").textContent,/saved encrypted|secret-sentinel/);
  assert.equal(f.el("acme-account-password").value,"");assert.equal(f.el("acme-account-consent").checked,false);
  f.approve();await f.prepare();assert.equal(f.requests.length,2,"uncertain attempt requires status refresh");
}
for(const field of ["network_used","account_created","terms_accepted","can_issue","saved","state","provider","schema_version","fingerprint","prepared_at","generation"]) {
  const f=fixture();f.override(()=>reply({...saved,[field]:field==="generation"?0:field==="saved"?false:field==="fingerprint"?"secret-sentinel":field==="prepared_at"?"2026-02-30T00:00:00Z":true}));await f.refresh();
  assert.doesNotMatch(f.el("acme-account-status").textContent,/saved encrypted|secret-sentinel/);
}
for(const boundary of [f=>{f.document.hidden=true;f.events.visibilitychange();},f=>f.windows.pagehide(),f=>f.el("acme-clear").listeners.click(),f=>f.el("acme-provider").listeners.change(),f=>f.el("acme-account-password").listeners.input(),f=>f.el("acme-account-consent").listeners.change(),f=>[...f.timers.values()][0]()]) {
  const f=fixture();await f.refresh();f.approve();let release;f.override(()=>new Promise(resolve=>{release=resolve;}));
  const work=f.prepare();while(!release)await new Promise(resolve=>setImmediate(resolve));await f.prepare();await f.refresh();assert.equal(f.requests.length,2);
  boundary(f);release(reply(saved,201));await work;assert.doesNotMatch(f.el("acme-account-status").textContent,/saved encrypted/);
  assert.equal(f.el("acme-account-password").value,"");assert.equal(f.el("acme-account-consent").checked,false);assert.equal(f.el("acme-account-prepare").disabled,true);
}
{
  const f=fixture();f.override(()=>reply(saved));await f.refresh();assert.match(f.el("acme-account-identity").textContent,/AB:AB/);f.events.visibilitychange();
  f.document.hidden=true;f.events.visibilitychange();assert.equal(f.el("acme-account-identity").textContent,"");assert.equal(f.el("acme-account-details").hidden,true);
}
console.log("Account-key UI: explicit local status/preparation, fresh password, no overwrites/storage, strict capabilities and late/uncertain refusal passed.");
