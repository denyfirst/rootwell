import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const source=fs.readFileSync("cmd/rootwelld/auth/acme-registration.js","utf8"), html=fs.readFileSync("cmd/rootwelld/auth/acme.html","utf8");
assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|console\.|WebSocket|XMLHttpRequest|sendBeacon/);
assert.match(html,/never the private key, Rootwell password, domains or email/);
assert.match(html,/rel="noopener noreferrer" referrerpolicy="no-referrer"/);
const fp=Array(32).fill("AB").join(":"),termsURL="https://letsencrypt.org/documents/terms.pdf",token="A".repeat(43);
const prepared={schema_version:"rootwell.acme.account-key.v1",provider:"letsencrypt-staging",generation:2,state:"key-prepared",fingerprint:fp,prepared_at:"2026-10-09T00:00:00Z",saved:true,network_used:false,account_created:false,terms_accepted:false,can_issue:false,registration_state:"not-registered"};
const localPending={...prepared,generation:3,registration_state:"registration-pending"};
const localRegistered={...prepared,generation:4,registration_state:"registered",account_created:true,terms_accepted:true};
const preview=()=>({schema_version:"rootwell.acme.registration-preview.v1",provider:"letsencrypt-staging",generation:2,fingerprint:fp,terms_url:termsURL,preview:token,expires_at:new Date(Date.now()+299000).toISOString().replace(/\.\d{3}Z$/,"Z"),network_used:true,can_issue:false});
const registered={schema_version:"rootwell.acme.registration.v1",provider:"letsencrypt-staging",generation:4,fingerprint:fp,state:"registered",network_used:true,saved:true,can_issue:false};
const reply=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"cache-control":"no-store","content-type":"application/json"}});
class Element {
  constructor(){this.value="";this.checked=false;this.disabled=false;this.hidden=false;this.textContent="";this.listeners={};this.href="";}
  addEventListener(name,fn){this.listeners[name]=fn;}
  removeAttribute(name){if(name==="href")this.href="";}
}
function fixture(){
  const elements={},el=id=>elements[id]??=new Element(),events={},windows={},timers=new Map(),requests=[];let next=null,id=0;
  el("acme-provider").value="letsencrypt-staging";
  const document={hidden:false,getElementById:el,addEventListener(name,fn){events[name]=fn;}};
  vm.runInNewContext(source,{document,window:{addEventListener(name,fn){windows[name]=fn;}},Date,TextDecoder,Uint8Array,AbortController,
    setTimeout(fn){const key=++id;timers.set(key,fn);return key;},clearTimeout(key){timers.delete(key);},
    fetch:async(url,options)=>{
      assert.ok(["/api/acme/account/status","/api/acme/registration/preview","/api/acme/registration/register","/api/acme/registration/reconcile"].includes(url));
      assert.equal(options.method,"POST");assert.equal(options.credentials,"same-origin");assert.equal(options.cache,"no-store");assert.equal(options.redirect,"error");assert.equal(options.headers["X-Rootwell-Request"],"1");
      const input=JSON.parse(options.body);requests.push({url,input});
      assert.equal(el("acme-registration-password").value,"");assert.equal(el("acme-registration-network").checked,false);assert.equal(el("acme-registration-agree").checked,false);
      if(url.endsWith("status"))assert.deepEqual(input,{provider:"letsencrypt-staging"});
      else if(url.endsWith("preview"))assert.deepEqual(input,{provider:"letsencrypt-staging",confirm:true,expected_generation:2});
      else if(url.endsWith("register"))assert.deepEqual(input,{provider:"letsencrypt-staging",confirm:true,expected_generation:2,password:"test-only password sentinel",preview:token,terms_agreed:true});
      else assert.deepEqual(input,{provider:"letsencrypt-staging",confirm:true,expected_generation:3,password:"test-only password sentinel"});
      if(next){const fn=next;next=null;return fn();}return reply(url.endsWith("status")?prepared:url.endsWith("preview")?preview():registered);
    }});
  return {el,document,events,windows,timers,requests,override(fn){next=fn;},refresh(){return el("acme-registration-refresh").listeners.click();},
    network(){el("acme-registration-network").checked=true;el("acme-registration-network").listeners.change();},
    preview(){return el("acme-registration-preview").listeners.click();},
    approve(){this.network();el("acme-registration-agree").checked=true;el("acme-registration-agree").listeners.change();el("acme-registration-password").value="test-only password sentinel";el("acme-registration-password").listeners.input();},
    submit(){return el("acme-registration-form").listeners.submit({preventDefault(){}});}};
}
{
  const f=fixture();assert.equal(f.requests.length,0);f.approve();await f.submit();assert.equal(f.requests.length,0,"cannot register without saved status and current preview");
  await f.refresh();await f.preview();assert.equal(f.requests.length,1,"terms preview requires explicit network consent");
  f.network();await f.preview();assert.equal(f.requests.length,2);assert.equal(f.el("acme-registration-link").href,termsURL);assert.equal(f.el("acme-registration-form").hidden,false);
  f.el("acme-registration-password").value="test-only password sentinel";f.el("acme-registration-password").listeners.input();await f.submit();assert.equal(f.requests.length,2,"password alone cannot agree to terms/register");
  f.approve();assert.equal(f.el("acme-registration-submit").disabled,false);await f.submit();assert.equal(f.requests.length,3);assert.match(f.el("acme-registration-status").textContent,/registered and saved encrypted.*complete backup/);
  assert.equal(f.el("acme-registration-link").href,"");f.approve();await f.submit();assert.equal(f.requests.length,3,"consent/proof is single use");
}
{
  const f=fixture();f.override(()=>reply(localPending));await f.refresh();assert.equal(f.el("acme-registration-preview").hidden,true);assert.equal(f.el("acme-registration-agreement").hidden,true);assert.match(f.el("acme-registration-submit").textContent,/Check existing/);
  f.network();await f.submit();assert.equal(f.requests.length,1,"reconciliation needs fresh password");f.approve();await f.submit();assert.equal(f.requests[1].url,"/api/acme/registration/reconcile");assert.match(f.el("acme-registration-status").textContent,/registered and saved encrypted/);
}
{
  const f=fixture();f.override(()=>reply(localPending));await f.refresh();f.approve();f.override(()=>reply({...registered,state:"not-registered"}));await f.submit();assert.match(f.el("acme-registration-status").textContent,/confirmed no account.*key is unchanged/);
}
{
  const f=fixture();f.override(()=>reply(localRegistered));await f.refresh();assert.equal(f.el("acme-registration-controls").hidden,true);f.approve();await f.preview();await f.submit();assert.equal(f.requests.length,1);
}
for(const bad of [()=>reply({...preview(),terms_url:"https://evil.invalid/terms.pdf"}),()=>reply({...preview(),terms_url:termsURL+"?private=x"}),()=>reply({...preview(),terms_url:"https://letsencrypt.org/documents/../terms.pdf"}),()=>reply({...preview(),terms_url:"https://letsencrypt.org/documents/%74erms.pdf"}),()=>reply({...preview(),expires_at:"2019-01-01T00:00:00Z"}),()=>reply({...preview(),expires_at:"2026-02-30T00:00:00Z"}),()=>reply({...preview(),generation:3}),()=>reply({...preview(),fingerprint:fp.replace("AB","CD")}),()=>reply({...preview(),can_issue:true}),()=>reply({...preview(),private_key:"secret-sentinel"}),()=>reply({...preview(),preview:"invalid"}),()=>reply({...preview(),network_used:false}),()=>new Response("secret-sentinel",{status:502})]){
  const f=fixture();await f.refresh();f.network();f.override(bad);await f.preview();assert.equal(f.el("acme-registration-link").href,"");assert.doesNotMatch(f.el("acme-registration-status").textContent,/Current terms link checked|secret-sentinel/);f.approve();await f.submit();assert.equal(f.requests.length,2,"unsafe preview cannot create authority");
}
for(const bad of [()=>new Response("secret-sentinel",{status:401}),()=>new Response("secret-sentinel",{status:403}),()=>new Response("secret-sentinel",{status:409}),()=>new Response("secret-sentinel",{status:429}),()=>new Response("secret-sentinel",{status:503}),()=>{throw new Error("secret-sentinel");},()=>reply({...registered,generation:3}),()=>reply({...registered,state:"not-registered"}),()=>reply({...registered,can_issue:true}),()=>reply({...registered,account_url:"secret-sentinel"}),()=>new Response(JSON.stringify(registered),{headers:{"cache-control":"no-store","content-type":"application/jsonp"}}),()=>new Response("x".repeat(4097),{headers:{"cache-control":"no-store","content-type":"application/json"}}),()=>new Response(JSON.stringify(registered).replace('"saved":true','"saved":true,"saved":true'),{headers:{"cache-control":"no-store","content-type":"application/json"}})]){
  const f=fixture();await f.refresh();f.network();await f.preview();f.approve();f.override(bad);await f.submit();assert.doesNotMatch(f.el("acme-registration-status").textContent,/registered and saved|secret-sentinel/);assert.equal(f.el("acme-registration-password").value,"");assert.equal(f.el("acme-registration-link").href,"");f.approve();await f.submit();assert.equal(f.requests.length,3,"uncertain operation requires status refresh, never blind retry");
}
for(const boundary of [f=>{f.document.hidden=true;f.events.visibilitychange();},f=>f.windows.pagehide(),f=>f.el("acme-clear").listeners.click(),f=>f.el("acme-provider").listeners.change(),f=>f.el("acme-registration-password").listeners.input(),f=>f.el("acme-registration-network").listeners.change(),f=>f.el("acme-registration-agree").listeners.change(),f=>[...f.timers.values()][0]()]){
  const f=fixture();await f.refresh();f.network();await f.preview();f.approve();let release;f.override(()=>new Promise(resolve=>{release=resolve;}));const work=f.submit();while(!release)await new Promise(resolve=>setImmediate(resolve));await f.submit();await f.refresh();assert.equal(f.requests.length,3);boundary(f);release(reply(registered));await work;
  assert.doesNotMatch(f.el("acme-registration-status").textContent,/registered and saved/);assert.equal(f.el("acme-registration-password").value,"");assert.equal(f.el("acme-registration-link").href,"");assert.equal(f.el("acme-registration-submit").disabled,true);
}
{
  const f=fixture();await f.refresh();f.network();await f.preview();f.approve();[...f.timers.values()][0]();await f.submit();assert.equal(f.requests.length,2,"expired preview must lose consent/token");assert.match(f.el("acme-registration-status").textContent,/expired/);
}
console.log("Registration UI: explicit status/current terms/fresh password, same-key reconciliation, single-use authority, bounded responses and late/uncertain refusal passed.");
