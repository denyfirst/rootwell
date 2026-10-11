import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const source=fs.readFileSync("cmd/rootwelld/auth/acme-order.js","utf8"),html=fs.readFileSync("cmd/rootwelld/auth/acme.html","utf8");
assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|console\.|WebSocket|XMLHttpRequest|sendBeacon|clipboard/);
assert.match(html,/keep both Values/);assert.match(html,/Your acknowledgement does not verify DNS/);
const domains=["*.example.com","example.com"],expiry=new Date(Date.now()+3600000).toISOString().replace(/\.\d{3}Z$/,"Z");
const empty={schema_version:"rootwell.acme.manual-dns.v2",provider:"letsencrypt-staging",generation:4,state:"not-started",domains:[],expires:"",records:[],network_used:false,saved:false,domain_verified:false,can_issue:false};
const pending={...empty,generation:5,state:"request-pending",domains,saved:true};
const known={...pending,generation:6,state:"order-known"};
const ready={...known,generation:7,state:"dns-ready",expires:expiry,records:domains.map((domain,i)=>({domain,name:"_acme-challenge.example.com",value:(i?"B":"A").repeat(42)+"A",required:true}))};
const acknowledged={...ready,generation:8,state:"dns-acknowledged"};
const waiting={...ready,generation:10,state:"validation-waiting",network_used:true};
const verified={...waiting,generation:12,state:"domain-verified",domain_verified:true};
const reply=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{"cache-control":"no-store","content-type":"application/json"}});
class Element{
  constructor(){this.value="";this.checked=false;this.disabled=false;this.hidden=false;this.textContent="";this.listeners={};this.children=[];}
  addEventListener(name,fn){this.listeners[name]=fn;}
  replaceChildren(...children){this.children=children;}
  append(...children){this.children.push(...children);}
}
function fixture(initial=empty){
  const elements={},el=id=>elements[id]??=new Element(),events={},windows={},timers=new Map(),requests=[];let next=null,key=0;
  el("acme-provider").value="letsencrypt-staging";
  const document={hidden:false,getElementById:el,createElement:()=>new Element(),addEventListener(name,fn){events[name]=fn;}};
  vm.runInNewContext(source,{document,window:{addEventListener(name,fn){windows[name]=fn;}},Date,TextDecoder,Uint8Array,AbortController,
    setTimeout(fn,ms){assert.equal(ms,30000);const id=++key;timers.set(id,fn);return id;},clearTimeout(id){timers.delete(id);},
    fetch:async(url,options)=>{
      assert.ok(["/api/acme/order/status","/api/acme/order/start","/api/acme/order/resume","/api/acme/order/ack","/api/acme/order/validate","/api/acme/order/refresh"].includes(url));
      assert.equal(options.method,"POST");assert.equal(options.credentials,"same-origin");assert.equal(options.cache,"no-store");assert.equal(options.redirect,"error");assert.equal(options.headers["X-Rootwell-Request"],"1");
      const input=JSON.parse(options.body);requests.push({url,input});assert.equal(el("acme-order-password").value,"");assert.equal(el("acme-order-consent").checked,false);
      if(url.endsWith("status"))assert.deepEqual(input,{provider:"letsencrypt-staging"});
      else{assert.equal(input.password,"test-only password sentinel");assert.equal(input.confirm,true);assert.equal(input.provider,"letsencrypt-staging");assert.equal(Object.keys(input).length,url.endsWith("start")?5:4);}
      if(next){const fn=next;next=null;return fn();}
      return reply(url.endsWith("status")?initial:url.endsWith("ack")?acknowledged:url.endsWith("validate")?waiting:url.endsWith("refresh")?verified:{...ready,network_used:true});
    }});
  return {el,document,events,windows,timers,requests,override(fn){next=fn;},refresh(){return el("acme-order-refresh").listeners.click();},
    approve(){el("acme-order-consent").checked=true;el("acme-order-consent").listeners.change();el("acme-order-password").value="test-only password sentinel";el("acme-order-password").listeners.input();},
    names(value="EXAMPLE.com\n*.example.com"){el("acme-order-domains").value=value;el("acme-order-domains").listeners.input();},submit(){return el("acme-order-form").listeners.submit({preventDefault(){}});}};
}
{
  const f=fixture();assert.equal(f.requests.length,0);f.names();f.approve();await f.submit();assert.equal(f.requests.length,0);
  await f.refresh();f.names();await f.submit();assert.equal(f.requests.length,1,"requires consent/password");f.approve();await f.submit();
  assert.deepEqual(f.requests[1].input.domains,domains);assert.equal(f.requests[1].input.expected_generation,4);assert.equal(f.el("acme-order-records").hidden,false);
  const text=f.el("acme-order-records").children.flatMap(c=>c.children.map(p=>p.textContent)).join("\n");assert.match(text,/Type: TXT/);for(const r of ready.records)assert.ok(text.includes(r.value));
  f.approve();await f.submit();assert.equal(f.requests[2].url,"/api/acme/order/ack");assert.equal(f.requests[2].input.expected_generation,7);assert.match(f.el("acme-order-status").textContent,/acknowledgement is saved.*No certificate was issued/);
  assert.match(f.el("acme-order-submit").textContent,/Ask CA/);await f.submit();assert.equal(f.requests.length,3,"CA validation requires fresh consent/password");
  f.approve();await f.submit();assert.equal(f.requests[3].url,"/api/acme/order/validate");assert.equal(f.requests[3].input.expected_generation,8);assert.match(f.el("acme-order-submit").textContent,/Refresh CA/);
  f.approve();await f.submit();assert.equal(f.requests[4].url,"/api/acme/order/refresh");assert.equal(f.requests[4].input.expected_generation,10);assert.match(f.el("acme-order-status").textContent,/CA confirmed every domain.*No certificate was issued/);
}
{
  const f=fixture(pending);await f.refresh();assert.equal(f.el("acme-order-form").hidden,true);assert.match(f.el("acme-order-status").textContent,/blocked/);f.approve();await f.submit();assert.equal(f.requests.length,1,"unlocated pending cannot recreate or continue");
}
for(const state of ["validation-pending","validation-waiting","validation-failed","domain-verified"]){
  const f=fixture({...ready,generation:10,state,domain_verified:state==="domain-verified"});await f.refresh();assert.equal(f.el("acme-order-resume-choice").hidden,true);
  f.el("acme-order-resume-choice").listeners.click();assert.match(f.el("acme-order-submit").textContent,/Refresh CA/);f.approve();await f.submit();assert.equal(f.requests[1].url,"/api/acme/order/refresh","never repeats Accept after intent");
}
for(const result of [{...waiting,domain_verified:true},{...verified,domains:["evil.example.com","example.com"]},{...verified,generation:8},{...verified,can_issue:true},{...verified,state:"dns-ready"},{...verified,records:[{...verified.records[0],value:"C".repeat(42)+"A"},verified.records[1]]},{...verified,expires:"9999-01-01T00:00:00Z"}]){
  const f=fixture(acknowledged);await f.refresh();f.approve();f.override(()=>reply(result));await f.submit();assert.equal(f.el("acme-order-records").hidden,true);assert.match(f.el("acme-order-status").textContent,/not confirmed/);
}
{
  const f=fixture(acknowledged);await f.refresh();f.approve();let release;f.override(()=>new Promise(resolve=>{release=resolve;}));const work=f.submit();while(!release)await new Promise(resolve=>setImmediate(resolve));f.document.hidden=true;f.events.visibilitychange();release(reply(waiting));await work;assert.equal(f.el("acme-order-submit").disabled,true);assert.equal(f.el("acme-order-records").hidden,true);
}
{
  const f=fixture(known);await f.refresh();assert.match(f.el("acme-order-submit").textContent,/Refresh/);f.approve();await f.submit();assert.equal(f.requests[1].url,"/api/acme/order/resume");assert.equal(f.requests[1].input.expected_generation,6);
}
{
  const f=fixture({...ready,expires:"2020-01-01T00:00:00Z"});await f.refresh();assert.equal(f.el("acme-order-form").hidden,true);assert.match(f.el("acme-order-status").textContent,/expired/);f.approve();await f.submit();assert.equal(f.requests.length,1);
  f.el("acme-order-resume-choice").listeners.click();f.approve();await f.submit();assert.equal(f.requests[1].url,"/api/acme/order/resume");
}
for(const mutate of [d=>({...d,can_issue:true}),d=>({...d,domain_verified:true}),d=>({...d,private_key:"sentinel"}),d=>({...d,records:[...d.records].reverse()}),d=>({...d,records:[{...d.records[0],value:"A".repeat(42)+"B"},d.records[1]]}),d=>({...d,expires:"2026-02-30T00:00:00Z"}),d=>({...d,domains:["evil.example.com","example.com"]}),d=>({...d,state:"dns-acknowledged"}),d=>({...d,generation:4})]){
  const f=fixture();await f.refresh();f.names();f.approve();f.override(()=>reply(mutate({...ready,network_used:true})));await f.submit();assert.equal(f.el("acme-order-records").hidden,true);assert.match(f.el("acme-order-status").textContent,/not confirmed/);assert.doesNotMatch(f.el("acme-order-status").textContent,/sentinel/);f.approve();await f.submit();assert.equal(f.requests.length,2,"uncertainty requires status refresh");
}
for(const refusal of [()=>new Response("secret-sentinel",{status:401}),()=>new Response("secret-sentinel",{status:409}),()=>new Response("secret-sentinel",{status:429}),()=>new Response("secret-sentinel",{status:503}),()=>{throw new Error("secret-sentinel");},()=>reply({...ready,network_used:true},201),()=>new Response("x".repeat(8193),{headers:{"content-type":"application/json","cache-control":"no-store"}}),()=>new Response(JSON.stringify({...ready,network_used:true}).replace('"can_issue":false','"can_issue":false,"can_issue":false'),{headers:{"content-type":"application/json","cache-control":"no-store"}}),()=>new Response(new Uint8Array([0xc3,0x28]),{headers:{"content-type":"application/json","cache-control":"no-store"}})]){
  const f=fixture();await f.refresh();f.names();f.approve();f.override(refusal);await f.submit();assert.equal(f.el("acme-order-records").hidden,true);assert.doesNotMatch(f.el("acme-order-status").textContent,/sentinel|Add every required/);assert.equal(f.el("acme-order-password").value,"");
}
for(const boundary of [f=>{f.document.hidden=true;f.events.visibilitychange();},f=>f.windows.pagehide(),f=>f.el("acme-clear").listeners.click(),f=>f.el("acme-provider").listeners.change(),f=>f.el("acme-order-password").listeners.input(),f=>f.el("acme-order-consent").listeners.change(),f=>f.el("acme-order-domains").listeners.input(),f=>[...f.timers.values()][0]()]){
  const f=fixture();await f.refresh();f.names();f.approve();let release;f.override(()=>new Promise(resolve=>{release=resolve;}));const work=f.submit();while(!release)await new Promise(resolve=>setImmediate(resolve));await f.submit();await f.refresh();assert.equal(f.requests.length,2);boundary(f);release(reply({...ready,network_used:true}));await work;assert.equal(f.el("acme-order-records").hidden,true);assert.equal(f.el("acme-order-submit").disabled,true);
}
{
  const f=fixture();f.override(()=>new Promise(()=>{}));const work=f.refresh();[...f.timers.values()][0]();await work;assert.equal(f.el("acme-order-refresh").disabled,false);assert.match(f.el("acme-order-status").textContent,/not confirmed/);
}
{
  const f=fixture();f.override(()=>new Response(new ReadableStream({start(c){c.enqueue(new Uint8Array());}}),{headers:{"content-type":"application/json","cache-control":"no-store"}}));await f.refresh();assert.match(f.el("acme-order-status").textContent,/not confirmed/);
}
console.log("Manual DNS UI: explicit consent/password, both TXT values, local acknowledgement, separate CA validation/read-only refresh, no premature verification, expiry and bounded late/uncertain refusal passed (VM, not visual QA).");
