import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const source=fs.readFileSync("cmd/rootwelld/auth/acme-order.js","utf8"),html=fs.readFileSync("cmd/rootwelld/auth/acme.html","utf8");
assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|console\.|WebSocket|XMLHttpRequest|sendBeacon|clipboard/);
assert.match(html,/keep both Values/);assert.match(html,/Your acknowledgement does not verify DNS/);
const domains=["*.example.com","example.com"],expiry=new Date(Date.now()+3600000).toISOString().replace(/\.\d{3}Z$/,"Z");
const empty={schema_version:"rootwell.acme.manual-dns.v6",provider:"letsencrypt-staging",generation:4,state:"not-started",domains:[],expires:"",records:[],network_used:false,saved:false,domain_verified:false,can_issue:false,certificate_key:{prepared:false,fingerprint:"",prepared_at:""},issuance:{state:"not-started",started_at:"",checked_at:"",observation:"",expires:""},new_request:{available:false,reason:"not-started",closed_count:0}};
const pending={...empty,generation:5,state:"request-pending",domains,saved:true,new_request:{available:false,reason:"unknown-order",closed_count:0}};
const known={...pending,generation:6,state:"order-known"};
const ready={...known,generation:7,state:"dns-ready",expires:expiry,records:domains.map((domain,i)=>({domain,name:"_acme-challenge.example.com",value:(i?"B":"A").repeat(42)+"A",required:true})),new_request:{available:false,reason:"active",closed_count:0}};
const acknowledged={...ready,generation:8,state:"dns-acknowledged"};
const waiting={...ready,generation:10,state:"validation-waiting",network_used:true};
const verified={...waiting,generation:12,state:"domain-verified",domain_verified:true};
const prepared={...verified,generation:13,network_used:false,can_issue:true,certificate_key:{prepared:true,fingerprint:Array(32).fill("AB").join(":"),prepared_at:new Date().toISOString().replace(/\.\d{3}Z$/,"Z")}};
const processing={...prepared,generation:15,network_used:true,can_issue:false,issuance:{state:"awaiting-certificate",started_at:prepared.certificate_key.prepared_at,checked_at:prepared.certificate_key.prepared_at,observation:"processing",expires:expiry}};
const saved={...processing,generation:16,issuance:{...processing.issuance,state:"certificate-saved",observation:"saved"},new_request:{available:true,reason:"complete",closed_count:0}};
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
      assert.ok(["/api/acme/order/status","/api/acme/order/start","/api/acme/order/resume","/api/acme/order/ack","/api/acme/order/validate","/api/acme/order/refresh","/api/acme/order/prepare-key","/api/acme/order/issue","/api/acme/order/certificate-refresh","/api/acme/order/close-request"].includes(url));
      assert.equal(options.method,"POST");assert.equal(options.credentials,"same-origin");assert.equal(options.cache,"no-store");assert.equal(options.redirect,"error");assert.equal(options.headers["X-Rootwell-Request"],"1");
      const input=JSON.parse(options.body);requests.push({url,input});assert.equal(el("acme-order-password").value,"");assert.equal(el("acme-order-consent").checked,false);
      if(url.endsWith("status"))assert.deepEqual(input,{provider:"letsencrypt-staging"});
      else{assert.equal(input.password,"test-only password sentinel");assert.equal(input.confirm,true);assert.equal(input.provider,"letsencrypt-staging");assert.equal(Object.keys(input).length,url.endsWith("start")?5:4);}
      if(next){const fn=next;next=null;return fn();}
      return reply(url.endsWith("status")?{...initial,network_used:false}:url.endsWith("certificate-refresh")?saved:url.endsWith("issue")?processing:url.endsWith("prepare-key")?prepared:url.endsWith("ack")?acknowledged:url.endsWith("validate")?waiting:url.endsWith("refresh")?verified:{...ready,network_used:true});
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
  assert.match(f.el("acme-order-submit").textContent,/Prepare certificate key/);await f.submit();assert.equal(f.requests.length,5,"no automatic key creation or stale consent");
  f.approve();await f.submit();assert.equal(f.requests[5].url,"/api/acme/order/prepare-key");assert.equal(f.requests[5].input.expected_generation,12);assert.match(f.el("acme-order-status").textContent,/key and signed request are saved encrypted.*no certificate has been requested or issued/);
  assert.match(f.el("acme-order-submit").textContent,/Get test certificate/);await f.submit();assert.equal(f.requests.length,6,"fresh consent and password required before finalize");
  f.approve();await f.submit();assert.equal(f.requests[6].url,"/api/acme/order/issue");assert.deepEqual(Object.keys(f.requests[6].input).sort(),["confirm","expected_generation","password","provider"]);
  assert.match(f.el("acme-order-submit").textContent,/Check certificate result/);await f.submit();assert.equal(f.requests.length,7,"no automatic polling or reused consent");
  f.approve();await f.submit();assert.equal(f.requests[7].url,"/api/acme/order/certificate-refresh");assert.match(f.el("acme-order-status").textContent,/request is complete.*will stay in Certificates/);assert.equal(f.el("acme-order-records").children[1].href,"/certificates");assert.match(f.el("acme-order-submit").textContent,/Prepare a new request/);assert.equal(f.el("acme-order-submit").disabled,true);
}
{
  const f=fixture(pending);await f.refresh();assert.equal(f.el("acme-order-form").hidden,true);assert.match(f.el("acme-order-status").textContent,/blocked/);f.approve();await f.submit();assert.equal(f.requests.length,1,"unlocated pending cannot recreate or continue");
}
for(const state of ["validation-pending","validation-waiting","validation-failed","domain-verified"]){
  const f=fixture({...ready,generation:10,state,domain_verified:state==="domain-verified"});await f.refresh();assert.equal(f.el("acme-order-resume-choice").hidden,true);
  f.el("acme-order-resume-choice").listeners.click();assert.match(f.el("acme-order-submit").textContent,state==="domain-verified"?/Prepare certificate key/:/Refresh CA/);f.approve();if(state==="domain-verified")f.override(()=>reply({...prepared,generation:11}));await f.submit();assert.equal(f.requests[1].url,state==="domain-verified"?"/api/acme/order/prepare-key":"/api/acme/order/refresh","never repeats Accept after intent");
  const expired=fixture({...ready,generation:10,state,expires:"2020-01-01T00:00:00Z",domain_verified:false});await expired.refresh();
  assert.equal(expired.el("acme-order-form").hidden,true);assert.equal(expired.el("acme-order-resume-choice").hidden,true);assert.match(expired.el("acme-order-status").textContent,/expired.*no longer confirms.*unavailable/);
  expired.el("acme-order-resume-choice").listeners.click();expired.approve();await expired.submit();assert.equal(expired.requests.length,1,"expired CA observation grants no connector authority");
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
for(const result of [{...prepared,network_used:true},{...prepared,generation:14},{...prepared,certificate_key:empty.certificate_key},{...prepared,domain_verified:false},{...prepared,expires:"9999-01-01T00:00:00Z"},{...prepared,domains:["evil.example.com","example.com"]},{...prepared,certificate_key:{...prepared.certificate_key,csr:"sentinel"}},{...prepared,certificate_key:{...prepared.certificate_key,fingerprint:"invalid"}},{...prepared,certificate_key:{...prepared.certificate_key,prepared_at:"2026-02-30T00:00:00Z"}}]){
  const f=fixture(verified);await f.refresh();f.approve();f.override(()=>reply(result));await f.submit();assert.equal(f.el("acme-order-records").hidden,true);assert.match(f.el("acme-order-status").textContent,/not confirmed/);assert.doesNotMatch(f.el("acme-order-status").textContent,/sentinel/);
}
{
  const f=fixture(prepared);await f.refresh();f.approve();f.override(()=>reply({...prepared,generation:15,network_used:true,certificate_key:{...prepared.certificate_key,fingerprint:Array(32).fill("CD").join(":")}}));await f.submit();assert.match(f.el("acme-order-status").textContent,/not confirmed/,"CA refresh cannot replace durable key");
}
for(const bad of [{...ready,certificate_key:prepared.certificate_key},{...verified,certificate_key:null},{...verified,schema_version:"rootwell.acme.manual-dns.v2"}]){
  const f=fixture(bad);await f.refresh();assert.match(f.el("acme-order-status").textContent,/not confirmed/);f.approve();await f.submit();assert.equal(f.requests.length,1);
}
{
  const f=fixture(verified);await f.refresh();f.approve();let release;f.override(()=>new Promise(resolve=>{release=resolve;}));const work=f.submit();while(!release)await new Promise(resolve=>setImmediate(resolve));f.document.hidden=true;f.events.visibilitychange();release(reply(prepared));await work;assert.equal(f.el("acme-order-submit").disabled,true);assert.equal(f.el("acme-order-records").hidden,true);
}
const startedAt=prepared.certificate_key.prepared_at;
for(const [state,observation] of [["issuance-pending",""],["not-issued","ready"],["awaiting-certificate","processing"],["issuance-failed","invalid"],["certificate-saved","saved"],["saved-certificate-deleted","saved"]]) {
  const completed=["certificate-saved","saved-certificate-deleted"].includes(state);
  const initial={...prepared,generation:15,can_issue:false,issuance:{state,started_at:startedAt,checked_at:observation?startedAt:"",observation,expires:expiry},certificate_key:state==="saved-certificate-deleted"?empty.certificate_key:prepared.certificate_key,new_request:completed?saved.new_request:prepared.new_request};
  const f=fixture(initial);await f.refresh();assert.equal(f.el("acme-order-form").hidden,false);await f.submit();assert.equal(f.requests.length,1,"no automatic operation or stale consent");
  if(state==="certificate-saved") {assert.match(f.el("acme-order-status").textContent,/request is complete/);assert.equal(f.el("acme-order-records").children[1].href,"/certificates");}
  else if(state==="saved-certificate-deleted") assert.match(f.el("acme-order-status").textContent,/were removed.*Other saved certificates.*unchanged/);
  else assert.match(f.el("acme-order-status").textContent,/no certificate is saved yet/);
  assert.doesNotMatch(f.el("acme-order-status").textContent,/No certificate has been requested or issued/);
}
for(const issuance of [{state:"certificate-saved",started_at:startedAt,checked_at:startedAt,observation:"valid"},{state:"production-trusted",started_at:startedAt,checked_at:startedAt,observation:"saved"},{state:"certificate-saved",started_at:startedAt,checked_at:"2026-02-30T00:00:00Z",observation:"saved"},{state:"not-started",started_at:"",checked_at:"",observation:"",private_key:"sentinel"}]) {
  const f=fixture({...prepared,issuance});await f.refresh();assert.match(f.el("acme-order-status").textContent,/not confirmed/);assert.doesNotMatch(f.el("acme-order-status").textContent,/sentinel/);f.approve();await f.submit();assert.equal(f.requests.length,1);
}
for(const initial of [prepared,processing])for(const boundary of [f=>{f.document.hidden=true;f.events.visibilitychange();},f=>f.windows.pagehide(),f=>f.el("acme-clear").listeners.click(),f=>f.el("acme-provider").listeners.change(),f=>f.el("acme-order-password").listeners.input(),f=>f.el("acme-order-consent").listeners.change(),f=>[...f.timers.values()][0]()]){
  const f=fixture(initial);await f.refresh();f.approve();let release;f.override(()=>new Promise(resolve=>{release=resolve;}));const work=f.submit();while(!release)await new Promise(resolve=>setImmediate(resolve));await f.submit();assert.equal(f.requests.length,2);boundary(f);release(reply(initial===prepared?processing:saved));await work;assert.equal(f.el("acme-order-form").hidden,true);assert.equal(f.el("acme-order-records").hidden,true);assert.equal(f.el("acme-order-submit").disabled,true);
}
for(const bad of [{...processing,generation:14},{...processing,can_issue:true},{...processing,issuance:{...processing.issuance,observation:"valid"}},{...processing,certificate_key:{...prepared.certificate_key,fingerprint:Array(32).fill("CD").join(":")}},{...processing,domains:["evil.example.com","example.com"]},{...processing,expires:"9999-01-01T00:00:00Z"},{...processing,records:[]},{...processing,private_key:"sentinel"},{...processing,network_used:false}]){
  const f=fixture(prepared);await f.refresh();f.approve();f.override(()=>reply(bad));await f.submit();assert.match(f.el("acme-order-status").textContent,/not confirmed/);assert.equal(f.el("acme-order-records").hidden,true);f.approve();await f.submit();assert.equal(f.requests.length,2,"uncertain finalize cannot be replayed without saved status");
}
for(const bad of [{...saved,issuance:{...saved.issuance,expires:"9999-01-01T00:00:00Z"}},{...saved,issuance:{...saved.issuance,started_at:"2020-01-01T00:00:00Z"}},{...saved,generation:processing.generation}]){
  const f=fixture(processing);await f.refresh();f.approve();f.override(()=>reply(bad));await f.submit();assert.match(f.el("acme-order-status").textContent,/not confirmed/);assert.equal(f.el("acme-order-records").hidden,true);
}
for(const initial of [saved,{...ready,expires:"2020-01-01T00:00:00Z",new_request:{available:true,reason:"expired",closed_count:0}}]){
  const f=fixture(initial);await f.refresh();assert.match(f.el("acme-order-submit").textContent,/Prepare a new request/);await f.submit();assert.equal(f.requests.length,1);
  f.approve();f.override(()=>reply({...empty,generation:initial.generation+1,new_request:{...empty.new_request,closed_count:1}}));await f.submit();assert.equal(f.requests[1].url,"/api/acme/order/close-request");assert.equal(f.requests[1].input.expected_generation,initial.generation);assert.match(f.el("acme-order-status").textContent,/Old request closed locally.*unchanged/);assert.equal(f.el("acme-order-domains").value,"");f.names();await f.submit();assert.equal(f.requests.length,2,"no automatic new CA order or old consent reuse");
}
for(const next of [{available:true,reason:"active",closed_count:0},{available:true,reason:"complete",closed_count:32},{available:false,reason:"active",closed_count:-1},{available:true,reason:"complete",closed_count:0,private_key:"sentinel"}]){const f=fixture({...saved,new_request:next});await f.refresh();assert.match(f.el("acme-order-status").textContent,/not confirmed/);f.approve();await f.submit();assert.equal(f.requests.length,1);}
for(const boundary of [f=>{f.document.hidden=true;f.events.visibilitychange();},f=>f.windows.pagehide(),f=>f.el("acme-clear").listeners.click(),f=>f.el("acme-provider").listeners.change(),f=>f.el("acme-order-password").listeners.input(),f=>f.el("acme-order-consent").listeners.change(),f=>[...f.timers.values()][0]()]){
  const f=fixture(saved);await f.refresh();f.approve();let release;f.override(()=>new Promise(resolve=>{release=resolve;}));const work=f.submit();while(!release)await new Promise(resolve=>setImmediate(resolve));await f.submit();assert.equal(f.requests.length,2);boundary(f);release(reply({...empty,generation:17,new_request:{...empty.new_request,closed_count:1}}));await work;assert.equal(f.el("acme-order-form").hidden,true);assert.equal(f.el("acme-order-submit").disabled,true);
}
for(const reason of ["clock-unavailable","capacity"]){const f=fixture({...saved,new_request:{available:false,reason,closed_count:reason==="capacity"?32:0}});await f.refresh();assert.equal(f.el("acme-order-form").hidden,true);assert.match(f.el("acme-order-status").textContent,reason==="capacity"?/limit.*blocked/:/clock.*backwards/);f.approve();await f.submit();assert.equal(f.requests.length,1);}
for(const refusal of [()=>new Response("secret-sentinel",{status:401}),()=>new Response("secret-sentinel",{status:409}),()=>new Response("secret-sentinel",{status:429}),()=>{throw new Error("secret-sentinel");}]){const f=fixture(saved);await f.refresh();f.approve();f.override(refusal);await f.submit();assert.match(f.el("acme-order-status").textContent,/not confirmed/);assert.doesNotMatch(f.el("acme-order-status").textContent,/secret-sentinel|closed locally/);f.approve();await f.submit();assert.equal(f.requests.length,2);}
console.log("Manual DNS v6 UI: explicit local closure retains certificates, fresh new-request consent, bounded strict states and late/uncertain refusal passed (VM, not visual QA).");
