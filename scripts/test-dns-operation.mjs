import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const source=fs.readFileSync("cmd/rootwelld/auth/dns-operation.js","utf8"), html=fs.readFileSync("cmd/rootwelld/auth/acme.html","utf8");
assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|console\.|sendBeacon|WebSocket|XMLHttpRequest|https:\/\//);
assert.match(html,/exclusive|Exclusive/);assert.match(html,/Existing records are left alone/);assert.match(html,/Nothing runs automatically/);
const stamp=n=>new Date(n).toISOString().replace(".000Z","Z"), now=Math.floor(Date.now()/1000)*1000;
const initial={schema_version:"rootwell.dns.operation.v1",provider:"cloudflare",generation:8,network_used:false,zone_name:"example.com",server_time:stamp(now),can_prepare:true,pending_domains:["example.com"],prepared:false,prepared_at:"",expires:stamp(now+3600000),records:[]};
const row={domain:"example.com",name:"_acme-challenge.example.com",state:"created",attempts:1,not_before:stamp(now+60000),blocked:false,cleanup_attempts:0,cleanup_not_before:"",cleanup_blocked:false,checked_at:stamp(now)};
const owned={...initial,generation:11,can_prepare:false,pending_domains:[],prepared:true,prepared_at:stamp(now-1000),records:[row]};
const response=(data,status=200,headers={"cache-control":"no-store","content-type":"application/json"})=>new Response(JSON.stringify(data),{status,headers});
class Element{
  constructor(){this.value="";this.checked=false;this.disabled=false;this.hidden=false;this.textContent="";this.children=[];this.listeners={};}
  addEventListener(n,f){this.listeners[n]=f;}append(child){this.children.push(child);}replaceChildren(){this.children=[];this.value="";}
}
function fixture(data=initial){
  const elements={},el=id=>elements[id]??=new Element(),events={},windows={},timers=new Map(),requests=[];let result=data,fetcher=null,index=0,clock=now;
  class Clock extends Date{static now(){return clock;}}
  const document={hidden:false,getElementById:el,createElement:()=>new Element(),addEventListener(n,f){events[n]=f;}};
  vm.runInNewContext(source,{document,window:{addEventListener(n,f){windows[n]=f;},dispatchEvent(e){requests.push({event:e.type});}},Event,Date:Clock,TextDecoder,Uint8Array,AbortController,
    setTimeout(fn){const id=++index;timers.set(id,fn);return id;},clearTimeout(id){timers.delete(id);},fetch:async(url,options)=>{
      assert.match(url,/^\/api\/acme\/dns\/(status|add|check|cleanup|recover)$/);assert.equal(options.method,"POST");assert.equal(options.credentials,"same-origin");assert.equal(options.cache,"no-store");assert.equal(options.redirect,"error");assert.equal(options.headers["X-Rootwell-Request"],"1");
      const input=JSON.parse(options.body);requests.push({url,input});return fetcher?fetcher(url,input):response(result);
    }});
  return {el,document,events,windows,timers,requests,set(d){result=d;},override(fn){fetcher=fn;},advance(ms){clock+=ms;},refresh:()=>el("dns-operation-refresh").listeners.click(),submit:()=>el("dns-operation-form").listeners.submit({preventDefault(){}}),
    approve(exclusive=false){el("dns-operation-password").value="fresh-instance-password-sentinel";el("dns-operation-password").listeners.input();el("dns-operation-consent").checked=true;el("dns-operation-consent").listeners.change();el("dns-operation-exclusive").checked=exclusive;el("dns-operation-exclusive").listeners.change();}};
}
{
  const f=fixture();assert.equal(f.requests.length,0);assert.equal(f.el("dns-operation-form").hidden,true);await f.refresh();assert.equal(f.el("dns-operation-form").hidden,false);assert.equal(f.el("dns-operation-submit").textContent,"Add DNS record");
  await f.submit();assert.equal(f.requests.length,1);f.approve();assert.equal(f.el("dns-operation-submit").disabled,false);f.set({...owned,network_used:true});await f.submit();
  assert.equal(f.requests[1].url,"/api/acme/dns/add");assert.equal(f.requests[1].input.expected_generation,8);assert.equal(f.requests[1].input.index,0);assert.equal(f.requests[1].input.confirm,true);assert.equal(Object.keys(f.requests[1].input).length,5);assert.equal(f.requests[2].event,"rootwell-dns-changed");assert.match(f.el("dns-operation-records").children[0].textContent,/Added by Rootwell/);assert.equal(f.el("dns-operation-password").value,"");
  f.approve();assert.equal(f.el("dns-operation-submit").disabled,true,"exclusive consent required");f.approve(true);assert.equal(f.el("dns-operation-submit").disabled,false);
  f.set({...owned,generation:13,network_used:true,records:[{...row,state:"deleted",cleanup_attempts:1,cleanup_not_before:stamp(now+60000)}]});await f.submit();assert.equal(f.requests[3].url,"/api/acme/dns/cleanup");assert.equal(f.requests[3].input.exclusive,true);assert.match(f.el("dns-operation-records").children[0].textContent,/Cleanup confirmed/);f.approve(true);assert.equal(f.el("dns-operation-submit").disabled,true);
}
for(const [state,overrides,allowed] of [["borrowed",{},false],["creating",{checked_at:"",not_before:stamp(now-1000)},true],["creating",{checked_at:"",not_before:stamp(now+60000)},false],["creating",{checked_at:"",attempts:6},false],["creating",{checked_at:"",blocked:true},false],["deleting",{cleanup_attempts:1,cleanup_not_before:stamp(now-1000)},true]]){
  const f=fixture({...owned,records:[{...row,state,...overrides}]});await f.refresh();f.approve();assert.equal(f.el("dns-operation-submit").disabled,!allowed,state);
  if(allowed){f.override((_url,input)=>{assert.equal(input.expected_generation,11);return response({...owned,generation:13,network_used:true,records:[{...row,state:state==="creating"?"created":"deleted",attempts:state==="creating"?2:1,cleanup_attempts:state==="creating"?0:2,cleanup_not_before:state==="creating"?"":stamp(now+60000)}]});});await f.submit();assert.equal(f.requests[1].url,"/api/acme/dns/check");}
}
for(const cleanup of [false,true]){
  const pending={...row,state:cleanup?"deleting":"creating",checked_at:cleanup?stamp(now):"",attempts:cleanup?1:6,not_before:stamp(now-10000),cleanup_attempts:cleanup?6:0,cleanup_not_before:cleanup?stamp(now-1000):""};
  const f=fixture({...owned,records:[pending]});await f.refresh();f.approve();assert.equal(f.el("dns-operation-submit").disabled,false);assert.equal(f.el("dns-operation-submit").textContent,"Check recovery result");assert.match(f.el("dns-operation-help").textContent,/1 of 6 only reads/);
  const next={...owned,generation:13,network_used:true,records:[{...pending,recovery:{attempts:1,not_before:stamp(now+60000),blocked:false}}]};f.set(next);await f.submit();assert.equal(f.requests[1].url,"/api/acme/dns/recover");assert.equal(Object.keys(f.requests[1].input).length,5);assert.equal(f.el("dns-operation-form").hidden,false);assert.equal(f.el("dns-operation-submit").disabled,true);
  for(const recovery of [{attempts:6,not_before:stamp(now-1000),blocked:false},{attempts:2,not_before:stamp(now-1000),blocked:true}]){const b=fixture({...owned,records:[{...pending,recovery}]});await b.refresh();b.approve();assert.equal(b.el("dns-operation-submit").disabled,true);assert.match(b.el("dns-operation-help").textContent,/reviewed operator maintenance/);}
  for(const change of [r=>({...r,attempts:r.attempts-1}),r=>({...r,recovery:{attempts:3,not_before:stamp(now+60000),blocked:false}}),r=>({...r,state:"borrowed"})]){const b=fixture({...owned,records:[pending]});await b.refresh();b.approve();b.set({...next,records:[change(next.records[0])]});await b.submit();assert.equal(b.el("dns-operation-form").hidden,true,"recovery response cannot reset or skip counters");}
  const done=fixture({...owned,records:[pending]});await done.refresh();done.approve();done.set({...next,records:[{...pending,state:cleanup?"deleted":"created",checked_at:stamp(now)}]});await done.submit();assert.equal(done.el("dns-operation-form").hidden,false,"terminal recovery result accepted");
}
for(const changes of [{schema_version:"other"},{provider:"other"},{generation:0},{network_used:true},{can_prepare:1},{zone_name:"*.example.com"},{server_time:"2026-02-30T00:00:00Z"},{prepared_at:stamp(now+1000)},{pending_domains:["other.com"]},{records:[{...row,state:"verified"}]},{records:[{...row,provider_id:"secret-sentinel"}]},{records:[{...row,attempts:0}]},{records:[{...row,checked_at:""}]},{records:[{...row,cleanup_attempts:1}]},{records:[{...row,domain:"other.com"}]},{records:[row,row]},{token:"secret-sentinel"}]){
  const f=fixture({...owned,...changes});await f.refresh();assert.equal(f.el("dns-operation-form").hidden,true,JSON.stringify(changes));assert.doesNotMatch(f.el("dns-operation-status").textContent,/secret-sentinel|Saved DNS work/);
}
for(const boundary of [f=>{f.document.hidden=true;f.events.visibilitychange();},f=>f.windows.pagehide(),f=>f.el("acme-clear").listeners.click(),f=>f.el("acme-order-form").listeners.submit(),f=>f.el("dns-config-form").listeners.submit(),f=>f.el("dns-operation-domain").listeners.change(),f=>f.el("dns-operation-password").listeners.input(),f=>[...f.timers.values()][0](),f=>f.advance(30000),f=>f.advance(-1)]){
  const f=fixture();await f.refresh();f.approve();let release;f.override(()=>new Promise(resolve=>release=resolve));const work=f.submit();while(!release)await new Promise(resolve=>setImmediate(resolve));await f.submit();await f.refresh();assert.equal(f.requests.length,2,"one in-flight operation");boundary(f);release(response({...owned,network_used:true}));await work;assert.equal(f.el("dns-operation-form").hidden,true);assert.equal(f.el("dns-operation-password").value,"");assert.equal(f.el("dns-operation-submit").disabled,true);assert.doesNotMatch(f.el("dns-operation-status").textContent,/Saved DNS work/);
}
for(const code of [401,403,409,429,503]){const f=fixture();await f.refresh();f.approve();f.override(()=>response({token:"sentinel"},code));await f.submit();assert.equal(f.el("dns-operation-form").hidden,true);assert.doesNotMatch(f.el("dns-operation-status").textContent,/sentinel/);}
for(const mutate of [d=>({...d,generation:12}),d=>({...d,records:[{...row,domain:"other.com",name:"_acme-challenge.other.com"}]}),d=>({...d,records:[{...row,state:"deleted",cleanup_attempts:1,cleanup_not_before:stamp(now+60000)}]}),d=>({...d,records:[{...row,attempts:2}]})]){const f=fixture();await f.refresh();f.approve();f.set(mutate({...owned,network_used:true}));await f.submit();assert.equal(f.el("dns-operation-form").hidden,true,"changed response source/direction refused");}
console.log("DNS operation UI: explicit one-record add/read/owned cleanup, fresh password/exclusive consent, immutable source, bounded response and malformed/hidden/late/clock refusal passed.");
