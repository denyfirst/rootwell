import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const source=fs.readFileSync("cmd/rootwelld/auth/automation-status.js","utf8"),html=fs.readFileSync("cmd/rootwelld/auth/acme.html","utf8");
assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|console\.|sendBeacon|WebSocket|XMLHttpRequest|https:\/\//);
assert.match(html,/Renewal overview/);assert.match(html,/not a CA renewal window/);
const now=Math.floor(Date.now()/1000)*1000,stamp=n=>new Date(n).toISOString().replace(".000Z","Z"),fp=Array(32).fill("AB").join(":");
const row={fingerprint:fp,name:"mail.example.com",not_after:stamp(now+3600000),review_at:stamp(now-3600000),state:"due"};
const initial={schema_version:"rootwell.automation.status.v2",provider:"letsencrypt-staging",network_used:false,automatic_renewal:false,unlock_expires:stamp(now+7200000),generation:13,checked_at:stamp(now),request:"close-needed",dns:"none",dns_wait_until:"",account_ready:true,dns_saved:true,capacity:{events_free:1012,events_reserved:0,archives_free:32,records_free:499,generations_free:999987,bytes_free:90000000},certificates:[row]};
const response=(d,status=200,headers={"cache-control":"no-store","content-type":"application/json"})=>new Response(JSON.stringify(d),{status,headers});
class Element{
  constructor(){this.disabled=false;this.hidden=false;this.textContent="";this.children=[];this.listeners={};}
  addEventListener(n,f){this.listeners[n]=f;}append(v){this.children.push(v);}replaceChildren(){this.children=[];}
}
function fixture(data=initial){
  const elements={},el=id=>elements[id]??=new Element(),events={},windows={},timers=new Map(),requests=[];let clock=now,index=0,fetcher=null;
  class Clock extends Date{static now(){return clock;}}
  const document={hidden:false,getElementById:el,createElement:()=>new Element(),addEventListener(n,f){events[n]=f;}};
  vm.runInNewContext(source,{document,window:{addEventListener(n,f){windows[n]=f;}},Date:Clock,TextDecoder,AbortController,
    setTimeout(f,ms){const id=++index;timers.set(id,{f,ms});return id;},clearTimeout(id){timers.delete(id);},fetch:async(url,options)=>{
      requests.push({url,options});assert.equal(url,"/api/automation/status");assert.equal(options.method,"POST");assert.equal(options.credentials,"same-origin");assert.equal(options.cache,"no-store");assert.equal(options.redirect,"error");assert.equal(options.headers["X-Rootwell-Request"],"1");assert.deepEqual(JSON.parse(options.body),{provider:"letsencrypt-staging"});return fetcher?fetcher():response(data);
    }});
  return{el,events,windows,timers,requests,document,advance:n=>{clock+=n;},override:f=>{fetcher=f;},refresh:()=>el("automation-status-refresh").listeners.click()};
}
{
  const f=fixture();assert.equal(f.requests.length,0,"no automatic reads/network");await f.refresh();assert.equal(f.el("automation-status-result").hidden,false);assert.match(f.el("automation-status-message").textContent,/1 test certificate/);assert.match(f.el("automation-status-next").textContent,/Close the completed/);assert.match(f.el("automation-status-unlock").textContent,/Logout, lock or restart/);assert.match(f.el("automation-status-capacity").textContent,/1012 unreserved/);assert.equal(f.el("automation-status-certificates").children.length,1);
  const stale=[...f.timers.values()].find(t=>t.ms===60000);assert.ok(stale);stale.f();assert.equal(f.el("automation-status-result").hidden,true);assert.equal(f.el("automation-status-certificates").children.length,0);
}
for(const [changes,match] of [
  [{dns:"maintenance"},/reviewed operator maintenance/],
  [{dns:"unknown",dns_wait_until:stamp(now+60000)},/read-only result check/],
  [{dns:"cleanup-needed"},/temporary DNS records/],
  [{dns:"clock-unavailable"},/server clock/],
  [{request:"unknown"},/same saved request/],
  [{request:"active"},/Continue the saved/],
  [{request:"capacity"},/Storage headroom/],
  [{request:"none",account_ready:false},/terms acceptance/],
  [{request:"none"},/Certificates/],
]){const f=fixture({...initial,...changes});await f.refresh();assert.equal(f.el("automation-status-result").hidden,false);assert.match(f.el("automation-status-next").textContent,match);}
for(const change of [
  {network_used:true},{automatic_renewal:1},{schema_version:"other"},{provider:"other"},{token:"secret-sentinel"},{generation:0},
  {checked_at:stamp(now-180000)},{checked_at:"2026-02-30T00:00:00Z"},{unlock_expires:stamp(now)},{unlock_expires:stamp(now+43201000)},
  {dns_wait_until:stamp(now+60000)},{dns:"ready"},{request:"verified"},{account_ready:1},
  {capacity:{...initial.capacity,events_reserved:50}},{capacity:{...initial.capacity,records_free:500}},
  {capacity:{...initial.capacity,events_free:1000}},{capacity:{...initial.capacity,generations_free:999986}},
  {certificates:[{...row,private_key:"secret-sentinel"}]},{certificates:[{...row,state:"issued"}]},{certificates:[{...row,state:"waiting"}]},
  {certificates:[{...row,state:"manual"}]},{certificates:[{...row,fingerprint:"a".repeat(64)}]},
  {certificates:[{...row,name:"bad\u0000name"}]},{certificates:[{...row,review_at:row.not_after}]},
]){const f=fixture({...initial,...change});await f.refresh();assert.equal(f.el("automation-status-result").hidden,true,JSON.stringify(change));assert.doesNotMatch(f.el("automation-status-message").textContent,/secret-sentinel/);}
{
  const f=fixture({...initial,automatic_renewal:true});await f.refresh();assert.equal(f.el("automation-status-result").hidden,false);assert.match(f.el("automation-status-message").textContent,/active in this login/);
}
for(const state of ["manual","waiting","expired","not-yet-valid","superseded"]){
  const r={...row,state};if(state==="manual")r.review_at="";if(state==="waiting")r.review_at=stamp(now+1000);if(state==="expired")r.not_after=stamp(now);
  const f=fixture({...initial,certificates:[r]});await f.refresh();assert.equal(f.el("automation-status-result").hidden,false,state);
}
for(const boundary of [f=>{f.document.hidden=true;f.events.visibilitychange();},f=>f.windows.pagehide(),f=>f.windows["rootwell-dns-changed"](),f=>f.el("acme-order-form").listeners.submit(),f=>f.el("dns-config-form").listeners.submit(),f=>[...f.timers.values()][0].f(),f=>f.advance(10000),f=>f.advance(-1)]){
  const f=fixture();let release;f.override(()=>new Promise(resolve=>release=resolve));const work=f.refresh();while(!release)await new Promise(resolve=>setImmediate(resolve));await f.refresh();assert.equal(f.requests.length,1,"one in-flight read");boundary(f);release(response(initial));await work;assert.equal(f.el("automation-status-result").hidden,true,"late response discarded");assert.equal(f.el("automation-status-certificates").children.length,0);
}
for(const [code,headers] of [[401,undefined],[403,undefined],[409,undefined],[429,undefined],[503,undefined],[200,{"cache-control":"public","content-type":"application/json"}],[200,{"cache-control":"no-store","content-type":"text/plain"}]]){
  const f=fixture();f.override(()=>response({token:"secret-sentinel"},code,headers));await f.refresh();assert.equal(f.el("automation-status-result").hidden,true);assert.doesNotMatch(f.el("automation-status-message").textContent,/secret-sentinel/);
}
{
  const f=fixture();f.override(()=>response({...initial,huge:"x".repeat(262145)}));await f.refresh();assert.equal(f.el("automation-status-result").hidden,true,"streaming byte cap");
}
console.log("Automation overview: local read only, exact snapshot, waits/capacity, lifetime reminders, no auto authority, malformed/bounded/stale/hidden/late refusal passed.");
