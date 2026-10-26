import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const source=fs.readFileSync("cmd/rootwelld/auth/renewal-timing.js","utf8"),html=fs.readFileSync("cmd/rootwelld/auth/acme.html","utf8");
assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|console\.|sendBeacon|WebSocket|XMLHttpRequest|https:\/\//);
assert.match(html,/When should I renew/);assert.match(html,/No private key, password or DNS token is sent/);
assert.ok(html.indexOf('/renewal-timing.js')<html.indexOf('/acme-order.js'),"timing reads selection before order clears its marker");
const now=Math.floor(Date.now()/1000)*1000,stamp=n=>new Date(n).toISOString().replace(".000Z","Z"),fp=Array(32).fill("AB").join(":"),other=Array(32).fill("CD").join(":");
const initial={fingerprint:fp,not_after:stamp(now+86400000),prepared:false,state:"not-prepared",started_at:"",observed_at:"",pending:false,can_read:true,can_interrupt:false,source:"",renew_at:"",fallback_at:"",effective_at:"",next_check:"",provider_not_before:"",blocked:false,failures:0,window_start:"",window_end:"",checked_at:"",expired:false,superseded:false};
const saved={...initial,prepared:true,state:"ari",started_at:stamp(now-1000),observed_at:stamp(now),can_read:false,source:"ari",renew_at:stamp(now+3600000),fallback_at:stamp(now+7200000),effective_at:stamp(now+3600000),next_check:stamp(now+60000),window_start:stamp(now+3600000),window_end:stamp(now+5400000),checked_at:stamp(now)};
const output=(s,mode="status",gen=13)=>({schema_version:"rootwell.acme.renewal-timing.v1",provider:"letsencrypt-staging",generation:gen,checked_at:stamp(now),unlock_expires:stamp(now+43200000),network_attempted:mode==="check",saved:mode!=="status",automatic_renewal:false,status:s});
const response=d=>new Response(JSON.stringify(d),{headers:{"content-type":"application/json","cache-control":"no-store"}});
class Element{constructor(){this.value="";this.checked=false;this.disabled=false;this.hidden=true;this.textContent="";this.children=[];this.listeners={};}addEventListener(n,f){this.listeners[n]=f;}appendChild(v){this.children.push(v);}replaceChildren(){this.children=[];}}
function start(data=output(initial)){
  const elements={},el=id=>elements[id]??=new Element(),events={},windows={},timers=new Map(),requests=[],sent=[];let index=0,clock=now,fetcher=()=>response(data);
  class Clock extends Date{static now(){return clock;}}
  const document={hidden:false,getElementById:el,createElement:()=>new Element(),addEventListener(n,f){events[n]=f;}};
  const window={addEventListener(n,f){windows[n]=f;},dispatchEvent(e){sent.push(e.type);windows[e.type]?.();}};
  const context={document,window,Date:Clock,TextDecoder,AbortController,Event,setTimeout(f,ms){const id=++index;timers.set(id,{f,ms});return id;},clearTimeout(id){timers.delete(id);},fetch:async(url,options)=>{requests.push({url,options});assert.match(url,/^\/api\/acme\/renewal-timing\/(status|check|interrupt)$/);assert.equal(options.credentials,"same-origin");assert.equal(options.cache,"no-store");assert.equal(options.redirect,"error");assert.equal(options.headers["X-Rootwell-Request"],"1");return fetcher(url,options);}};
  vm.runInNewContext(source,context);
  const api=context.rootwellRenewalTiming;
  api.setCertificates([{fingerprint:other,name:"Ordinary imported certificate",state:"manual"},{fingerprint:fp,name:"mail.example.com",not_after:initial.not_after,state:"due"}],13);
  return {api,el,events,windows,timers,requests,sent,document,advance:n=>{clock+=n;},override:f=>{fetcher=f;},read:()=>el("renewal-time-refresh").listeners.click(),submit:()=>el("renewal-time-form").listeners.submit({preventDefault(){}}),consent:()=>{el("renewal-time-password").value="synthetic-test-password";el("renewal-time-password").listeners.input();el("renewal-time-consent").checked=true;el("renewal-time-consent").listeners.change();}};
}
{
  const f=start();assert.equal(f.requests.length,0,"no automatic provider/status calls");assert.equal(f.el("renewal-time-certificate").children.length,1,"imports remain manual");await f.read();assert.equal(f.el("renewal-time-result").hidden,false);assert.equal(f.el("renewal-time-form").hidden,false);assert.equal(f.el("renewal-time-submit").disabled,true);
  assert.deepEqual(JSON.parse(f.requests[0].options.body),{provider:"letsencrypt-staging",fingerprint:fp,expected_generation:13});
  await f.submit();assert.equal(f.requests.length,1,"missing password/consent cannot connect");f.el("renewal-time-password").value="synthetic-test-password";await f.submit();assert.equal(f.requests.length,1,"password alone cannot connect");
  f.consent();assert.equal(f.el("renewal-time-submit").disabled,false);f.override((url,options)=>{assert.equal(url,"/api/acme/renewal-timing/check");const input=JSON.parse(options.body);assert.equal(input.password,"synthetic-test-password");assert.equal(input.confirm,true);assert.equal(Object.keys(input).length,5);return response(output(saved,"check",15));});
  await f.submit();assert.equal(f.el("renewal-time-result").hidden,false);assert.match(f.el("renewal-time-next").textContent,/Suggested renewal time/);assert.match(f.el("renewal-time-reason").textContent,/Next provider check/);assert.equal(f.el("renewal-time-form").hidden,true);assert.equal(f.el("renewal-time-password").value,"");assert.equal(f.el("renewal-time-consent").checked,false);assert.deepEqual(f.sent,["rootwell-timing-changed"]);assert.match(f.el("renewal-time-message").textContent,/Automatic renewal is not enabled/);
  [...f.timers.values()].find(t=>t.ms===60000).f();assert.equal(f.el("renewal-time-result").hidden,true);
}
for(const s of [
  {...saved,state:"unsupported",source:"fallback",effective_at:saved.fallback_at,window_start:"",window_end:"",checked_at:""},
  {...saved,state:"error",source:"fallback",effective_at:saved.fallback_at,failures:1,provider_not_before:stamp(now+3600000)},
  {...initial,blocked:true,can_read:false},
  {...saved,expired:true,not_after:stamp(now),started_at:stamp(now-4000000),observed_at:stamp(now-4000000),renew_at:stamp(now-2700000),effective_at:stamp(now-2700000),fallback_at:stamp(now-2000),window_start:stamp(now-3600000),window_end:stamp(now-1800000),checked_at:stamp(now-4000000)},
  {...initial,superseded:true,can_read:false},
]){const f=start(output(s));if(s.expired)f.api.setCertificates([{fingerprint:fp,name:"mail.example.com",not_after:s.not_after,state:"expired"}],13);await f.read();assert.equal(f.el("renewal-time-result").hidden,false,JSON.stringify(s));assert.equal(f.el("renewal-time-form").hidden,true);}
{
  const pending={...saved,state:"pending",observed_at:"",pending:true,can_interrupt:true,failures:1};const f=start(output(pending));await f.read();assert.equal(f.el("renewal-time-form").hidden,false);assert.match(f.el("renewal-time-submit").textContent,/Finish interrupted/);assert.equal(f.el("renewal-time-privacy").hidden,true);
  f.consent();f.override((url)=>{assert.equal(url,"/api/acme/renewal-timing/interrupt");return response(output({...pending,state:"interrupted",pending:false,can_interrupt:false,observed_at:stamp(now)},"interrupt",14));});await f.submit();assert.equal(f.el("renewal-time-result").hidden,false);assert.equal(f.requests.length,2);
}
for(const change of [{automatic_renewal:true},{network_attempted:true},{saved:true},{generation:14},{schema_version:"other"},{token:"secret-sentinel"},{checked_at:stamp(now-180000)},{unlock_expires:stamp(now)},{status:{...initial,fingerprint:other}},{status:{...initial,private_key:"secret-sentinel"}},{status:{...initial,can_read:true,blocked:true}},{status:{...initial,failures:1}},{status:{...saved,source:"secret-sentinel"}},{status:{...saved,renew_at:"bad"}},{status:{...saved,observed_at:"bad"}},{status:{...saved,window_end:saved.window_start}}]){
  const f=start({...output(initial),...change});await f.read();assert.equal(f.el("renewal-time-result").hidden,true,JSON.stringify(change));assert.equal(f.el("renewal-time-form").hidden,true);assert.doesNotMatch(f.el("renewal-time-message").textContent,/secret-sentinel/);
}
for(const boundary of [f=>{f.document.hidden=true;f.events.visibilitychange();},f=>f.windows.pagehide(),f=>f.api.invalidate(),f=>f.windows["rootwell-dns-changed"](),f=>f.el("acme-order-form").listeners.submit(),f=>f.el("renewal-time-certificate").listeners.change(),f=>f.advance(25000),f=>f.advance(-1),f=>[...f.timers.values()].find(t=>t.ms===25000).f()]){
  const f=start();let release;f.override(()=>new Promise(resolve=>{release=resolve;}));const work=f.read();while(!release)await new Promise(resolve=>setImmediate(resolve));await f.read();assert.equal(f.requests.length,1);boundary(f);release(response(output(initial)));await work;assert.equal(f.el("renewal-time-result").hidden,true);assert.equal(f.el("renewal-time-form").hidden,true);
}
for(const mode of ["failure","oversize","headers"]){const f=start();f.override(()=>mode==="failure"?new Response("secret-sentinel",{status:503}):mode==="oversize"?response({...output(initial),padding:"x".repeat(16385)}):new Response(JSON.stringify(output(initial)),{headers:{"content-type":"text/plain","cache-control":"public"}}));await f.read();assert.equal(f.el("renewal-time-result").hidden,true);assert.doesNotMatch(f.el("renewal-time-message").textContent,/secret-sentinel/);}
console.log("Renewal timing UI: explicit public-source check, fresh secret clearing, local retirement, fixed result, no auto renewal, bounded/stale/hidden/late/malformed refusal passed.");
