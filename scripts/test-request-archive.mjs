import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const source=fs.readFileSync("cmd/rootwelld/auth/request-archive.js","utf8");
assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|console\.|https:\/\//);
const now=Math.floor(Date.now()/1000)*1000,stamp=new Date(now).toISOString().replace('.000Z','Z');
const status={generation:201,active_requests:32,archived_requests:32,pages_free:3,can_archive:true,reason:'ready'};
const out=(s=status,saved=false)=>({schema_version:'rootwell.request-archive.v1',checked_at:stamp,network_used:false,saved,status:s});
const response=d=>new Response(JSON.stringify(d),{headers:{'content-type':'application/json','cache-control':'no-store'}});
class Element{constructor(){this.value='';this.checked=false;this.hidden=true;this.disabled=false;this.textContent='';this.listeners={};}addEventListener(n,f){this.listeners[n]=f;}}
function fixture(){const nodes={},el=id=>nodes[id]??=new Element(),events={},windows={},timers=new Map(),requests=[];let index=0,clock=now,fetcher=()=>response(out()),refreshed=0;
  class Clock extends Date{static now(){return clock;}}
  const document={hidden:false,getElementById:el,addEventListener(n,f){events[n]=f;}};
  vm.runInNewContext(source,{document,window:{addEventListener(n,f){windows[n]=f;}},rootwellInventoryLifecycle:{refreshActivity(){refreshed++;}},Date:Clock,TextDecoder,AbortController,setTimeout(f,ms){const id=++index;timers.set(id,{f,ms});return id;},clearTimeout(id){timers.delete(id);},fetch:async(url,options)=>{requests.push({url,options});return fetcher(url,options);}});
  return{el,events,windows,timers,requests,document,refreshed:()=>refreshed,advance:n=>clock+=n,override:f=>fetcher=f,read:()=>el('request-archive-status').listeners.click(),submit:()=>el('request-archive-form').listeners.submit({preventDefault(){}}),consent:()=>{el('request-archive-password').value='synthetic-password';el('request-archive-password').listeners.input();for(const id of ['request-archive-backup','request-archive-consent']){el(id).checked=true;el(id).listeners.change();}}};
}
{
  const f=fixture();assert.equal(f.requests.length,0);await f.submit();assert.equal(f.requests.length,0);await f.read();assert.equal(f.requests[0].url,'/api/acme/request-storage/status');assert.deepEqual(JSON.parse(f.requests[0].options.body),{});assert.equal(f.el('request-archive-form').hidden,false);
  f.el('request-archive-password').value='synthetic-password';await f.submit();assert.equal(f.requests.length,1,'password alone cannot archive');f.consent();
  f.override((url,options)=>{assert.equal(url,'/api/acme/request-storage/archive');assert.equal(options.credentials,'same-origin');assert.equal(options.redirect,'error');assert.equal(options.cache,'no-store');assert.deepEqual(JSON.parse(options.body),{expected_generation:201,password:'synthetic-password',confirm:true,backup_confirmed:true,scope:'lossless-request-archive'});return response(out({...status,generation:202,active_requests:0,archived_requests:64,pages_free:2,can_archive:false,reason:'not-needed'},true));});
  await f.submit();assert.equal(f.el('request-archive-password').value,'');assert.equal(f.el('request-archive-consent').checked,false);assert.equal(f.el('request-archive-form').hidden,true);assert.equal(f.refreshed(),1);assert.match(f.el('request-archive-message').textContent,/All records are retained/);
}
for(const s of [{...status,active_requests:1,can_archive:false,reason:'not-needed'},{...status,archived_requests:128,pages_free:0,can_archive:false,reason:'archive-limit',generation:6000},{...status,generation:1000000,can_archive:false,reason:'generation-limit'}]){const f=fixture();f.override(()=>response(out(s)));await f.read();assert.equal(f.el('request-archive-form').hidden,true);assert.equal(f.el('request-archive-save').disabled,true);assert.doesNotMatch(f.el('request-archive-message').textContent,/Status is not current/);}
for(const change of [{saved:true},{network_used:true},{password:'secret-sentinel'},{checked_at:new Date(now-180000).toISOString().replace('.000Z','Z')},{status:{...status,pages_free:4}},{status:{...status,can_archive:false}},{status:{...status,active_requests:33}},{status:{...status,reason:'invented'}}]){const f=fixture();f.override(()=>response({...out(),...change}));await f.read();assert.equal(f.el('request-archive-form').hidden,true);assert.equal(f.el('request-archive-save').disabled,true);assert.doesNotMatch(f.el('request-archive-message').textContent,/secret-sentinel/);}
for(const revoke of [f=>{f.document.hidden=true;f.events.visibilitychange();},f=>f.windows.pagehide(),f=>f.advance(-1),f=>f.advance(25000),f=>[...f.timers.values()].find(t=>t.ms===25000).f()]){
  const f=fixture();let release;f.override(()=>new Promise(resolve=>release=resolve));const work=f.read();while(!release)await new Promise(resolve=>setImmediate(resolve));revoke(f);release(response(out()));await work;assert.equal(f.el('request-archive-form').hidden,true);assert.equal(f.el('request-archive-save').disabled,true);
}
for(const mode of ['lost','oversize','utf8','wrong-generation']){const f=fixture();await f.read();f.consent();f.override(()=>mode==='lost'?new Response('secret-sentinel',{status:503}):mode==='oversize'?response({...out(),padding:'x'.repeat(4097)}):mode==='utf8'?new Response(new Uint8Array([255]),{headers:{'content-type':'application/json','cache-control':'no-store'}}):response(out({...status,generation:203},true)));await f.submit();assert.equal(f.el('request-archive-password').value,'');assert.equal(f.el('request-archive-form').hidden,true);assert.match(f.el('request-archive-message').textContent,/check status instead of repeating/);assert.doesNotMatch(f.el('request-archive-message').textContent,/secret-sentinel/);}
console.log('Request archive UI: explicit fresh password/backup/scope consent, exact retained counts, bounded/stale/hidden/late/error refusal, secret clearing and no automatic mutation passed.');


