import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const source=fs.readFileSync("cmd/rootwelld/auth/renewal-job.js","utf8"),html=fs.readFileSync("cmd/rootwelld/auth/acme.html","utf8");
assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|console\.|sendBeacon|WebSocket|XMLHttpRequest|https:\/\//);
assert.match(html,/one test renewal and its owned DNS cleanup/);assert.match(html,/I will not edit these challenge records/);assert.ok(html.indexOf('/renewal-job.js')<html.indexOf('/renewal-timing.js'));
const now=Math.floor(Date.now()/1000)*1000,stamp=n=>new Date(n).toISOString().replace('.000Z','Z'),fp=Array(32).fill('AB').join(':'),newfp=Array(32).fill('CD').join(':'),jid='ab'.repeat(16);
const idle={id:'',fingerprint:'',name:'',generation:0,state:'not-running',reason:'not-started',phase:'',saved_fingerprint:'',checked_at:'',next_check:'',expires:'',actions:0,limit:160};
const waiting={id:jid,fingerprint:fp,name:'mail.example.com',generation:15,state:'waiting',reason:'step-saved',phase:'timing',saved_fingerprint:'',checked_at:stamp(now),next_check:stamp(now+300000),expires:stamp(now+3600000),actions:1,limit:160};
const plan={generation:13,fingerprint:fp,name:'mail.example.com',can_start:true,reason:'timing',next_check:''};
const output=(job=idle,p=null)=>({schema_version:'rootwell.acme.renewal-job.v1',provider:'letsencrypt-staging',scope:'session-test-renewal',test_only:true,checked_at:stamp(now),job,readiness:p});
const response=(d,code=200,headers={'content-type':'application/json','cache-control':'no-store'})=>new Response(JSON.stringify(d),{status:code,headers});
class Element{constructor(){this.value='';this.checked=false;this.disabled=false;this.hidden=true;this.textContent='';this.href='';this.listeners={};}addEventListener(n,f){this.listeners[n]=f;}}
function fixture(){
  const nodes={},el=id=>nodes[id]??=new Element(),events={},windows={},timers=new Map(),requests=[],sent=[];let index=0,clock=now,fetcher=()=>response(output());
  class Clock extends Date{static now(){return clock;}}
  const document={hidden:false,getElementById:el,addEventListener(n,f){events[n]=f;}};
  const window={addEventListener(n,f){windows[n]=f;},dispatchEvent(e){sent.push(e.type);windows[e.type]?.();}};
  const context={document,window,Date:Clock,TextDecoder,AbortController,Event,setTimeout(f,ms){const id=++index;timers.set(id,{f,ms});return id;},clearTimeout(id){timers.delete(id);},fetch:async(url,options)=>{requests.push({url,options});assert.match(url,/^\/api\/acme\/renewal-job\/(preview|start|status|stop)$/);assert.equal(options.credentials,'same-origin');assert.equal(options.cache,'no-store');assert.equal(options.redirect,'error');return fetcher(url,options);}};
  vm.runInNewContext(source,context);
  return {api:context.rootwellRenewalJob,el,events,windows,timers,requests,sent,document,advance:n=>{clock+=n;},override:f=>{fetcher=f;},status:()=>el('renewal-job-status').listeners.click(),preview:()=>el('renewal-job-preview').listeners.click(),stop:()=>el('renewal-job-stop').listeners.click(),submit:()=>el('renewal-job-form').listeners.submit({preventDefault(){}}),consent:()=>{el('renewal-job-password').value='synthetic-password';el('renewal-job-password').listeners.input();el('renewal-job-consent').checked=true;el('renewal-job-consent').listeners.change();el('renewal-job-exclusive').checked=true;el('renewal-job-exclusive').listeners.change();}};
}
async function ready(f){f.api.setSource(fp,13);f.override(()=>response(output(idle,plan)));await f.preview();assert.equal(f.el('renewal-job-form').hidden,false);}
{
  const f=fixture();await f.preview();await f.submit();assert.equal(f.requests.length,0);await f.status();assert.equal(f.el('renewal-job-result').hidden,false);assert.equal(f.el('renewal-job-form').hidden,true);
  await ready(f);assert.equal(f.el('renewal-job-start').disabled,true);f.consent();f.el('renewal-job-exclusive').checked=false;await f.submit();assert.equal(f.requests.length,2,'separate exclusive-editing consent required');f.el('renewal-job-exclusive').checked=true;
  f.override((url,options)=>{assert.equal(url,'/api/acme/renewal-job/start');assert.deepEqual(JSON.parse(options.body),{provider:'letsencrypt-staging',fingerprint:fp,expected_generation:13,password:'synthetic-password',confirm:true,exclusive_dns:true,scope:'session-test-renewal'});return response(output(waiting,plan));});await f.submit();
  assert.equal(f.el('renewal-job-stop').disabled,false);assert.equal(f.el('renewal-job-form').hidden,true);assert.equal(f.el('renewal-job-password').value,'');assert.equal(f.el('renewal-job-consent').checked,false);assert.equal(f.el('renewal-job-exclusive').checked,false);assert.match(f.el('renewal-job-state').textContent,/Waiting/);
  f.override((url,options)=>{assert.equal(url,'/api/acme/renewal-job/stop');assert.deepEqual(JSON.parse(options.body),{provider:'letsencrypt-staging',job_id:jid});return response(output({...waiting,state:'paused',reason:'stopped',next_check:''}));});await f.stop();assert.equal(f.el('renewal-job-stop').disabled,true);assert.match(f.el('renewal-job-reason').textContent,/Sent operations may still have taken effect/);
}
for(const reason of ['dns-maintenance','outcome-unconfirmed','poll-limit','storage-changed','scope-changed','access-ended','request-expired','source-ended']){
  const f=fixture();f.override(()=>response(output({...waiting,state:'paused',reason,next_check:'',saved_fingerprint:newfp})));await f.status();assert.equal(f.el('renewal-job-result').hidden,false,reason);assert.match(f.el('renewal-job-saved').textContent,/saved — cleanup still needs confirmation/);assert.doesNotMatch(f.el('renewal-job-state').textContent,/Complete/);
}
{
  const f=fixture();f.override(()=>response(output({...waiting,state:'complete',reason:'complete',phase:'complete',saved_fingerprint:newfp,next_check:''})));await f.status();assert.equal(f.el('renewal-job-result').hidden,false);assert.match(f.el('renewal-job-reason').textContent,/cleanup is confirmed/);assert.equal(f.el('renewal-job-recovery').href,'/certificates');
}
for(const change of [{test_only:false},{scope:'session-timing-only'},{provider:'other'},{schema_version:'other'},{checked_at:stamp(now-120000)},{token:'secret-sentinel'},{job:{...waiting,actions:161}},{job:{...waiting,expires:stamp(now+43201000)}},{job:{...waiting,saved_fingerprint:fp}},{job:{...waiting,state:'complete',reason:'complete',next_check:''}},{job:{...waiting,phase:'replay'}},{job:{...waiting,reason:'unknown'}},{job:{...idle,id:jid}}]){
  const f=fixture();f.override(()=>response({...output(waiting),...change}));await f.status();assert.equal(f.el('renewal-job-result').hidden,true,JSON.stringify(change));assert.doesNotMatch(f.el('renewal-job-message').textContent,/secret-sentinel/);
}
for(const p of [{...plan,fingerprint:newfp},{...plan,generation:14},{...plan,can_start:true,reason:'dns-maintenance'},{...plan,can_start:false},{...plan,private_key:'secret-sentinel'}]){
  const f=fixture();f.api.setSource(fp,13);f.override(()=>response(output(idle,p)));await f.preview();assert.equal(f.el('renewal-job-form').hidden,true);assert.equal(f.el('renewal-job-result').hidden,true);
}
for(const boundary of [f=>{f.document.hidden=true;f.events.visibilitychange();},f=>f.windows.pagehide(),f=>f.windows['rootwell-dns-changed'](),f=>f.windows['rootwell-watch-changed'](),f=>f.el('acme-order-form').listeners.submit(),f=>f.api.setSource(newfp,14),f=>[...f.timers.values()].find(t=>t.ms===25000).f(),f=>f.advance(25000),f=>f.advance(-1)]){
  const f=fixture();await ready(f);f.consent();let release;f.override(()=>new Promise(resolve=>release=resolve));const work=f.submit();while(!release)await new Promise(resolve=>setImmediate(resolve));assert.equal(f.el('renewal-job-password').value,'');boundary(f);release(response(output(waiting,plan)));await work;assert.equal(f.el('renewal-job-result').hidden,true);assert.equal(f.el('renewal-job-form').hidden,true);assert.equal(f.el('renewal-job-consent').checked,false);assert.equal(f.el('renewal-job-exclusive').checked,false);
}
for(const [code,headers] of [[401,undefined],[403,undefined],[409,undefined],[429,undefined],[503,undefined],[200,{'content-type':'text/plain','cache-control':'no-store'}],[200,{'content-type':'application/json','cache-control':'public'}]]){
  const f=fixture();f.override(()=>response({token:'secret-sentinel'},code,headers));await f.status();assert.equal(f.el('renewal-job-result').hidden,true);assert.doesNotMatch(f.el('renewal-job-message').textContent,/secret-sentinel/);
}
{
  const f=fixture();f.override(()=>response({...output(waiting),oversize:'x'.repeat(16385)}));await f.status();assert.equal(f.el('renewal-job-result').hidden,true);
}
console.log('Session renewal UI: separate source/password/two consents, bounded exact contracts, saved-but-unconfirmed cleanup, stop, stale/hidden/late/oversize refusal passed.');
