import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const source=fs.readFileSync("cmd/rootwelld/auth/timing-watch.js","utf8"),html=fs.readFileSync("cmd/rootwelld/auth/acme.html","utf8");
assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|console\.|sendBeacon|WebSocket|XMLHttpRequest|https:\/\//);
assert.match(html,/Allow automatic timing checks for this certificate during this login only/);assert.match(html,/even if the browser is closed/);assert.ok(html.indexOf('/timing-watch.js')<html.indexOf('/renewal-timing.js'));
const now=Math.floor(Date.now()/1000)*1000,stamp=n=>new Date(n).toISOString().replace('.000Z','Z'),fp=Array(32).fill('AB').join(':'),jid='ab'.repeat(16);
const idle={name:'',id:'',fingerprint:'',generation:0,state:'not-running',reason:'not-started',recovery:'none',checked_at:'',next_check:'',expires:'',checks:0,limit:12};
const waiting={name:'mail.example.com',id:jid,fingerprint:fp,generation:15,state:'waiting',reason:'provider-wait',recovery:'none',checked_at:stamp(now),next_check:stamp(now+3600000),expires:stamp(now+43200000),checks:1,limit:12};
const plan={generation:13,fingerprint:fp,name:'mail.example.com',can_start:true,reason:'ready',recovery:'none',next_check:''};
const output=(job=idle,p=null)=>({schema_version:'rootwell.acme.timing-watch.v1',provider:'letsencrypt-staging',checked_at:stamp(now),scope:'session-timing-only',automatic_renewal:false,watch:job,readiness:p});
const response=d=>new Response(JSON.stringify(d),{headers:{'content-type':'application/json','cache-control':'no-store'}});
class Element{constructor(){this.value='';this.checked=false;this.disabled=false;this.hidden=true;this.textContent='';this.href='';this.listeners={};}addEventListener(n,f){this.listeners[n]=f;}}
function startFixture(){
  const nodes={},el=id=>nodes[id]??=new Element(),events={},windows={},timers=new Map(),requests=[],sent=[];let index=0,clock=now,fetcher=()=>response(output());
  class Clock extends Date{static now(){return clock;}}
  const document={hidden:false,getElementById:el,addEventListener(n,f){events[n]=f;}};
  const window={addEventListener(n,f){windows[n]=f;},dispatchEvent(e){sent.push(e.type);windows[e.type]?.();}};
  const context={document,window,Date:Clock,TextDecoder,AbortController,Event,setTimeout(f,ms){const id=++index;timers.set(id,{f,ms});return id;},clearTimeout(id){timers.delete(id);},fetch:async(url,options)=>{requests.push({url,options});assert.match(url,/^\/api\/acme\/timing-watch\/(preview|start|status|stop)$/);assert.equal(options.credentials,'same-origin');assert.equal(options.cache,'no-store');assert.equal(options.redirect,'error');return fetcher(url,options);}};
  vm.runInNewContext(source,context);
  return {api:context.rootwellTimingWatch,el,events,windows,timers,requests,sent,document,advance:n=>{clock+=n;},override:f=>{fetcher=f;},status:()=>el('watch-status').listeners.click(),preview:()=>el('watch-preview').listeners.click(),stop:()=>el('watch-stop').listeners.click(),submit:()=>el('watch-form').listeners.submit({preventDefault(){}}),consent:()=>{el('watch-password').value='synthetic-rootwell-password';el('watch-password').listeners.input();el('watch-consent').checked=true;el('watch-consent').listeners.change();}};
}
{
  const f=startFixture();assert.equal(f.requests.length,0);await f.preview();await f.submit();assert.equal(f.requests.length,0,'no selected source or consent cannot start');
  await f.status();assert.deepEqual(JSON.parse(f.requests[0].options.body),{provider:'letsencrypt-staging'});assert.equal(f.el('watch-result').hidden,false);assert.equal(f.el('watch-form').hidden,true);
  f.api.setSource(fp,13);f.override(()=>response(output(idle,plan)));await f.preview();assert.equal(f.el('watch-form').hidden,false);assert.equal(f.el('watch-start').disabled,true);await f.submit();assert.equal(f.requests.length,2);
  f.el('watch-password').value='synthetic-rootwell-password';await f.submit();assert.equal(f.requests.length,2,'password alone cannot grant session watch');
  f.consent();f.override((url,options)=>{assert.equal(url,'/api/acme/timing-watch/start');const input=JSON.parse(options.body);assert.deepEqual(input,{provider:'letsencrypt-staging',fingerprint:fp,expected_generation:13,password:'synthetic-rootwell-password',confirm:true,scope:'session-timing-only'});return response(output(waiting,plan));});await f.submit();assert.equal(f.el('watch-stop').disabled,false);assert.equal(f.el('watch-form').hidden,true);assert.match(f.el('watch-state').textContent,/mail.example.com — Waiting/);assert.equal(f.el('watch-password').value,'');assert.equal(f.el('watch-consent').checked,false);assert.deepEqual(f.sent,['rootwell-watch-changed','rootwell-timing-changed']);
  f.override((url,options)=>{assert.equal(url,'/api/acme/timing-watch/stop');assert.deepEqual(JSON.parse(options.body),{provider:'letsencrypt-staging',watch_id:jid});return response(output({...waiting,state:'paused',reason:'stopped',next_check:''}));});await f.stop();assert.equal(f.el('watch-stop').disabled,true);assert.match(f.el('watch-reason').textContent,/may still need local recovery/);
}
for(const [reason,recovery,text]of [['timing-interrupted','timing','finish the interrupted check locally'],['dns-unconfirmed','dns','Never repeat a create or deletion'],['dns-maintenance','maintenance','do not reset attempts'],['storage-capacity','capacity','No history or ownership is deleted'],['request-unconfirmed','request','Do not create another request']]){
  const f=startFixture();f.api.setSource(fp,13);f.override(()=>response(output(idle,{...plan,can_start:false,reason,recovery})));await f.preview();assert.equal(f.el('watch-form').hidden,true);assert.equal(f.el('watch-start').disabled,true);assert.match(f.el('watch-reason').textContent,new RegExp(text));assert.equal(f.el('watch-recovery').hidden,false);assert.doesNotMatch(f.el('watch-recovery').href,/^https?:/);
}
{
  const f=startFixture();f.api.setSource(fp,13);f.override(()=>response(output(idle,plan)));await f.preview();f.consent();f.override(()=>response(output({...waiting,state:'paused',reason:'provider-failed',recovery:'timing',next_check:''},plan)));await f.submit();assert.match(f.el('watch-reason').textContent,/provider check failed/);assert.doesNotMatch(f.el('watch-reason').textContent,/Ready for/);assert.equal(f.el('watch-form').hidden,true);
}
for(const change of [{automatic_renewal:true},{scope:'session-renewal'},{password:'secret-sentinel'},{watch:{...waiting,private_key:'secret-sentinel'}},{watch:{...waiting,checks:13}},{watch:{...waiting,reason:'invented'}},{watch:{...waiting,state:'paused'}},{watch:{...waiting,expires:stamp(now+43201000)}},{checked_at:stamp(now-180000)},{readiness:plan}]){
  const f=startFixture();f.override(()=>response({...output(waiting),...change}));await f.status();assert.equal(f.el('watch-result').hidden,true,JSON.stringify(change));assert.equal(f.el('watch-stop').disabled,true);assert.doesNotMatch(f.el('watch-message').textContent,/secret-sentinel/);
}
for(const boundary of [f=>{f.document.hidden=true;f.events.visibilitychange();},f=>f.windows.pagehide(),f=>f.api.invalidate(),f=>f.api.setSource(fp,14),f=>f.windows['rootwell-dns-changed'](),f=>f.el('acme-order-form').listeners.submit(),f=>f.advance(25000),f=>f.advance(-1),f=>[...f.timers.values()].find(t=>t.ms===25000).f()]){
  const f=startFixture();let release;f.override(()=>new Promise(resolve=>{release=resolve;}));const work=f.status();while(!release)await new Promise(resolve=>setImmediate(resolve));await f.status();assert.equal(f.requests.length,1);boundary(f);release(response(output(waiting)));await work;assert.equal(f.el('watch-result').hidden,true);assert.equal(f.el('watch-stop').disabled,true);
}
for(const mode of ['lost','timeout','hidden']){
  const f=startFixture();f.api.setSource(fp,13);f.override(()=>response(output(idle,plan)));await f.preview();f.consent();let release;f.override(()=>new Promise(resolve=>{release=resolve;}));const work=f.submit();while(!release)await new Promise(resolve=>setImmediate(resolve));assert.equal(f.el('watch-password').value,'');assert.equal(f.el('watch-consent').checked,false);
  if(mode==='timeout')[...f.timers.values()].find(t=>t.ms===25000).f();if(mode==='hidden'){f.document.hidden=true;f.events.visibilitychange();}
  release(new Response('secret-sentinel',{status:503}));await work;assert.equal(f.el('watch-form').hidden,true);assert.equal(f.el('watch-stop').disabled,true);assert.match(f.el('watch-message').textContent,/may still be running/);assert.doesNotMatch(f.el('watch-message').textContent,/secret-sentinel/);
  f.document.hidden=false;f.override(()=>response(output(waiting)));await f.status();assert.equal(f.el('watch-stop').disabled,false,'unknown outcome can still be discovered/stopped');
}
for(const mode of ['oversize','headers','utf8']){
  const f=startFixture();f.override(()=>mode==='oversize'?response({...output(),padding:'x'.repeat(16385)}):mode==='utf8'?new Response(new Uint8Array([255]),{headers:{'content-type':'application/json','cache-control':'no-store'}}):new Response('{}',{headers:{'content-type':'text/plain'}}));await f.status();assert.equal(f.el('watch-result').hidden,true);assert.equal(f.el('watch-start').disabled,true);
}
console.log('Timing watch UI: separate scoped consent, local status/preview, stop without secret, fixed recovery guidance, no auto renewal, no hidden calls, strict bounded/stale/hidden/late/error refusal passed.');
