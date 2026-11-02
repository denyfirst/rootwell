import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source=fs.readFileSync('cmd/rootwelld/auth/production-account.js','utf8');
const html=fs.readFileSync('cmd/rootwelld/auth/acme.html','utf8');
assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|console\.|sendBeacon|WebSocket|XMLHttpRequest|https:\/\//);
assert.match(html,/Production registration, certificate requests and renewal are not enabled by this step/);
const empty={schema_version:'rootwell.acme.account-key.v1',provider:'letsencrypt-production',generation:2,state:'not-prepared',fingerprint:'',prepared_at:'',saved:false,network_used:false,account_created:false,terms_accepted:false,can_issue:false,registration_state:'not-registered'};
const saved={...empty,generation:3,state:'key-prepared',fingerprint:Array(32).fill('CD').join(':'),prepared_at:'2026-11-02T00:00:00Z',saved:true};
const reply=(value,status=200,headers={})=>new Response(JSON.stringify(value),{status,headers:{'content-type':'application/json','cache-control':'no-store',...headers}});
function fixture(){
  const elements=new Map(),timers=new Map(),events={},windows={},requests=[];let serial=0,override=null;
  const el=name=>{const id='production-account-'+name;if(!elements.has(id))elements.set(id,{value:'',checked:false,disabled:false,hidden:false,open:true,textContent:'',listeners:{},addEventListener(k,f){this.listeners[k]=f;}});return elements.get(id);};
  const document={hidden:false,getElementById:id=>el(id.replace(/^production-account-/,'')),addEventListener(k,f){events[k]=f;}};
  vm.runInNewContext(source,{document,window:{addEventListener(k,f){windows[k]=f;},dispatchEvent(){}},AbortController,TextDecoder,Event,Date,setTimeout(fn,ms){const id=++serial;timers.set(id,{fn,ms});return id;},clearTimeout(id){timers.delete(id);},fetch:async(url,options)=>{
    assert.ok(['/api/acme/production-account/status','/api/acme/production-account/prepare'].includes(url));
    assert.equal(options.method,'POST');assert.equal(options.credentials,'same-origin');assert.equal(options.cache,'no-store');assert.equal(options.redirect,'error');assert.equal(options.headers['X-Rootwell-Request'],'1');
    assert.equal(el('password').value,'');assert.equal(el('consent').checked,false);
    const input=JSON.parse(options.body);requests.push({url,input});
    if(url.endsWith('prepare'))assert.deepEqual(input,{provider:empty.provider,expected_generation:2,password:'test-only password sentinel',confirm:true});else assert.deepEqual(input,{provider:empty.provider});
    if(override){const run=override;override=null;return run();}return reply(url.endsWith('prepare')?saved:empty,url.endsWith('prepare')?201:200);
  }});
  return {el,document,events,windows,timers,requests,setReply(fn){override=fn;},read:()=>el('status').listeners.click(),write:()=>el('form').listeners.submit({preventDefault(){}}),approve(){el('password').value='test-only password sentinel';el('password').listeners.input();el('consent').checked=true;el('consent').listeners.change();}};
}
{
  const f=fixture();assert.equal(f.requests.length,0);f.approve();await f.write();assert.equal(f.requests.length,0);
  await f.read();assert.equal(f.el('form').hidden,false);await f.write();assert.equal(f.requests.length,1);
  f.el('password').value='test-only password sentinel';f.el('password').listeners.input();await f.write();assert.equal(f.requests.length,1,'password alone must not write');
  f.approve();await f.write();assert.equal(f.requests.length,2);assert.match(f.el('message').textContent,/saved encrypted.*Not registered.*complete backup/);assert.equal(f.el('form').hidden,true);
  f.approve();await f.write();assert.equal(f.requests.length,2,'no overwrite');
}
for(const bad of [null,{...saved,provider:'letsencrypt-staging'},{...saved,registration_state:'registered'},{...saved,network_used:true},{...saved,account_created:true},{...saved,terms_accepted:true},{...saved,can_issue:true},{...saved,generation:7},{...saved,private_key:'secret-sentinel'},{...saved,prepared_at:'2026-02-30T00:00:00Z'}]){
  const f=fixture();await f.read();f.approve();f.setReply(()=>reply(bad,201));await f.write();assert.equal(f.el('password').value,'');assert.equal(f.el('consent').checked,false);assert.doesNotMatch(f.el('message').textContent,/saved encrypted|secret-sentinel/);f.approve();await f.write();assert.equal(f.requests.length,2,'failed write needs fresh status');
}
for(const make of [()=>new Response('secret-sentinel',{status:401}),()=>reply(saved,201,{'cache-control':'public'}),()=>new Response('x'.repeat(4097),{headers:{'content-type':'application/json','cache-control':'no-store'}}),()=>{throw Error('secret-sentinel');}]){
  const f=fixture();await f.read();f.approve();f.setReply(make);await f.write();assert.equal(f.el('password').value,'');assert.equal(f.el('consent').checked,false);assert.doesNotMatch(f.el('message').textContent,/secret-sentinel|saved encrypted/);
}
for(const trigger of [f=>{f.document.hidden=true;f.events.visibilitychange();},f=>f.windows.pagehide(),f=>{f.el('panel').open=false;f.el('panel').listeners.toggle();},f=>f.windows['rootwell-renewal-job-changed'](),f=>{for(const timer of f.timers.values())if(timer.ms===60000){timer.fn();break;}}]){
  const f=fixture();await f.read();f.approve();trigger(f);assert.equal(f.el('password').value,'');assert.equal(f.el('consent').checked,false);assert.equal(f.el('form').hidden,true);await f.write();assert.equal(f.requests.length,1);
}
{
  const f=fixture();await f.read();f.approve();let finish;f.setReply(()=>new Promise(resolve=>{finish=resolve;}));const pending=f.write();f.windows.pagehide();finish(reply(saved,201));await pending;assert.equal(f.el('form').hidden,true);assert.doesNotMatch(f.el('message').textContent,/saved encrypted/);
}
console.log('Production local account key UI consent, profile, refusal, bounds, clearing and late-response tests passed.');
