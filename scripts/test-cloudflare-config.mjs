import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const source=fs.readFileSync("cmd/rootwelld/auth/cloudflare-config.js","utf8"), html=fs.readFileSync("cmd/rootwelld/auth/acme.html","utf8");
assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|console\.|WebSocket|XMLHttpRequest|sendBeacon|https:\/\//);
assert.match(html,/does not contact Cloudflare/);assert.match(html,/Access-only backups do not include the token/);assert.match(html,/not your Global API Key/);
const empty={schema_version:"rootwell.dns.config.v1",provider:"cloudflare",generation:1,state:"not-configured",zone_name:"",saved_at:"",can_change:true,network_used:false,token_verified:false,dns_changed:false};
const saved={...empty,generation:2,state:"saved",zone_name:"example.com",saved_at:"2026-10-14T00:00:00Z"};
const sentinel="synthetic-only-credential-not-a-real-token-1234567890";
const reply=(data,status=200,headers={"cache-control":"no-store","content-type":"application/json"})=>new Response(JSON.stringify(data),{status,headers});
class Element {constructor(){this.value="";this.checked=false;this.disabled=false;this.hidden=false;this.textContent="";this.listeners={};}addEventListener(n,f){this.listeners[n]=f;}}
function fixture(){
  const elements={},el=id=>elements[id]??=new Element(),events={},windows={},timers=new Map(),requests=[];
  let next=null,index=0,clock=Date.now();class Clock extends Date{static now(){return clock;}}
  const document={hidden:false,getElementById:el,addEventListener(n,f){events[n]=f;}};
  vm.runInNewContext(source,{document,window:{addEventListener(n,f){windows[n]=f;}},TextDecoder,Uint8Array,AbortController,Date:Clock,
    setTimeout(fn){const id=++index;timers.set(id,fn);return id;},clearTimeout(id){timers.delete(id);},
    fetch:async(url,options)=>{
      assert.ok(["/api/dns/cloudflare/status","/api/dns/cloudflare/save","/api/dns/cloudflare/remove"].includes(url));
      assert.equal(options.method,"POST");assert.equal(options.credentials,"same-origin");assert.equal(options.cache,"no-store");assert.equal(options.redirect,"error");assert.equal(options.headers["X-Rootwell-Request"],"1");
      const input=JSON.parse(options.body);requests.push({url,input});
      if(url.endsWith("status"))assert.deepEqual(input,{provider:"cloudflare"});
      else {
        assert.equal(input.password,"test-only Rootwell password");assert.equal(input.confirm,true);assert.ok(input.expected_generation>=1);
        if(url.endsWith("save")){assert.equal(input.zone_id,"0123456789abcdef0123456789abcdef");assert.equal(input.zone_name,"example.com");assert.equal(input.token,sentinel);assert.equal(Object.keys(input).length,7);}
        else assert.equal(Object.keys(input).length,4);
      }
      if(next){const f=next;next=null;return f();}
      return reply(url.endsWith("status")?empty:url.endsWith("remove")?{...empty,generation:3}:saved);
    }});
  return {el,events,windows,document,timers,requests,override:f=>next=f,advance:ms=>clock+=ms,
    refresh:()=>el("dns-config-refresh").listeners.click(),submit:()=>el("dns-config-form").listeners.submit({preventDefault(){}}),
    approve(){for(const[id,value]of[["dns-config-zone","example.com"],["dns-config-zone-id","0123456789abcdef0123456789abcdef"],["dns-config-token",sentinel],["dns-config-password","test-only Rootwell password"]]){el(id).value=value;el(id).listeners.input();}el("dns-config-consent").checked=true;el("dns-config-consent").listeners.change();}};
}
{
  const f=fixture();assert.equal(f.requests.length,0);f.approve();await f.submit();assert.equal(f.requests.length,0,"no displayed generation, no save");
  await f.refresh();assert.equal(f.el("dns-config-form").hidden,false);await f.submit();assert.equal(f.requests.length,1,"password/consent missing");
  f.approve();assert.equal(f.el("dns-config-submit").disabled,false);await f.submit();assert.equal(f.requests.length,2);
  assert.match(f.el("dns-config-status").textContent,/saved encrypted for example.com.*Not yet checked/);assert.equal(f.el("dns-config-token").value,"");assert.equal(f.el("dns-config-password").value,"");
  assert.equal(f.el("dns-config-submit").textContent,"Replace encrypted settings");
  f.el("dns-config-action").value="remove";f.el("dns-config-action").listeners.change();assert.equal(f.el("dns-config-fields").hidden,true);assert.match(f.el("dns-config-consent-label").textContent,/Remove this token/);
  f.el("dns-config-password").value="test-only Rootwell password";f.el("dns-config-password").listeners.input();f.el("dns-config-consent").checked=true;f.el("dns-config-consent").listeners.change();await f.submit();
  assert.match(f.el("dns-config-status").textContent,/No Cloudflare token saved/);assert.equal(f.requests.at(-1).url,"/api/dns/cloudflare/remove");
}
{
  const f=fixture();f.override(()=>reply({...saved,can_change:false}));await f.refresh();assert.equal(f.el("dns-config-form").hidden,true);f.approve();await f.submit();assert.equal(f.requests.length,1,"active request cannot change token");
}
for(const response of [()=>new Response("secret-sentinel",{status:401}),()=>new Response("secret-sentinel",{status:403}),()=>new Response("secret-sentinel",{status:409}),()=>new Response("secret-sentinel",{status:429}),()=>new Response("secret-sentinel",{status:503}),()=>reply(saved,201),()=>reply({...saved,generation:9}),()=>reply({...saved,token:"secret-sentinel"}),()=>reply(null),()=>{throw new Error("secret-sentinel");},()=>new Response("x".repeat(4097),{headers:{"cache-control":"no-store","content-type":"application/json"}}),()=>reply(saved,200,{"content-type":"application/json"}),()=>reply(saved,200,{"cache-control":"no-store","content-type":"application/jsonp"})]){
  const f=fixture();await f.refresh();f.approve();f.override(response);await f.submit();assert.doesNotMatch(f.el("dns-config-status").textContent,/saved encrypted|secret-sentinel/);assert.equal(f.el("dns-config-token").value,"");assert.equal(f.el("dns-config-password").value,"");assert.equal(f.el("dns-config-consent").checked,false);
  f.approve();await f.submit();assert.equal(f.requests.length,2,"uncertain mutation needs status reread");
}
for(const changes of [{schema_version:"bad"},{provider:"other"},{generation:0},{state:"verified"},{can_change:1},{network_used:true},{token_verified:true},{dns_changed:true},{zone_name:"*.example.com"},{zone_name:"Example.com"},{saved_at:"2026-02-30T00:00:00Z"},{saved_at:"2101-01-01T00:00:00Z"},{zone_id:"secret-sentinel"}]){
  const f=fixture();f.override(()=>reply({...saved,...changes}));await f.refresh();assert.doesNotMatch(f.el("dns-config-status").textContent,/saved encrypted|secret-sentinel/);assert.equal(f.el("dns-config-form").hidden,true);
}
for(const boundary of [f=>{f.document.hidden=true;f.events.visibilitychange();},f=>f.windows.pagehide(),f=>f.el("acme-clear").listeners.click(),f=>f.el("acme-provider").listeners.change(),f=>f.el("dns-config-token").listeners.input(),f=>f.el("dns-config-consent").listeners.change(),f=>f.el("dns-config-action").listeners.change(),f=>[...f.timers.values()][0](),f=>f.advance(15000),f=>f.advance(-1)]){
  const f=fixture();await f.refresh();f.approve();let release;f.override(()=>new Promise(resolve=>release=resolve));const work=f.submit();while(!release)await new Promise(resolve=>setImmediate(resolve));await f.submit();await f.refresh();assert.equal(f.requests.length,2,"one in-flight operation");boundary(f);release(reply(saved));await work;
  assert.doesNotMatch(f.el("dns-config-status").textContent,/saved encrypted/);assert.equal(f.el("dns-config-token").value,"");assert.equal(f.el("dns-config-password").value,"");assert.equal(f.el("dns-config-submit").disabled,true);
}
for(const value of ["a".repeat(39),"a".repeat(257),sentinel+"\r\n",sentinel+" "]){const f=fixture();await f.refresh();f.approve();f.el("dns-config-token").value=value;f.el("dns-config-token").listeners.input();await f.submit();assert.equal(f.requests.length,1);}
console.log("Cloudflare settings UI: explicit local-only custody, fresh password/consent/generation, removal, no token storage/output and malformed/hidden/late/clock refusal passed.");
