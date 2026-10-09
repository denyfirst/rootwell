import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const source=fs.readFileSync("cmd/rootwelld/auth/acme-setup.js","utf8"),html=fs.readFileSync("cmd/rootwelld/auth/acme.html","utf8");
assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|console\.|createObjectURL|WebSocket|XMLHttpRequest|sendBeacon/);
assert.match(html,/No external connection/);assert.doesNotMatch(html,/<script[^>]*https?:/);
// ADR 0051 adds a separate fresh-password custody form; syntax setup still
// has no secret picker/request field or account-preparation authority.
const setupForm=html.match(/<form id="acme-form"[\s\S]*?<\/form>/)?.[0];assert.ok(setupForm);
assert.doesNotMatch(setupForm,/<input[^>]*type="password"|acme-account/);
assert.doesNotMatch(setupForm,/<button[^>]*>.*(?:Issue|Register|Renew)|acme-registration/);
assert.doesNotMatch(source,/acme-account-password|\/api\/acme\/account|private_key|terms_agreed/);
assert.match(html,/<div class="layout">/);assert.match(html,/<form id="acme-form" class="csr-form">/);
const directory="https://acme-staging-v02.api.letsencrypt.org/directory";
class Element {constructor(){this.value="";this.textContent="";this.hidden=true;this.disabled=false;this.children=[];this.listeners={};}addEventListener(n,f){this.listeners[n]=f;}replaceChildren(){this.children=[];}appendChild(n){this.children.push(n);}click(){return this.listeners.click?.();}}
function fixture(){const elements={},byId=id=>elements[id]??=new Element(),events={},windows={},timers=new Map(),requests=[];let next=null,id=0;
  byId("acme-provider").value="letsencrypt-staging";byId("acme-challenge").value="dns-01";
  const document={hidden:false,getElementById:byId,createElement(){return new Element();},addEventListener(n,f){events[n]=f;}};
  vm.runInNewContext(source,{document,window:{addEventListener(n,f){windows[n]=f;}},TextDecoder,Uint8Array,AbortController,
    setTimeout(fn,delay){const n=++id;timers.set(n,{fn,delay});return n;},clearTimeout(n){timers.delete(n);},
    fetch:async(url,options)=>{assert.equal(url,"/api/acme/plan");assert.equal(options.method,"POST");assert.equal(options.credentials,"same-origin");assert.equal(options.cache,"no-store");assert.equal(options.headers["X-Rootwell-Request"],"1");const input=JSON.parse(options.body);requests.push(input);if(next){const n=next;next=null;return n();}return new Response(JSON.stringify({schema_version:"rootwell.acme.setup.v1",provider:input.provider,challenge:input.challenge,domains:input.domains,directory,state:"setup-checked",network_enabled:false,saved:false,account_created:false,can_issue:false}),{headers:{"cache-control":"no-store"}});}});
  byId("acme-domains").value="EXAMPLE.com\n*.example.com";byId("acme-domains").listeners.input();
  return {byId,document,events,windows,timers,requests,override(fn){next=fn;},submit(){return byId("acme-form").listeners.submit({preventDefault(){}});}};
}
{const f=fixture();assert.equal(f.requests.length,0);await f.submit();assert.equal(f.requests.length,1);assert.deepEqual(f.requests[0].domains,["example.com","*.example.com"]);assert.equal(f.byId("acme-result").hidden,false);assert.equal(f.byId("acme-names").children[0].textContent,"example.com");assert.match(f.byId("acme-status").textContent,/Nothing saved or sent/);f.byId("acme-challenge").value="http-01";f.byId("acme-challenge").listeners.change();assert.equal(f.byId("acme-result").hidden,true);assert.match(f.byId("acme-help").textContent,/port 80/);}
for(const response of [()=>new Response("secret-sentinel",{status:400}),()=>new Response("secret-sentinel",{status:401}),()=>new Response("x".repeat(16385),{headers:{"cache-control":"no-store"}}),()=>new Response("null",{headers:{"cache-control":"no-store"}}),()=>{throw new Error("secret-sentinel");}]){const f=fixture();f.override(response);await f.submit();assert.equal(f.byId("acme-result").hidden,true);assert.doesNotMatch(f.byId("acme-status").textContent,/secret-sentinel/);}
for(const field of ["can_issue","saved","network_enabled","account_created"]){const f=fixture();f.override(()=>new Response(JSON.stringify({schema_version:"rootwell.acme.setup.v1",provider:"letsencrypt-staging",challenge:"dns-01",domains:["example.com","*.example.com"],directory,state:"setup-checked",network_enabled:false,saved:false,account_created:false,can_issue:false,[field]:true}),{headers:{"cache-control":"no-store"}}));await f.submit();assert.equal(f.byId("acme-result").hidden,true,"server capability claim displayed as validated setup");}
for(const boundary of [f=>{f.byId("acme-domains").value="changed.example.com";f.byId("acme-domains").listeners.input();},f=>{f.document.hidden=true;f.events.visibilitychange();},f=>f.windows.pagehide(),f=>f.byId("acme-clear").click(),f=>[...f.timers.values()][0].fn()]){const f=fixture();let release;f.override(()=>new Promise(resolve=>{release=resolve;}));const work=f.submit();while(!release)await new Promise(resolve=>setImmediate(resolve));boundary(f);release(new Response(JSON.stringify({schema_version:"rootwell.acme.setup.v1",provider:"letsencrypt-staging",challenge:"dns-01",domains:["example.com","*.example.com"],directory,state:"setup-checked",network_enabled:false,saved:false,account_created:false,can_issue:false}),{headers:{"cache-control":"no-store"}}));await work;assert.equal(f.byId("acme-result").hidden,true);assert.equal(f.byId("acme-names").children.length,0);}
for(const value of ["",Array(33).fill("example.com").join("\n"),"x".repeat(8193),"\u212a.example.com","bücher.com","\u00a0example.com"]){const f=fixture();f.byId("acme-domains").value=value;await f.submit();assert.equal(f.requests.length,0);}
console.log("ACME setup UI: local-only explicit check, no execution capability, bounded errors and late/hidden/source/deadline clearing passed.");
