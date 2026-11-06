import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
import { X509Certificate } from "node:crypto";

const source = fs.readFileSync("cmd/rootwelld/auth/website-check.js","utf8");
const examples = JSON.parse(fs.readFileSync("cmd/rootwelld/auth/website-examples.json","utf8"));
const helperSource=fs.readFileSync("cmd/rootwelld/auth/website-expected.js","utf8");
const colon=hash=>hash.toUpperCase().match(/../g).join(":");
const baseExpected=examples.examples.valid.path.map(c=>({sha256:colon(c.fingerprint),subject:c.subject,is_ca:c.role!=="leaf"}));
const expectedEntries=bytes=>bytes[0]===6?baseExpected.slice(0,1):bytes[0]===2?[{...baseExpected[0],sha256:colon("f".repeat(64))}]:bytes[0]===4?[baseExpected[0],{...baseExpected[0],sha256:colon("f".repeat(64))}]:bytes[0]===5?baseExpected.slice(1):baseExpected;
const engine={explore(bytes){return JSON.stringify(bytes[0]===3?{schema_version:"rootwell.browser.explore.v1",ok:false,result:null,error:{code:"unsupported-public-bundle"}}:{schema_version:"rootwell.browser.explore.v1",ok:true,error:null,result:{verification:"not-performed",trust_anchor:"not-selected",count:expectedEntries(bytes).length,certificates:expectedEntries(bytes)}});},analyze(inputs){const bytes=inputs[0],entries=expectedEntries(bytes);return JSON.stringify({schema_version:"rootwell.browser.chain.v1",ok:true,error:"",result:{verification:"not-performed",trust_anchor:"not-selected",certificates:entries.map((c,i)=>({sha256:c.sha256,self_signed:c.is_ca&&i===entries.length-1,parents:bytes[0]!==4&&i<entries.length-1?[i+1]:[]}))}});}};
assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|console\.|WebSocket|XMLHttpRequest|sendBeacon/);
class Element {
  constructor(){ this.value="";this.files=[];this.checked=false;this.hidden=false;this.disabled=false;this.dataset={};this.listeners={};this.children=[];this.textContent=""; }
  addEventListener(n,f){this.listeners[n]=f;} append(...children){this.children.push(...children);} replaceChildren(...children){this.children=children;} scrollIntoView(){}
}
const allText = node => node.textContent + " " + node.children.map(allText).join(" ");
function fixture(readOnly=false,saved=null,selectedEngine=engine){
  const nodes={}, byId=id=>nodes[id]??=new Element(), events={}, windows={}, timers=new Map(), requests=[];let next=null,timerId=0;
  byId("website-target").value="website.example.org";if(readOnly)byId("website-form").dataset.readOnly="true";
  if(saved!==null)byId("website-saved-source").textContent=typeof saved==="string"?saved:JSON.stringify(saved);
  const document={hidden:false,getElementById:byId,createElement:()=>new Element(),addEventListener(n,f){events[n]=f;}};
  const context=vm.createContext({document,TextEncoder,TextDecoder,Uint8Array,AbortController,URL,Date,atob,btoa,rootwellInventoryEngineReady:Promise.resolve(selectedEngine),
    addEventListener(n,f){windows[n]=f;},setTimeout(fn){timers.set(++timerId,fn);return timerId;},clearTimeout(id){timers.delete(id);},
    fetch:async(url,options)=>{requests.push({url,options});assert.equal(options.cache,"no-store");assert.equal(options.credentials,"same-origin");assert.equal(options.redirect,"error");if(next){const fn=next;next=null;return fn();}return new Response(JSON.stringify(url==="/website-examples.json"?examples:examples.examples.valid),{headers:{"Content-Type":"application/json"}});}
  });
  vm.runInContext(helperSource,context);vm.runInContext(source,context);
  const settle=async()=>{for(let i=0;i<8;i++)await new Promise(resolve=>setImmediate(resolve));};
  return {byId,document,events,windows,timers,requests,settle,override(fn){next=fn;},approve(){if(!byId("website-target").value){byId("website-target").value="website.example.org";byId("website-target").listeners.input();}byId("website-consent").checked=true;},select(marker=1,read){byId("website-compare").checked=true;byId("website-compare").listeners.change();byId("expected-certificate").files=[{size:1,name:"private-name-must-never-be-sent",arrayBuffer:read||async function(){return Uint8Array.of(marker).buffer;}}];byId("expected-certificate").listeners.change();},async submit(){byId("website-form").listeners.submit({preventDefault(){}});await settle();},async example(name){byId("example-"+name).listeners.click();await settle();}};
}
{
  const f=fixture();assert.equal(f.requests.length,0);await f.submit();assert.equal(f.requests.length,0);
  f.approve();await f.submit();assert.equal(f.requests.length,1);assert.equal(f.requests[0].url,"/api/website-check");assert.equal(f.requests[0].options.method,"POST");assert.deepEqual(JSON.parse(f.requests[0].options.body),{target:"website.example.org",confirm:true});
  assert.equal(f.byId("website-result").hidden,false);assert.equal(f.byId("website-consent").checked,false);await f.submit();assert.equal(f.requests.length,1);
}
{
  const f=fixture();f.approve();await f.submit();assert.match(allText(f.byId("website-result")),/Valid from/);
  const rootReport=structuredClone(examples.examples.valid);rootReport.state="failed";rootReport.trusted=false;rootReport.path[2].role="root";rootReport.path[2].sent=true;rootReport.path[2].position=3;
  rootReport.findings=[{code:"trust",level:"failed",title:"Trust not established",detail:"Synthetic root is not in the pool.",action:"Check the intended trust store."}];
  const root=fixture();root.approve();root.override(()=>new Response(JSON.stringify(rootReport),{headers:{"Content-Type":"application/json"}}));await root.submit();assert.equal(root.byId("website-result").hidden,false);assert.match(allText(root.byId("website-result")),/Server-sent root/);assert.match(allText(root.byId("website-result")),/Path not verified/);assert.doesNotMatch(allText(root.byId("website-result")),/Trusted locally/);
  const futureReport=structuredClone(rootReport);futureReport.path[0].in_date=false;futureReport.path[0].not_before="2027-01-01T00:00:00Z";
  const future=fixture();future.approve();future.override(()=>new Response(JSON.stringify(futureReport),{headers:{"Content-Type":"application/json"}}));await future.submit();assert.equal(future.byId("website-result").hidden,false);assert.match(allText(future.byId("website-result")),/Outside validity/);assert.match(allText(future.byId("website-result")),/Valid from/);
}
for(const name of ["valid","missing","wrong"]){const f=fixture(true);await f.example(name);assert.equal(f.requests.length,1);assert.equal(f.requests[0].url,"/website-examples.json");assert.equal(f.requests[0].options.method,"GET");assert.equal(f.requests[0].options.body,undefined);assert.equal(f.byId("website-submit").disabled,true);assert.equal(f.byId("website-result").hidden,false);assert.match(f.byId("website-status").textContent,/Example only/);f.approve();await f.submit();assert.equal(f.requests.length,1);}
for(const make of [
  ()=>new Response("secret-sentinel",{status:502}),
  ()=>new Response("x".repeat(98305),{headers:{"Content-Type":"application/json"}}),
  ()=>new Response("null",{headers:{"Content-Type":"application/json"}}),
  ()=>new Response(JSON.stringify(examples.examples.valid),{headers:{"Content-Type":"text/html"}}),
  ()=>new Response(JSON.stringify({...examples.examples.valid,trusted:false}),{headers:{"Content-Type":"application/json"}}),
  ()=>new Response(JSON.stringify({...examples.examples.valid,hostname:"another.example.org"}),{headers:{"Content-Type":"application/json"}}),
  ()=>new Response(JSON.stringify({...examples.examples.valid,state:"failed"}),{headers:{"Content-Type":"application/json"}}),
  ()=>{const r=structuredClone(examples.examples.valid);r.path[0].in_date=false;return new Response(JSON.stringify(r),{headers:{"Content-Type":"application/json"}});},
  ()=>{const r=structuredClone(examples.examples.valid);delete r.issuer_checks;return new Response(JSON.stringify(r),{headers:{"Content-Type":"application/json"}});},
  ()=>{const r=structuredClone(examples.examples.valid);r.issuer_checks[0].verified=["f".repeat(64)];return new Response(JSON.stringify(r),{headers:{"Content-Type":"application/json"}});},
  ()=>{const r=structuredClone(examples.examples.valid);r.issuer_checks[1].child=r.issuer_checks[0].child;return new Response(JSON.stringify(r),{headers:{"Content-Type":"application/json"}});},
  ()=>{const r=structuredClone(examples.examples.valid);r.issuer_checks[0].rejected=[...r.issuer_checks[0].verified];return new Response(JSON.stringify(r),{headers:{"Content-Type":"application/json"}});},
  ()=>{const r=structuredClone(examples.examples.valid);r.presented[0].fingerprint+="\n";return new Response(JSON.stringify(r),{headers:{"Content-Type":"application/json"}});},
  ()=>{throw Error("secret-sentinel");}
]){const f=fixture();f.approve();f.override(make);await f.submit();assert.equal(f.byId("website-result").hidden,true);assert.match(f.byId("website-status").textContent,/No result/);assert.doesNotMatch(f.byId("website-status").textContent,/secret-sentinel/);}
for(const boundary of [
  f=>{f.document.hidden=true;f.events.visibilitychange();},
  f=>f.windows.pagehide(),
  f=>f.byId("website-target").listeners.input(),
  f=>f.byId("website-consent").listeners.change(),
  f=>[...f.timers.values()][0]()
]){
  const f=fixture();f.approve();let release;f.override(()=>new Promise(resolve=>{release=resolve;}));await f.submit();assert.ok(release);f.approve();await f.submit();assert.equal(f.requests.length,1);boundary(f);release(new Response(JSON.stringify(examples.examples.valid),{headers:{"Content-Type":"application/json"}}));await f.settle();assert.equal(f.byId("website-result").hidden,true);
}
console.log("Website check UI: bounded/strict responses, single-use consent, synthetic-only examples, no raw errors and cancellation/late results passed.");
{
  const f=fixture();f.select();f.approve();f.override(()=>new Response(JSON.stringify(examples.examples.wrong),{headers:{"Content-Type":"application/json"}}));await f.submit();assert.equal(f.requests.length,1);assert.deepEqual(JSON.parse(f.requests[0].options.body),{target:"website.example.org",confirm:true});assert.doesNotMatch(f.requests[0].options.body,/private-name|fingerprint|BEGIN|certificate/);
  const output=allText(f.byId("website-result"));assert.match(output,/Your certificate matches, but the website check fails/);assert.match(output,/Intermediate certificate/);assert.match(output,/sent as its issuer cannot verify/);assert.match(output,/This issuer cannot verify the certificate above/);assert.match(output,/Server-sent certificate #2/);assert.match(output,/Root not sent/);assert.match(output,/needs a fix/);
  const mismatch=fixture();mismatch.select(2);mismatch.approve();await mismatch.submit();assert.match(allText(mismatch.byId("website-result")),/serves a different certificate/);assert.match(allText(mismatch.byId("website-result")),/chain checks out/);
}
for(const marker of [3,5]){const f=fixture();f.select(marker);f.approve();await f.submit();assert.equal(f.requests.length,0);assert.match(f.byId("website-status").textContent,/No website was contacted/);}
{
  const f=fixture();f.select(4);f.approve();await f.submit();assert.equal(f.requests.length,0);assert.equal(f.byId("expected-choice-box").hidden,false);assert.match(f.byId("website-status").textContent,/Several site certificates/);f.byId("expected-choice").value=baseExpected[0].sha256.replaceAll(":","").toLowerCase();f.byId("expected-choice").listeners.change();f.approve();await f.submit();assert.equal(f.requests.length,1);assert.match(allText(f.byId("website-result")),/serves your certificate/);
}
for(const boundary of [f=>f.windows.pagehide(),f=>{f.document.hidden=true;f.events.visibilitychange();},f=>f.byId("expected-certificate").listeners.change(),f=>[...f.timers.values()][0]()]){
  const f=fixture();let release;f.select(1,()=>new Promise(resolve=>{release=resolve;}));f.approve();await f.submit();assert.ok(release);assert.equal(f.requests.length,0);boundary(f);release(Uint8Array.of(1).buffer);await f.settle();assert.equal(f.requests.length,0);assert.equal(f.byId("website-result").hidden,true);
}
{const f=fixture(true);await f.example("compare");assert.equal(f.requests.length,1);assert.equal(f.requests[0].url,"/website-examples.json");assert.match(allText(f.byId("website-result")),/Your certificate matches, but the website check fails/);assert.match(allText(f.byId("website-result")),/Server-sent certificate #2/);}
console.log("Expected certificate UI: local-only file processing, exact per-node mismatch, wrong/missing CA localization, ambiguous selection, unchanged request and late-read refusal passed.");

const savedSelection={schema_version:'rootwell.website-saved.v1',fingerprint:baseExpected[0].sha256,generation:2,der:Buffer.from([6]).toString('base64')};
{
  const f=fixture(false,savedSelection);assert.equal(f.requests.length,0);assert.equal(f.byId('website-saved-source').textContent,'');assert.equal(f.byId('website-target').value,'');assert.equal(f.byId('website-consent').checked,false);assert.equal(f.byId('expected-saved').hidden,false);assert.equal(f.byId('expected-file-fields').hidden,true);assert.equal(f.byId('website-compare').checked,true);
  await f.submit();assert.equal(f.requests.length,0);f.approve();await f.submit();assert.equal(f.requests.length,1);assert.deepEqual(JSON.parse(f.requests[0].options.body),{target:'website.example.org',confirm:true});assert.doesNotMatch(f.requests[0].options.body,/fingerprint|generation|der|certificate/);assert.match(allText(f.byId('website-result')),/serves your certificate/);
  f.byId('expected-change').listeners.click();assert.equal(f.byId('expected-saved').hidden,true);assert.equal(f.byId('expected-file-fields').hidden,false);assert.equal(f.byId('website-result').hidden,true);await f.submit();assert.equal(f.requests.length,1,'changing source needs fresh consent');
}
for(const saved of ['{broken',{...savedSelection,extra:'secret-sentinel'},{...savedSelection,generation:0},{...savedSelection,generation:9007199254740992},{...savedSelection,fingerprint:savedSelection.fingerprint+'\n'},{...savedSelection,fingerprint:colon('f'.repeat(64))},{...savedSelection,der:'Bg==='},...[1,3,4,5].map(b=>({...savedSelection,der:Buffer.from([b]).toString('base64')}))]){
  const f=fixture(false,saved);f.approve();await f.submit();assert.equal(f.requests.length,0);assert.equal(f.byId('website-result').hidden,true);assert.doesNotMatch(f.byId('website-status').textContent,/secret-sentinel/);
}
for(const boundary of [f=>f.windows.pagehide(),f=>{f.document.hidden=true;f.events.visibilitychange();},f=>f.byId('expected-change').listeners.click(),f=>[...f.timers.values()][0]()]){
  let release;const pending=new Promise(resolve=>{release=resolve;});const f=fixture(false,savedSelection,pending);f.approve();await f.submit();assert.equal(f.requests.length,0);boundary(f);release(engine);await f.settle();assert.equal(f.requests.length,0);assert.equal(f.byId('website-result').hidden,true);
}
const [wasmPath,runtimePath]=process.argv.slice(2);
if(wasmPath&&runtimePath){
  vm.runInThisContext(fs.readFileSync(runtimePath,'utf8'));let ready;const loaded=new Promise(resolve=>{ready=resolve;});globalThis.rootwellWasmReady=ready;
  const go=new globalThis.Go(),wasm=await WebAssembly.instantiate(fs.readFileSync(wasmPath),go.importObject);void go.run(wasm.instance);await loaded;
  const realEngine={explore:globalThis.rootwellExplore,analyze:globalThis.rootwellAnalyze};
  const cert=new X509Certificate(examples.expected_certificate_pem),payload={...savedSelection,fingerprint:cert.fingerprint256,der:cert.raw.toString('base64')};
  const f=fixture(false,payload,realEngine);assert.equal(f.requests.length,0);f.approve();await f.submit();assert.equal(f.requests.length,1);assert.match(allText(f.byId('website-result')),/serves your certificate/);
  const other=new X509Certificate(examples.different_certificate_pem),different=fixture(false,{...payload,fingerprint:other.fingerprint256,der:other.raw.toString('base64')},realEngine);different.approve();await different.submit();assert.equal(different.requests.length,1);assert.match(allText(different.byId('website-result')),/serves a different certificate/);
  for(const bad of [{...payload,fingerprint:colon('f'.repeat(64))},{...payload,der:Buffer.from('private-sentinel').toString('base64')}]){const f=fixture(false,bad,realEngine);f.approve();await f.submit();assert.equal(f.requests.length,0);}
  console.log('Saved certificate handoff through actual Go WASM and website UI: exact identity, mismatch, malformed/secret refusal and no automatic network passed.');process.exit(0);
}
console.log('Saved website UI: inert one-certificate selection, separate consent, unchanged target-only request, source change and late/hidden/timeout refusal passed.');
