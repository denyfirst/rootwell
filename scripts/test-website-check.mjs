import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = fs.readFileSync("cmd/rootwelld/auth/website-check.js","utf8");
const examples = JSON.parse(fs.readFileSync("cmd/rootwelld/auth/website-examples.json","utf8"));
assert.doesNotMatch(source,/innerHTML|localStorage|sessionStorage|console\.|WebSocket|XMLHttpRequest|sendBeacon/);
class Element {
  constructor(){ this.value="";this.checked=false;this.hidden=false;this.disabled=false;this.dataset={};this.listeners={};this.children=[];this.textContent=""; }
  addEventListener(n,f){this.listeners[n]=f;} append(...children){this.children.push(...children);} replaceChildren(...children){this.children=children;} scrollIntoView(){}
}
const allText = node => node.textContent + " " + node.children.map(allText).join(" ");
function fixture(readOnly=false){
  const nodes={}, byId=id=>nodes[id]??=new Element(), events={}, windows={}, timers=new Map(), requests=[];let next=null,timerId=0;
  byId("website-target").value="website.example.org";if(readOnly)byId("website-form").dataset.readOnly="true";
  const document={hidden:false,getElementById:byId,createElement:()=>new Element(),addEventListener(n,f){events[n]=f;}};
  vm.runInNewContext(source,{document,TextDecoder,AbortController,URL,Date,
    addEventListener(n,f){windows[n]=f;},setTimeout(fn){timers.set(++timerId,fn);return timerId;},clearTimeout(id){timers.delete(id);},
    fetch:async(url,options)=>{requests.push({url,options});assert.equal(options.cache,"no-store");assert.equal(options.credentials,"same-origin");assert.equal(options.redirect,"error");if(next){const fn=next;next=null;return fn();}return new Response(JSON.stringify(url==="/website-examples.json"?examples:examples.examples.valid),{headers:{"Content-Type":"application/json"}});}
  });
  const settle=async()=>{for(let i=0;i<8;i++)await new Promise(resolve=>setImmediate(resolve));};
  return {byId,document,events,windows,timers,requests,settle,override(fn){next=fn;},approve(){byId("website-consent").checked=true;},async submit(){byId("website-form").listeners.submit({preventDefault(){}});await settle();},async example(name){byId("example-"+name).listeners.click();await settle();}};
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
