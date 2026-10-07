import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";
const source=fs.readFileSync("web/workbench/certificate-key-match.js","utf8");
assert.doesNotMatch(source,/fetch\(|innerHTML|localStorage|sessionStorage|console\.|XMLHttpRequest|sendBeacon|\.download|clipboard/);
class Element {
  constructor() { this.files=[];this.value="";this.disabled=false;this.hidden=false;this.open=true;this.listeners={};this.children=[];this.textContent=""; }
  addEventListener(e,f){ this.listeners[e]=f; }
  replaceChildren(){this.children=[];} appendChild(e){this.children.push(e);} click(){return this.listeners.click?.();}
}
const fingerprint=Array.from({length:32},()=>"AB").join(":");
function fixture() {
  const elements={}, byId=id=>elements[id]??=new Element(),listeners={},win={},requests=[],buffers=[],timers=new Map();let next=null;
  const document={hidden:false,getElementById:byId,querySelectorAll:()=>[byId("convert-tab")],createElement:()=>new Element(),addEventListener(e,f){listeners[e]=f;}};
  const file=values=>({size:values.length,arrayBuffer:async()=>{const b=Uint8Array.from(values);buffers.push(b);return b.buffer;}});
  const context=vm.createContext({document,window:{addEventListener(e,f){win[e]=f;}},TextEncoder,Uint8Array,AbortController,Set,
    rootwellWorkbenchReady:Promise.resolve({module:{}}),setTimeout(fn,ms){timers.set(fn,ms);return fn;},clearTimeout(fn){timers.delete(fn);},
    rootwellCSRWorker:{async run(module,operation,key,cert,pwd,option,signal){ requests.push({operation,key,cert,pwd,signal});if(next){const f=next;next=null;return f();}return JSON.stringify({schema_version:"rootwell.browser.key-match.v1",ok:true,error:null,records:[{fingerprint,subject:"<not-html>",key_status:"matched"}]});}}
  });
  vm.runInContext(source,context);
  byId("match-certificate").files=[file([1,2,3])];byId("match-key").files=[file([4,5])];byId("match-password").value="fixture-password";
  return {byId,file,requests,buffers,document,listeners,win,timers,override(f){next=f;}};
}
async function ready(){await Promise.resolve();await Promise.resolve();}
{
  const f=fixture();await ready();await f.byId("match-check").click();
  assert.equal(f.requests.length,1);assert.equal(f.requests[0].operation,"certificate-key-match");assert.equal(f.byId("match-password").value,"");
  assert.match(f.byId("match-results").children[0].textContent,/Key matches · <not-html>/);
  for(const b of [...f.buffers,f.requests[0].pwd])assert.ok(b.every(x=>x===0),"owned secret bytes retained");
  f.byId("match-key").listeners.change();assert.equal(f.byId("match-results").children.length,0);
}
for(const response of [()=>"secret-sentinel",()=>JSON.stringify({schema_version:"rootwell.browser.key-match.v1",ok:false,error:"secret-sentinel",records:null}),()=>{throw new Error("secret-sentinel");}]) {
  const f=fixture();await ready();f.override(response);await f.byId("match-check").click();assert.equal(f.byId("match-results").children.length,0);assert.doesNotMatch(f.byId("match-status").textContent,/secret-sentinel|does not match/);
}
{
  const f=fixture();await ready();f.override(()=>JSON.stringify({schema_version:"rootwell.browser.key-match.v1",ok:true,error:null,records:[{fingerprint,subject:"Certificate",key_status:"mismatch"}]}));
  await f.byId("match-check").click();assert.match(f.byId("match-results").children[0].textContent,/does not match/);
}
for(const cancel of [f=>{f.document.hidden=true;f.listeners.visibilitychange();},f=>f.byId("convert-tab").click(),f=>f.win.pagehide(),f=>{f.byId("key-match-tools").open=false;f.byId("key-match-tools").listeners.toggle();},f=>[...f.timers.keys()][0]()]) {
  const f=fixture();await ready();let complete;f.override(()=>new Promise(resolve=>{complete=resolve;}));const pending=f.byId("match-check").click();
  while(!complete) await ready();cancel(f);assert.equal(f.requests[0].signal.aborted,true);
  complete(JSON.stringify({schema_version:"rootwell.browser.key-match.v1",ok:true,error:null,records:[{fingerprint,subject:"late",key_status:"matched"}]}));await pending;
  assert.equal(f.byId("match-results").children.length,0,"late result restored after boundary");
}
{
  const f=fixture();await ready();f.byId("match-key").files=[{size:64*1024+1,arrayBuffer(){throw new Error("must not read");}}];await f.byId("match-check").click();assert.equal(f.requests.length,0);assert.equal(f.buffers.length,0);
}
console.log("Inspect key-match UI: match/mismatch/error distinction, no network/storage/export, source/nav/hidden/deadline clearing passed.");
