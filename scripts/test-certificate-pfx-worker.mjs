import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const clientSource=fs.readFileSync('cmd/rootwelld/auth/certificate-pfx.js','utf8'),workerSource=fs.readFileSync('cmd/rootwelld/auth/certificate-pfx-worker.js','utf8');
for(const source of [clientSource,workerSource])assert.doesNotMatch(source,/fetch\s*\(|XMLHttpRequest|WebSocket|localStorage|sessionStorage|createObjectURL|sendBeacon/);
class Module{}
const timers=new Map(),workers=[];let nextTimer=0;
class Worker{
 constructor(path){assert.equal(path,'/certificate-pfx-worker.js');this.messages=[];workers.push(this);}
 postMessage(message,transfer=[]){this.messages.push(structuredClone(message,{transfer}));}
 terminate(){this.terminated=true;}
}
const client=vm.createContext({WebAssembly:{Module},Worker,Uint8Array,AbortController,setTimeout(fn,ms){const id=++nextTimer;timers.set(id,{fn,ms});return id;},clearTimeout(id){timers.delete(id);}});
vm.runInContext(clientSource,client);
const source=Uint8Array.of(1,2,3),password=Uint8Array.of(65,66),fp='AB:'.repeat(31)+'AB';
const result=()=>({schema_version:'rootwell.browser.pfx-import.v1',ok:true,error:null,result:{fingerprint:fp,certificate:Uint8Array.of(1),private_key:Uint8Array.of(2),key_password:Uint8Array.of(3)}});
const run=()=>client.rootwellCertificatePFX.run(new Module(),source,password,new AbortController().signal);
{
 const pending=run(),worker=workers.at(-1);assert.equal(worker.messages.length,1);assert.equal(worker.messages[0].type,'init');assert.deepEqual(Object.keys(worker.messages[0]).sort(),['module','type'],'secrets transferred before readiness');assert.equal([...timers.values()][0].ms,90000);
 worker.onmessage({data:{type:'ready'}});assert.equal(worker.messages[1].type,'prepare');assert.deepEqual([...new Uint8Array(worker.messages[1].input)],[1,2,3]);
 const answer=result();worker.onmessage({data:{type:'prepared',answer}});assert.equal((await pending).fingerprint,fp);assert.equal(worker.terminated,true);assert.equal(timers.size,0);assert.deepEqual([...source],[1,2,3]);assert.deepEqual([...password],[65,66]);
}
{
 const pending=run(),worker=workers.at(-1);timers.values().next().value.fn();await assert.rejects(pending);worker.onmessage({data:{type:'ready'}});assert.equal(worker.messages.length,1,'late readiness transferred a password');const late=result();worker.onmessage({data:{type:'prepared',answer:late}});for(const key of ['certificate','private_key','key_password'])assert.ok(late.result[key].every(b=>b===0));
}
{
 const controller=new AbortController(),pending=client.rootwellCertificatePFX.run(new Module(),source,password,controller.signal),worker=workers.at(-1);worker.onmessage({data:{type:'ready'}});controller.abort();await assert.rejects(pending);assert.equal(worker.terminated,true);
}
for(const corrupt of [a=>{a.result.fingerprint+='\n';},a=>{a.result.extra='not-allowed';},a=>{a.result.private_key=new Uint8Array(65537);},a=>{a.ok=false;}]){
 const pending=run(),worker=workers.at(-1);worker.onmessage({data:{type:'ready'}});const answer=result();corrupt(answer);worker.onmessage({data:{type:'prepared',answer}});await assert.rejects(pending);for(const key of ['certificate','private_key','key_password'])assert.ok(answer.result[key].every(b=>b===0));
}
await assert.rejects(client.rootwellCertificatePFX.run(null,source,password,new AbortController().signal));

async function boot(makeAnswer=result){
 const posted=[];let receivedInput,receivedPassword;
 const worker={WebAssembly:{Module,instantiate:async()=>({})},Uint8Array,ArrayBuffer,importScripts(path){assert.equal(path,'/wasm_exec.js');},postMessage(message,transfer=[]){posted.push(structuredClone(message,{transfer}));},close(){this.closed=true;}};
 worker.self=worker;worker.Go=class{constructor(){this.importObject={};}run(){worker.rootwellPFXImport=(input,password)=>{receivedInput=input;receivedPassword=password;return makeAnswer();};worker.rootwellWasmReady();return new Promise(()=>{});}};
 vm.runInNewContext(workerSource,worker);worker.onmessage({data:{type:'init',module:new Module()}});await new Promise(resolve=>setImmediate(resolve));
 return {worker,posted,inputs(){return [receivedInput,receivedPassword];}};
}
{
 const f=await boot();assert.equal(f.posted[0].type,'ready');const input=Uint8Array.of(8,9),secret=Uint8Array.of(7);f.worker.onmessage({data:{type:'prepare',input:input.buffer,password:secret.buffer}});
 assert.equal(f.posted[1].type,'prepared');assert.equal(f.worker.closed,true);for(const b of f.inputs())assert.ok(b.every(v=>v===0));assert.deepEqual([...f.posted[1].answer.result.private_key],[2]);
 f.worker.onmessage({data:{type:'prepare',input:Uint8Array.of(1).buffer,password:Uint8Array.of(2).buffer}});assert.equal(f.posted.at(-1).type,'failure','worker reused for a second operation');
}
{
 const answer=result();answer.result.fingerprint='bad';const f=await boot(()=>answer);f.worker.onmessage({data:{type:'prepare',input:Uint8Array.of(1).buffer,password:Uint8Array.of(2).buffer}});assert.equal(f.posted.at(-1).type,'failure');for(const key of ['certificate','private_key','key_password'])assert.ok(answer.result[key].every(b=>b===0));
}
console.log('PFX library worker: ready-only transfer, bounded one-shot output, timeout/abort, no network/storage and owned-buffer clearing passed.');
