"use strict";
importScripts("/wasm_exec.js");
let initialized=false,ready=false,used=false;
const refuse=()=>{self.postMessage({type:"failure"});self.close();};
self.rootwellWasmReady=()=>{
  if(typeof self.rootwellPFXImport!=="function"){refuse();return;}
  ready=true;self.postMessage({type:"ready"});
};
self.onmessage=event=>{
  const request=event.data;
  if(!initialized){
    initialized=true;
    if(!request||request.type!=="init"||!(request.module instanceof WebAssembly.Module)){refuse();return;}
    try{const go=new Go();WebAssembly.instantiate(request.module,go.importObject).then(instance=>go.run(instance)).then(refuse,refuse);}catch{refuse();}
    return;
  }
  if(!ready||used||!request||request.type!=="prepare"){refuse();return;}
  used=true;let input,password,outputs=[];
  try{
    if(!(request.input instanceof ArrayBuffer)||!(request.password instanceof ArrayBuffer)||request.input.byteLength<1||request.input.byteLength>1<<20||request.password.byteLength<1||request.password.byteLength>128)throw new Error();
    input=new Uint8Array(request.input);password=new Uint8Array(request.password);
    const answer=self.rootwellPFXImport(input,password),r=answer?.result;
    outputs=[r?.certificate,r?.private_key,r?.key_password];
    if(!answer||answer.schema_version!=="rootwell.browser.pfx-import.v1"||answer.ok!==true||answer.error!==null||!r||
      Object.keys(r).sort().join(",")!=="certificate,fingerprint,key_password,private_key"||
      typeof r.fingerprint!=="string"||r.fingerprint.length!==95||!/^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(r.fingerprint))throw new Error();
    if(!outputs.every((b,i)=>b instanceof Uint8Array&&b.length>0&&b.length<=[768<<10,64<<10,128][i]))throw new Error();
    self.postMessage({type:"prepared",answer},outputs.map(b=>b.buffer));
  }catch{refuse();}
  finally{for(const [b,max] of [[request.input,1<<20],[request.password,128]])if(b instanceof ArrayBuffer&&b.byteLength<=max)new Uint8Array(b).fill(0);for(const b of outputs)if(b instanceof Uint8Array&&b.byteLength)b.fill(0);self.close();}
};
