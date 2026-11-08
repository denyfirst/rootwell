"use strict";
(() => {
  // The client receives only a compiled fixed asset and explicitly selected
  // PFX bytes. No storage, downloads, HTTP or plaintext key output.
  function run(module,input,password,signal){
    if(!(module instanceof WebAssembly.Module)||!(input instanceof Uint8Array)||!input.length||input.length>1<<20||!(password instanceof Uint8Array)||!password.length||password.length>128||signal.aborted||typeof Worker!=="function")return Promise.reject(new Error("PFX preparation unavailable"));
    const owned=[input.slice(),password.slice()];
    return new Promise((resolve,reject)=>{
      let worker,timer,sent=false,finished=false;
      const finish=(failed,answer)=>{
        if(finished)return;finished=true;clearTimeout(timer);signal.removeEventListener("abort",abort);worker?.terminate();
        for(const b of owned)if(b.byteLength)b.fill(0);
        if(failed)reject(new Error("PFX preparation failed"));else resolve(answer);
      };
      const abort=()=>finish(true);
      try{
        worker=new Worker("/certificate-pfx-worker.js",{name:"rootwell-library-pfx"});
        signal.addEventListener("abort",abort,{once:true});timer=setTimeout(()=>finish(true),90000);
        worker.onerror=()=>finish(true);
        worker.onmessage=event=>{
          const message=event.data;
          if(finished){for(const key of ["certificate","private_key","key_password"]){const b=message?.answer?.result?.[key];if(b instanceof Uint8Array)b.fill(0);}return;}
          if(!sent&&message?.type==="ready"){
            sent=true;try{worker.postMessage({type:"prepare",input:owned[0].buffer,password:owned[1].buffer},owned.map(b=>b.buffer));}catch{finish(true);}
          }else if(sent&&message?.type==="prepared"){
            const a=message.answer,r=a?.result;
            if(!a||a.schema_version!=="rootwell.browser.pfx-import.v1"||a.ok!==true||a.error!==null||!r||Object.keys(r).sort().join(",")!=="certificate,fingerprint,key_password,private_key"||typeof r.fingerprint!=="string"||r.fingerprint.length!==95||!/^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(r.fingerprint)||
              ![r.certificate,r.private_key,r.key_password].every((b,i)=>b instanceof Uint8Array&&b.length>0&&b.length<=[768<<10,64<<10,128][i])){
              for(const key of ["certificate","private_key","key_password"]){const b=r?.[key];if(b instanceof Uint8Array)b.fill(0);}finish(true);return;
            }
            finish(false,r);
          }else {for(const key of ["certificate","private_key","key_password"]){const b=message?.answer?.result?.[key];if(b instanceof Uint8Array)b.fill(0);}finish(true);}
        };
        worker.postMessage({type:"init",module});if(signal.aborted)finish(true);
      }catch{finish(true);}
    });
  }
  Object.defineProperty(globalThis,"rootwellCertificatePFX",{value:Object.freeze({run})});
})();
