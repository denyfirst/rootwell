(() => {
  "use strict";
  const el = id => document.getElementById("production-account-" + id);
  const form=el("form"),status=el("status"),prepare=el("prepare"),password=el("password"),consent=el("consent"),message=el("message"),identity=el("identity");
  const provider="letsencrypt-production";
  const fields="account_created,can_issue,fingerprint,generation,network_used,prepared_at,provider,registration_state,saved,schema_version,state,terms_accepted";
  const uncertain="Status could not be confirmed. Check the separate saved key before retrying. An existing key is never replaced.";
  let snapshot=null,active=null,epoch=0,stale=null;
  const wipe=()=>{password.value="";consent.checked=false;};
  const enable=()=>{status.disabled=!!active||document.hidden;prepare.disabled=!!active||document.hidden||snapshot?.state!=="not-prepared"||!password.value||!consent.checked;};
  const reset=()=>{++epoch;active?.abort();active=null;clearTimeout(stale);snapshot=null;wipe();form.hidden=true;identity.hidden=true;identity.textContent="";message.textContent=uncertain;enable();};
  const valid=data=>{
    if(!data||typeof data!=="object"||Array.isArray(data)||Object.keys(data).sort().join(",")!==fields||data.schema_version!=="rootwell.acme.account-key.v1"||data.provider!==provider||!Number.isSafeInteger(data.generation)||data.generation<1||data.generation>1000000||data.network_used!==false||data.account_created!==false||data.terms_accepted!==false||data.can_issue!==false||data.registration_state!=="not-registered")throw new Error();
    if(data.state==="not-prepared"&&data.saved===false&&data.fingerprint===""&&data.prepared_at==="")return data;
    if(data.state!=="key-prepared"||data.saved!==true||data.generation<2||typeof data.fingerprint!=="string"||!/^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/.test(data.fingerprint)||typeof data.prepared_at!=="string"||!/^(?:20[2-9]\d|2100)-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(data.prepared_at)||!Number.isFinite(Date.parse(data.prepared_at))||new Date(data.prepared_at).toISOString()!==data.prepared_at.replace("Z",".000Z"))throw new Error();
    return data;
  };
  const run=async writing=>{
    if(active||document.hidden||writing&&(snapshot?.state!=="not-prepared"||!password.value||!consent.checked))return;
    const expected=snapshot?.generation,input={provider};
    if(writing){input.expected_generation=expected;input.password=password.value;input.confirm=true;}
    const current=++epoch,controller=new AbortController(),began=Date.now();active=controller;snapshot=null;clearTimeout(stale);wipe();form.hidden=true;identity.hidden=true;identity.textContent="";enable();
    message.textContent=writing?"Preparing a separate encrypted key locally…":"Reading local key status — no provider connection…";
    const timer=setTimeout(()=>{if(current===epoch)reset();},25000);
    try {
      const request={method:"POST",credentials:"same-origin",cache:"no-store",redirect:"error",signal:controller.signal,headers:{"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify(input)};
      input.password="";const pending=fetch("/api/acme/production-account/"+(writing?"prepare":"status"),request);request.body="";
      const response=await pending;
      if(response.status!==(writing?201:200)||response.headers.get("cache-control")!=="no-store"||response.headers.get("content-type")?.split(";")[0].trim().toLowerCase()!=="application/json"||!response.body)throw new Error();
      const reader=response.body.getReader(),decoder=new TextDecoder("utf-8",{fatal:true});let text="",size=0;
      try{for(;;){const part=await reader.read();if(part.done)break;size+=part.value.byteLength;if(size>4096||current!==epoch||controller.signal.aborted||document.hidden)throw new Error();text+=decoder.decode(part.value,{stream:true});}text+=decoder.decode();}finally{await reader.cancel();reader.releaseLock();}
      const data=valid(JSON.parse(text));
      if(current!==epoch||controller.signal.aborted||document.hidden||Date.now()-began<0||Date.now()-began>=25000||writing&&(!data.saved||data.generation!==expected+1))throw new Error();
      active=null;snapshot=data;form.hidden=data.saved;identity.hidden=!data.saved;identity.textContent=data.saved?"Public key SHA-256: "+data.fingerprint+" · Prepared: "+data.prepared_at:"";
      message.textContent=data.saved?"Separate production account key saved encrypted. Not registered; no provider connection. Make a new complete backup.":"No separate production key saved. You can prepare it below. Your test key stays unchanged.";
      stale=setTimeout(reset,60000);enable();
      if(writing)window.dispatchEvent(new Event("rootwell-production-key-changed"));
    } catch {if(current===epoch)reset();}
    finally {input.password="";clearTimeout(timer);controller.abort();if(current===epoch){active=null;wipe();enable();}}
  };
  status.addEventListener("click",()=>run(false));form.addEventListener("submit",event=>{event.preventDefault();return run(true);});
  password.addEventListener("input",()=>{if(active)reset();enable();});consent.addEventListener("change",()=>{if(active)reset();enable();});
  document.addEventListener("visibilitychange",()=>{if(document.hidden)reset();});window.addEventListener("pagehide",reset);
  el("panel").addEventListener("toggle",()=>{if(!el("panel").open)reset();});
  for(const name of ["rootwell-dns-changed","rootwell-watch-changed","rootwell-timing-changed","rootwell-renewal-job-changed"])window.addEventListener(name,reset);
  enable();
})();
