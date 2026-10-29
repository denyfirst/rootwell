(() => {
  "use strict";
  const el=id=>document.getElementById(id), status=el("watch-status"), preview=el("watch-preview"), stop=el("watch-stop"), form=el("watch-form"), password=el("watch-password"), consent=el("watch-consent"), start=el("watch-start"), message=el("watch-message"), result=el("watch-result"), recovery=el("watch-recovery");
  const fp=v=>typeof v==="string"&&/^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/.test(v), id=v=>typeof v==="string"&&/^[0-9a-f]{32}$/.test(v);
  const keys=(v,k)=>v&&typeof v==="object"&&!Array.isArray(v)&&Object.keys(v).sort().join(",")===k.split(",").sort().join(",");
  const date=v=>typeof v==="string"&&/^(?:20\d\d|2100)-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{0,8}[1-9])?Z$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).getUTCFullYear()>=2020&&new Date(v.replace(/\.\d+Z$/,"Z")).toISOString()===v.replace(/\.\d+Z$/,"Z").replace("Z",".000Z");
  const name=v=>typeof v==="string"&&v.length>0&&v.length<=255&&!/[\u0000-\u001f\u007f]/.test(v);
  const pretty=v=>new Intl.DateTimeFormat("en-GB",{day:"numeric",month:"short",year:"numeric",hour:"2-digit",minute:"2-digit",timeZone:"UTC"}).format(new Date(v))+" UTC";
  const reasons={
    "not-started":["Nothing is running. Select a certificate above, then check before enabling.","none"],
    ready:["Ready for separately approved automatic timing checks. No certificate will be renewed.","none"],
    checking:["Checking the provider's recommended time. No DNS or certificate request is made.","none"],
    busy:["Another operation is using Rootwell. The watch will wait; no provider request was sent by this tick.","none"],
    "provider-wait":["Waiting for the saved next-check time. Longer provider waits are always respected.","none"],
    stopped:["Timing checks stopped. A sent check may still need local recovery; refresh renewal readiness.","none"],
    "access-ended":["This watch's login ended or changed. It cannot resume under another login.","none"],
    "server-stopped":["The server stopped. A new login and separate permission are needed.","none"],
    "source-ended":["This certificate expired or a newer certificate is saved. Review Certificates.","certificates"],
    "timing-interrupted":["Read the saved renewal time above, then finish the interrupted check locally. The wait and retry count stay saved.","timing"],
    "provider-maintenance":["Provider access needs reviewed maintenance. Do not erase data or restore an old backup to retry.","maintenance"],
    "dns-maintenance":["DNS recovery is blocked or exhausted. Inspect the provider and arrange reviewed maintenance; do not reset attempts.","maintenance"],
    "dns-unconfirmed":["A DNS operation is unconfirmed. Use its read-only Check result or Recover check. Never repeat a create or deletion.","dns"],
    "dns-cleanup":["An owned DNS record still needs cleanup using the existing helper and its separate confirmation.","dns"],
    "request-unconfirmed":["Read the same saved certificate request. Do not create another request to bypass an uncertain result.","request"],
    "request-active":["Finish or reconcile the existing certificate request before enabling a watch.","request"],
    "account-unavailable":["Check the saved account and registration. A timing watch cannot create or replace an account.","request"],
    "storage-capacity":["Storage is at its safe limit. Make a complete backup and review maintenance. No history or ownership is deleted automatically.","capacity"],
    "storage-unavailable":["Storage cannot be safely read. Keep a complete backup and review maintenance.","maintenance"],
    "storage-changed":["Saved data changed or cannot be read. Refresh renewal readiness; the watch will not adopt a new generation automatically.","readiness"],
    "clock-unavailable":["The clock cannot be safely evaluated. Review server time before enabling another watch.","maintenance"],
    "outcome-unconfirmed":["A check's outcome is unconfirmed. Refresh renewal readiness and read its saved time. Nothing will be retried automatically.","readiness"],
    "provider-failed":["The provider check failed. Review saved timing and its wait before granting new permission.","timing"],
    "check-limit":["The watch reached its 12-check limit. Review saved timing before granting another watch.","timing"]
  };
  const links={certificates:["/certificates","Review Certificates"],timing:["#renewal-readiness","Review saved timing above"],maintenance:["#renewal-readiness","Review readiness and maintenance"],dns:["#cloudflare-dns","Review DNS result and recovery"],request:["#certificate-request","Review the saved request"],capacity:["#renewal-readiness","Review storage headroom above"],readiness:["#renewal-readiness","Refresh renewal readiness above"]};
  const uncertain="Outcome not confirmed. Timing checks may still be running. Read watch status before another action; do not enable another watch blindly.";
  let source=null,plan=null,job=null,active=null,epoch=0,stale=null;
  const wipe=()=>{password.value="";consent.checked=false;};
  const running=()=>job&&["waiting","running"].includes(job.state);
  const enable=()=>{status.disabled=!!active||document.hidden;preview.disabled=!!active||!source||document.hidden;stop.disabled=!!active||!running()||document.hidden;start.disabled=!!active||!source||!plan?.can_start||running()||!password.value||!consent.checked||document.hidden;};
  const reset=()=>{++epoch;active?.abort();active=null;clearTimeout(stale);plan=null;job=null;wipe();form.hidden=true;result.hidden=true;recovery.hidden=true;message.textContent=uncertain;enable();};
  const setSource=(fingerprint,generation)=>{reset();source=fp(fingerprint)&&Number.isSafeInteger(generation)&&generation>=1&&generation<=1000000?{fingerprint,generation}:null;enable();};
  const invalidate=()=>{setSource("",0);};
  const validate=(d,mode,input)=>{
    if(!keys(d,"schema_version,provider,checked_at,scope,automatic_renewal,watch,readiness")||d.schema_version!=="rootwell.acme.timing-watch.v1"||d.provider!=="letsencrypt-staging"||d.scope!=="session-timing-only"||d.automatic_renewal!==false||!date(d.checked_at))throw new Error();
    const w=d.watch;
    if(!keys(w,"id,fingerprint,name,generation,state,reason,recovery,checked_at,next_check,expires,checks,limit")||!["not-running","waiting","running","paused"].includes(w.state)||!Object.hasOwn(reasons,w.reason)||w.recovery!==reasons[w.reason][1]||w.limit!==12||!Number.isSafeInteger(w.checks)||w.checks<0||w.checks>12)throw new Error();
    if(w.state==="not-running"){if(w.reason!=="not-started"||w.checks!==0||w.generation!==0||[w.id,w.fingerprint,w.name,w.checked_at,w.next_check,w.expires].some(v=>v!==""))throw new Error();}
    else if(!id(w.id)||!fp(w.fingerprint)||!name(w.name)||!Number.isSafeInteger(w.generation)||w.generation<1||w.generation>1000000||!date(w.checked_at)||!date(w.expires)||Date.parse(w.checked_at)>Date.parse(d.checked_at)+1000||Date.parse(w.expires)-Date.parse(d.checked_at)>43200000||w.state!=="paused"&&Date.parse(w.expires)<=Date.parse(d.checked_at)||w.next_check!==""&&!date(w.next_check)||w.state!=="waiting"&&w.next_check!=="")throw new Error();
    const p=d.readiness;
    if(["preview","start"].includes(mode)){if(!keys(p,"generation,fingerprint,name,can_start,reason,recovery,next_check")||p.generation!==input.expected_generation||p.fingerprint!==input.fingerprint||!name(p.name)||typeof p.can_start!=="boolean"||!Object.hasOwn(reasons,p.reason)||p.recovery!==reasons[p.reason][1]||p.can_start!==["ready","provider-wait"].includes(p.reason)||p.next_check!==""&&!date(p.next_check))throw new Error();}
    else if(p!==null)throw new Error();
    if(mode==="start"&&(w.fingerprint!==input.fingerprint||w.generation<input.expected_generation||w.generation>input.expected_generation+2))throw new Error();
    if(mode==="stop"&&(w.id!==input.watch_id||w.state!=="paused"||w.reason!=="stopped"))throw new Error();
    return d;
  };
  const render=(d,mode)=>{
    job=d.watch;plan=d.readiness;
    const reason=mode==="preview"&&plan&&!running()?plan.reason:job.reason,step=reasons[reason][1],title={"not-running":"Not running",waiting:"Waiting",running:"Checking",paused:"Paused"}[job.state];
    el("watch-state").textContent=(job.name||plan?.name||"Timing checks")+" — "+title;
    el("watch-next").textContent=job.next_check?"Next check: "+pretty(job.next_check):!job.id&&plan?.next_check?"Saved next check: "+pretty(plan.next_check):"No provider request is queued.";
    el("watch-reason").textContent=reasons[reason][0]+(job.expires?" This watch ends no later than "+pretty(job.expires)+".":"");
    recovery.hidden=step==="none";if(step!=="none"){recovery.href=links[step][0];recovery.textContent=links[step][1];}
    form.hidden=!source||!plan?.can_start||running();result.hidden=false;message.textContent="Timing watch status checked. This watch checks timing only.";clearTimeout(stale);stale=setTimeout(reset,60000);enable();
  };
  const changed=()=>{window.dispatchEvent(new Event("rootwell-watch-changed"));window.dispatchEvent(new Event("rootwell-timing-changed"));};
  const run=async mode=>{
    if(active||document.hidden||mode==="preview"&&!source||mode==="start"&&(!source||!plan?.can_start||running()||!password.value||!consent.checked)||mode==="stop"&&!running())return;
    const input={provider:"letsencrypt-staging"};if(["preview","start"].includes(mode)){input.fingerprint=source.fingerprint;input.expected_generation=source.generation;}if(mode==="start"){input.password=password.value;input.confirm=true;input.scope="session-timing-only";}if(mode==="stop")input.watch_id=job.id;
    const current=++epoch,controller=new AbortController(),began=Date.now();active=controller;plan=null;wipe();form.hidden=true;result.hidden=true;enable();message.textContent=mode==="start"?"Enabling only approved timing checks…":mode==="stop"?"Stopping timing checks…":"Reading local watch status — no provider connection…";
    const timeout=setTimeout(()=>{if(current===epoch)reset();},25000);
    try{
      const pending=fetch("/api/acme/timing-watch/"+mode,{method:"POST",credentials:"same-origin",cache:"no-store",redirect:"error",signal:controller.signal,headers:{"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify(input)});input.password="";
      const response=await pending;if(response.status!==200||response.headers.get("cache-control")!=="no-store"||response.headers.get("content-type")?.split(";")[0].trim().toLowerCase()!=="application/json"||!response.body)throw new Error();
      const reader=response.body.getReader(),decoder=new TextDecoder("utf-8",{fatal:true});let text="",size=0;try{for(;;){const part=await reader.read();if(part.done)break;size+=part.value.byteLength;if(size>16384||current!==epoch||controller.signal.aborted||document.hidden)throw new Error();text+=decoder.decode(part.value,{stream:true});}text+=decoder.decode();}finally{await reader.cancel();reader.releaseLock();}
      const d=validate(JSON.parse(text),mode,input);if(current!==epoch||controller.signal.aborted||document.hidden||Date.now()-began<0||Date.now()-began>=25000||Math.abs(Date.now()-Date.parse(d.checked_at))>=120000)throw new Error();
      active=null;if(mode==="start"||mode==="stop"){source=null;changed();}render(d,mode);
    }catch{if(current===epoch)reset();}
    finally{input.password="";clearTimeout(timeout);controller.abort();if(current===epoch){active=null;wipe();enable();}}
  };
  status.addEventListener("click",()=>run("status"));preview.addEventListener("click",()=>run("preview"));stop.addEventListener("click",()=>run("stop"));form.addEventListener("submit",event=>{event.preventDefault();return run("start");});
  password.addEventListener("input",()=>{if(active)reset();enable();});consent.addEventListener("change",()=>{if(active)reset();enable();});
  recovery.addEventListener("click",()=>{if(recovery.href.endsWith("#cloudflare-dns")){const details=el("cloudflare-dns");if(details)details.open=true;}});
  document.addEventListener("visibilitychange",()=>{if(document.hidden)invalidate();});window.addEventListener("pagehide",invalidate);window.addEventListener("rootwell-dns-changed",invalidate);window.addEventListener("rootwell-renewal-job-changed",invalidate);
  for(const id of ["acme-order-form","dns-config-form","dns-operation-form","acme-account-form","acme-registration-form"])el(id)?.addEventListener("submit",invalidate);
  Object.defineProperty(globalThis,"rootwellTimingWatch",{value:Object.freeze({setSource,invalidate})});enable();
})();
