(() => {
  "use strict";
  const el=id=>document.getElementById(id),status=el("renewal-job-status"),preview=el("renewal-job-preview"),stop=el("renewal-job-stop"),form=el("renewal-job-form"),password=el("renewal-job-password"),consent=el("renewal-job-consent"),exclusive=el("renewal-job-exclusive"),start=el("renewal-job-start"),message=el("renewal-job-message"),result=el("renewal-job-result"),link=el("renewal-job-recovery");
  const keys=(v,k)=>v&&typeof v==="object"&&!Array.isArray(v)&&Object.keys(v).sort().join(",")===k.split(",").sort().join(",");
  const fp=v=>typeof v==="string"&&/^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/.test(v),id=v=>typeof v==="string"&&/^[0-9a-f]{32}$/.test(v);
  const count=(v,max)=>Number.isSafeInteger(v)&&v>=0&&v<=max;
  const name=v=>typeof v==="string"&&v.length>0&&v.length<=255&&!/[\u0000-\u001f\u007f]/.test(v);
  const date=v=>typeof v==="string"&&/^(?:20\d\d|2100)-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{0,8}[1-9])?Z$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v.replace(/\.\d+Z$/,"Z")).toISOString()===v.replace(/\.\d+Z$/,"Z").replace("Z",".000Z");
  const pretty=v=>new Intl.DateTimeFormat("en-GB",{day:"numeric",month:"short",hour:"2-digit",minute:"2-digit",timeZone:"UTC"}).format(new Date(v))+" UTC";
  const actions={timing:"Check the recommended renewal time",close:"Retain the previous request",order:"Request the new test certificate","order-read":"Read the same saved request","dns-plan":"Prepare temporary DNS records","dns-add":"Add a required DNS record","dns-check":"Check the saved DNS operation","dns-cleanup":"Remove a Rootwell-owned temporary DNS record",ack:"Confirm DNS is ready",validate:"Ask the CA to check domain control","validation-read":"Read the same CA verification",key:"Prepare an independent new certificate key",certificate:"Request issuance once","certificate-read":"Read the same certificate result"};
  const reasons={
    "not-started":["Nothing is running. Select a saved test certificate above, then check before enabling.","#renewal-readiness"],
    ready:["Ready for the separately approved test renewal.","#renewal-readiness"],
    "step-saved":["The last step was saved. Waiting before the next bounded step.","#session-renewal-panel"],
    busy:["Another operation is using Rootwell. This tick has not contacted a provider.","#session-renewal-panel"],
    "provider-wait":["Waiting for the saved provider time. Longer waits are respected.","#renewal-readiness"],
    "renewal-wait":["The selected certificate is not due yet. Its saved renewal time will be respected.","#renewal-readiness"],
    "dns-wait":["Waiting before a scoped read of the saved DNS operation. A create or deletion is never replayed.","#cloudflare-dns"],
    stopped:["Stopped locally. Sent operations may still have taken effect. Read the saved request before continuing.","#certificate-request"],
    "server-stopped":["The server stopped. A new login and separate approval are required.","#renewal-readiness"],
    "access-ended":["This login ended or changed. The job cannot continue under another login.","#renewal-readiness"],
    "storage-changed":["Saved data changed or cannot be read. Refresh readiness; the job will not adopt unrelated changes.","#renewal-readiness"],
    "scope-changed":["The selected certificate or DNS configuration changed. Review it before granting another job.","#renewal-readiness"],
    "outcome-unconfirmed":["The last outcome is unconfirmed. Read the same saved request and DNS result. No write will be repeated automatically.","#certificate-request"],
    "action-limit":["The bounded session action limit was reached. Review the saved request.","#certificate-request"],
    "poll-limit":["The read limit was reached. Review the saved result before granting further work.","#certificate-request"],
    complete:["The new checked test certificate and key are saved, and owned DNS cleanup is confirmed. Both certificate pairs remain saved.","/certificates"],
    "invalid-state":["The saved state cannot safely select a next step. Review the same request.","#certificate-request"],
    "account-unavailable":["Prepare and register the test account first. Account and terms decisions remain yours.","#certificate-request"],
    "other-work-pending":["Resolve the interrupted timing check for another certificate first. Its reserved recovery space is kept.","#renewal-readiness"],
    "dns-configuration":["Save a restricted Cloudflare credential for the certificate's zone first.","#cloudflare-dns"],
    "dns-zone-mismatch":["The saved Cloudflare zone does not cover all selected names.","#cloudflare-dns"],
    "storage-capacity":["There is not enough room for the full remaining cycle. Make a complete backup and review history storage. Nothing is pruned automatically.","/certificates#history-storage"],
    "request-capacity":["Retain closed request history to make room before another cycle.","/certificates#request-storage"],
    "source-ended":["The original certificate expired or already has a successor. Choose the current certificate.","/certificates"],
    "timing-interrupted":["Resolve the interrupted timing check first; its wait and counters stay saved.","#renewal-readiness"],
    "timing-unconfirmed":["Review the saved provider timing result before enabling renewal.","#renewal-readiness"],
    "provider-maintenance":["Provider access is blocked. Review maintenance; never restore an old backup to retry.","#renewal-readiness"],
    "clock-unavailable":["Review the server clock before continuing.","#renewal-readiness"],
    "request-active":["Finish or reconcile the unrelated saved request first.","#certificate-request"],
    "request-expired":["This renewal request expired. Review it and its DNS cleanup; the job will not replace it automatically.","#certificate-request"],
    "order-unconfirmed":["The order result is unknown. Review the same saved request; another order will not be created.","#certificate-request"],
    "validation-failed":["The CA did not confirm domain control. Review the saved verification result.","#certificate-request"],
    "dns-maintenance":["DNS work is blocked, exhausted or needs operator recovery. Counters and ownership are never reset by this job.","#cloudflare-dns"],
    "dns-unconfirmed":["Review the saved DNS result before continuing.","#cloudflare-dns"],
    "dns-cleanup":["Clean up the previous request's owned temporary DNS records first.","#cloudflare-dns"],
    "certificate-unconfirmed":["Review the same saved certificate result. The job will not prepare a replacement key or replay issuance.","#certificate-request"]
  };
  const planned=new Set([...Object.keys(actions),"provider-wait","renewal-wait","dns-wait"]);
  const uncertain="Outcome not confirmed. A granted renewal may still be running. Read renewal status before another action.";
  let source=null,plan=null,job=null,active=null,epoch=0,stale=null;
  const running=()=>job&&["waiting","running"].includes(job.state);
  const wipe=()=>{password.value="";consent.checked=false;exclusive.checked=false;};
  const enable=()=>{status.disabled=!!active||document.hidden;preview.disabled=!!active||!source||document.hidden;stop.disabled=!!active||!running()||document.hidden;start.disabled=!!active||!source||!plan?.can_start||running()||!password.value||!consent.checked||!exclusive.checked||document.hidden;};
  const reset=()=>{++epoch;active?.abort();active=null;clearTimeout(stale);plan=null;job=null;wipe();form.hidden=true;result.hidden=true;link.hidden=true;message.textContent=uncertain;enable();};
  const setSource=(fingerprint,generation)=>{reset();source=fp(fingerprint)&&count(generation,1000000)&&generation>0?{fingerprint,generation}:null;enable();};
  const invalidate=()=>setSource("",0);
  const validate=(d,mode,input)=>{
    if(!keys(d,"schema_version,provider,scope,test_only,checked_at,job,readiness")||d.schema_version!=="rootwell.acme.renewal-job.v1"||d.provider!=="letsencrypt-staging"||d.scope!=="session-test-renewal"||d.test_only!==true||!date(d.checked_at))throw new Error();
    const j=d.job,p=d.readiness;
    if(!keys(j,"id,fingerprint,name,generation,state,reason,phase,saved_fingerprint,checked_at,next_check,expires,actions,limit")||!["not-running","waiting","running","paused","complete"].includes(j.state)||!Object.hasOwn(reasons,j.reason)&&!Object.hasOwn(actions,j.reason)||!count(j.actions,160)||j.limit!==160||j.phase!==""&&!Object.hasOwn(actions,j.phase)&&!["wait","pause","complete"].includes(j.phase)||j.saved_fingerprint!==""&&(!fp(j.saved_fingerprint)||j.saved_fingerprint===j.fingerprint))throw new Error();
    if(j.state==="not-running"){if(j.reason!=="not-started"||j.actions!==0||j.generation!==0||[j.id,j.fingerprint,j.name,j.phase,j.saved_fingerprint,j.checked_at,j.next_check,j.expires].some(v=>v!==""))throw new Error();}
    else if(!id(j.id)||!fp(j.fingerprint)||!name(j.name)||!count(j.generation,1000000)||j.generation<1||!date(j.checked_at)||!date(j.expires)||Date.parse(j.checked_at)>Date.parse(d.checked_at)+1000||Date.parse(j.expires)-Date.parse(d.checked_at)>43200000||["waiting","running"].includes(j.state)&&Date.parse(j.expires)<=Date.parse(d.checked_at)||j.next_check!==""&&!date(j.next_check)||j.state!=="waiting"&&j.next_check!==""||j.state==="complete"&&(j.reason!=="complete"||!fp(j.saved_fingerprint)))throw new Error();
    if(["preview","start"].includes(mode)){if(!keys(p,"generation,fingerprint,name,can_start,reason,next_check")||p.generation!==input.expected_generation||p.fingerprint!==input.fingerprint||!name(p.name)||typeof p.can_start!=="boolean"||!Object.hasOwn(reasons,p.reason)&&!Object.hasOwn(actions,p.reason)||p.can_start!==planned.has(p.reason)||p.next_check!==""&&!date(p.next_check))throw new Error();}else if(p!==null)throw new Error();
    if(mode==="start"&&(j.fingerprint!==input.fingerprint||j.generation<input.expected_generation||j.generation>input.expected_generation+3))throw new Error();
    if(mode==="stop"&&(j.id!==input.job_id||!(j.state==="paused"&&j.reason==="stopped"||j.state==="complete"&&j.reason==="complete")))throw new Error();
    return d;
  };
  const render=(d,mode)=>{
    job=d.job;plan=d.readiness;
    const reason=mode==="preview"&&plan&&!running()?plan.reason:job.reason,info=reasons[reason]||[actions[reason]+".","#session-renewal-panel"];
    const title={"not-running":"Not running",waiting:"Waiting",running:"Working",paused:"Paused",complete:"Complete"}[job.state];
    el("renewal-job-state").textContent=(job.name||plan?.name||"Test renewal")+" — "+title;
    el("renewal-job-reason").textContent=info[0];
    el("renewal-job-next").textContent=job.next_check?"Next step no earlier than "+pretty(job.next_check):plan?.next_check?"Saved time: "+pretty(plan.next_check):"No next step is queued.";
    el("renewal-job-saved").textContent=job.saved_fingerprint?(job.state==="complete"?"Saved test certificate: ":"New test certificate saved — cleanup still needs confirmation: ")+job.saved_fingerprint:"Read the saved request for certificate results.";
    el("renewal-job-details").textContent=job.id?job.actions+" / 160 actions · original login ends "+pretty(job.expires)+" · saved generation "+job.generation:"One source, one bounded test cycle. No deployment or continuous unattended renewal.";
    link.href=info[1];link.textContent=info[1].startsWith("/certificates")?"Open Certificates":"Review this step";link.hidden=false;
    form.hidden=!source||!plan?.can_start||running();result.hidden=false;message.textContent="Session renewal status checked. Test certificates only; your original pair is retained.";clearTimeout(stale);stale=setTimeout(reset,60000);enable();
  };
  const changed=()=>{window.dispatchEvent(new Event("rootwell-renewal-job-changed"));window.dispatchEvent(new Event("rootwell-timing-changed"));};
  const run=async mode=>{
    if(active||document.hidden||mode==="preview"&&!source||mode==="start"&&(!source||!plan?.can_start||running()||!password.value||!consent.checked||!exclusive.checked)||mode==="stop"&&!running())return;
    const input={provider:"letsencrypt-staging"};if(["preview","start"].includes(mode)){input.fingerprint=source.fingerprint;input.expected_generation=source.generation;}if(mode==="start"){input.password=password.value;input.confirm=true;input.exclusive_dns=true;input.scope="session-test-renewal";}if(mode==="stop")input.job_id=job.id;
    const current=++epoch,controller=new AbortController(),began=Date.now();active=controller;plan=null;wipe();form.hidden=true;result.hidden=true;enable();message.textContent=mode==="start"?"Granting this test renewal…":mode==="stop"?"Stopping local work…":"Reading local status — no provider connection…";
    const timeout=setTimeout(()=>{if(current===epoch)reset();},25000);
    try{
      const pending=fetch("/api/acme/renewal-job/"+mode,{method:"POST",credentials:"same-origin",cache:"no-store",redirect:"error",signal:controller.signal,headers:{"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify(input)});input.password="";
      const response=await pending;if(response.status!==200||response.headers.get("cache-control")!=="no-store"||response.headers.get("content-type")?.split(";")[0].trim().toLowerCase()!=="application/json"||!response.body)throw new Error();
      const reader=response.body.getReader(),decoder=new TextDecoder("utf-8",{fatal:true});let text="",size=0;try{for(;;){const part=await reader.read();if(part.done)break;size+=part.value.byteLength;if(size>16384||current!==epoch||controller.signal.aborted||document.hidden)throw new Error();text+=decoder.decode(part.value,{stream:true});}text+=decoder.decode();}finally{await reader.cancel();reader.releaseLock();}
      const d=validate(JSON.parse(text),mode,input);if(current!==epoch||controller.signal.aborted||document.hidden||Date.now()-began<0||Date.now()-began>=25000||Math.abs(Date.now()-Date.parse(d.checked_at))>=120000)throw new Error();
      active=null;if(mode==="start"||mode==="stop"){source=null;changed();}render(d,mode);
    }catch{if(current===epoch)reset();}finally{input.password="";clearTimeout(timeout);controller.abort();if(current===epoch){active=null;wipe();enable();}}
  };
  status.addEventListener("click",()=>run("status"));preview.addEventListener("click",()=>run("preview"));stop.addEventListener("click",()=>run("stop"));form.addEventListener("submit",event=>{event.preventDefault();return run("start");});
  password.addEventListener("input",()=>{if(active)reset();enable();});for(const field of [consent,exclusive])field.addEventListener("change",()=>{if(active)reset();enable();});
  link.addEventListener("click",()=>{if(link.href.endsWith("#cloudflare-dns"))el("cloudflare-dns").open=true;});
  document.addEventListener("visibilitychange",()=>{if(document.hidden)invalidate();});window.addEventListener("pagehide",invalidate);window.addEventListener("rootwell-dns-changed",invalidate);window.addEventListener("rootwell-watch-changed",invalidate);
  for(const id of ["acme-order-form","dns-config-form","dns-operation-form","acme-account-form","acme-registration-form"])el(id)?.addEventListener("submit",invalidate);
  Object.defineProperty(globalThis,"rootwellRenewalJob",{value:Object.freeze({setSource,invalidate})});enable();
})();
