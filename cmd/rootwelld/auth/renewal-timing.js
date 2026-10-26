(() => {
  "use strict";
  const el=id=>document.getElementById(id), panel=el("renewal-time-panel"), select=el("renewal-time-certificate"), refresh=el("renewal-time-refresh"), form=el("renewal-time-form"), password=el("renewal-time-password"), consent=el("renewal-time-consent"), submit=el("renewal-time-submit"), message=el("renewal-time-message"), result=el("renewal-time-result");
  const fp=v=>typeof v==="string"&&/^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(v);
  const domain=v=>typeof v==="string"&&v.length<=255&&/^(?:\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(v)&&v.includes(".")&&!v.includes("..");
  const keys=(v,k)=>v&&typeof v==="object"&&!Array.isArray(v)&&Object.keys(v).sort().join(",")===k.split(",").sort().join(",");
  const date=v=>typeof v==="string"&&/^(?:20\d\d|2100)-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{0,8}[1-9])?Z$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).getUTCFullYear()>=2020&&new Date(v).getUTCFullYear()<=2100&&new Date(v.replace(/\.\d+Z$/,"Z")).toISOString()===v.replace(/\.\d+Z$/,"Z").replace("Z",".000Z");
  const pretty=v=>new Intl.DateTimeFormat("en-GB",{day:"numeric",month:"short",year:"numeric",hour:"2-digit",minute:"2-digit",timeZone:"UTC"}).format(new Date(v))+" UTC";
  const uncertain="Saved timing is not current. Use Check renewal readiness above, then read the saved renewal time again. An interrupted check is never retried automatically.";
  let epoch=0, active=null, activeMutation=false, snapshot=null, generation=0, certificates=new Map(), stale=null;
  const wipe=()=>{password.value="";consent.checked=false;};
  const enable=()=>{select.disabled=!!active;refresh.disabled=!!active||!certificates.has(select.value)||document.hidden;submit.disabled=!!active||!snapshot||(!snapshot.can_read&&!snapshot.can_interrupt)||!password.value||!consent.checked||document.hidden;};
  const resetStatus=(forget=false)=>{const unknown=forget===true||activeMutation;++epoch;active?.abort();active=null;activeMutation=false;clearTimeout(stale);snapshot=null;wipe();form.hidden=true;result.hidden=true;for(const id of ["renewal-time-next","renewal-time-reason","renewal-time-technical"])el(id).textContent="";message.textContent=uncertain;if(unknown){certificates.clear();generation=0;select.replaceChildren();globalThis.rootwellTimingWatch?.invalidate();window.dispatchEvent(new Event("rootwell-timing-changed"));}enable();};
  const invalidate=()=>{resetStatus();certificates.clear();generation=0;select.replaceChildren();panel.hidden=true;globalThis.rootwellTimingWatch?.invalidate();enable();};
  const setCertificates=(rows,gen)=>{
    invalidate();if(!Number.isSafeInteger(gen)||gen<1||gen>1000000||!Array.isArray(rows)||rows.length>500)return;
    for(const row of rows){if(row.state==="manual")continue;if(!fp(row.fingerprint)||typeof row.name!=="string"||!row.name||row.name.length>255||/[\u0000-\u001f\u007f]/.test(row.name)||row.not_after!==undefined&&!date(row.not_after)||certificates.has(row.fingerprint)){invalidate();return;}certificates.set(row.fingerprint,row);}
    generation=gen;
    for(const row of certificates.values()){const option=document.createElement("option");option.value=row.fingerprint;option.textContent=row.name+(row.state==="superseded"?" — older certificate":row.state==="expired"?" — expired":"");select.appendChild(option);}
    if(certificates.size){select.value=certificates.keys().next().value;panel.hidden=false;message.textContent="Read the saved renewal time for this test certificate. Nothing contacts the provider automatically.";}
    enable();
    globalThis.rootwellTimingWatch?.setSource(select.value,generation);
  };
  const validate=(d,mode,chosen,expected)=>{
    if(!keys(d,"schema_version,provider,generation,checked_at,unlock_expires,network_attempted,saved,automatic_renewal,status")||d.schema_version!=="rootwell.acme.renewal-timing.v1"||d.provider!=="letsencrypt-staging"||d.generation!==expected+(mode==="status"?0:mode==="check"?2:1)||d.generation>1000000||!date(d.checked_at)||!date(d.unlock_expires)||Date.parse(d.unlock_expires)<=Date.parse(d.checked_at)||Date.parse(d.unlock_expires)-Date.parse(d.checked_at)>43200000||d.network_attempted!==(mode==="check")||d.saved!==(mode!=="status")||d.automatic_renewal!==false)throw new Error();
    const s=d.status;
    if(!keys(s,"fingerprint,not_after,prepared,state,started_at,observed_at,pending,can_read,can_interrupt,source,renew_at,fallback_at,effective_at,next_check,provider_not_before,blocked,failures,window_start,window_end,checked_at,expired,superseded")||s.fingerprint!==chosen||!date(s.not_after)||certificates.get(chosen).not_after&&certificates.get(chosen).not_after!==s.not_after||!["prepared","pending","can_read","can_interrupt","blocked","expired","superseded"].every(k=>typeof s[k]==="boolean")||!Number.isSafeInteger(s.failures)||s.failures<0||s.failures>6||!["not-prepared","pending","ari","unsupported","error","interrupted"].includes(s.state)||s.prepared!==(s.state!=="not-prepared")||s.pending!==(s.state==="pending")||s.can_interrupt!==s.pending||s.expired!==(Date.parse(s.not_after)<=Date.parse(d.checked_at)))throw new Error();
    if(s.provider_not_before!==""&&!date(s.provider_not_before))throw new Error();
    if(!s.prepared){if(s.failures!==0||["source","started_at","observed_at","renew_at","fallback_at","effective_at","next_check","window_start","window_end","checked_at"].some(k=>s[k]!==""))throw new Error();}
    else {
      if(!["fallback","ari"].includes(s.source)||![s.started_at,s.renew_at,s.fallback_at,s.effective_at,s.next_check].every(date)||Date.parse(s.started_at)>Date.parse(d.checked_at)||Date.parse(s.renew_at)>=Date.parse(s.not_after)||Date.parse(s.fallback_at)>=Date.parse(s.not_after)||(s.pending?s.observed_at!=="":!date(s.observed_at)||Date.parse(s.observed_at)<Date.parse(s.started_at)||Date.parse(s.observed_at)>Date.parse(d.checked_at)))throw new Error();
      if(["ari","unsupported"].includes(s.state)?s.failures!==0:s.failures<1)throw new Error();
      if(Date.parse(s.next_check)<=Date.parse(s.started_at)||(s.state==="ari"||s.source==="ari")&&s.window_start==="")throw new Error();
      if(Date.parse(s.effective_at)!==Math.max(Date.parse(s.source==="fallback"?s.fallback_at:s.renew_at),s.provider_not_before?Date.parse(s.provider_not_before):0))throw new Error();
      if(s.window_start!==""||s.window_end!==""||s.checked_at!==""){if(![s.window_start,s.window_end,s.checked_at].every(date)||Date.parse(s.window_end)<=Date.parse(s.window_start)||Date.parse(s.window_end)>Date.parse(s.not_after)||Date.parse(s.checked_at)>Date.parse(d.checked_at))throw new Error();}
    }
    if(s.can_read&&(s.pending||s.expired||s.superseded||s.blocked||s.next_check&&Date.parse(s.next_check)>Date.parse(d.checked_at)||s.provider_not_before&&Date.parse(s.provider_not_before)>Date.parse(d.checked_at)))throw new Error();
    return d;
  };
  const render=d=>{
    snapshot=d.status;generation=d.generation;const s=snapshot;
    globalThis.rootwellTimingWatch?.setSource(s.fingerprint,generation);
    el("renewal-time-next").textContent=s.prepared?"Suggested renewal time: "+pretty(s.effective_at):"No renewal time has been saved yet.";
    const wait=[s.next_check,s.provider_not_before].filter(Boolean).sort((a,b)=>Date.parse(b)-Date.parse(a))[0];
    el("renewal-time-reason").textContent=s.superseded?"A newer certificate is already saved. The original stays in Certificates.":s.expired?"This certificate has expired. Continue its renewal with your issuer; timing checks cannot extend it.":s.blocked?"Provider access is paused for reviewed maintenance. Do not reset or restore an old backup to retry.":s.pending?"The last timing check was interrupted. Finish it locally before any later check; the saved wait stays in place.":!s.can_read&&wait?(s.state==="error"?"The provider check failed. ":s.state==="unsupported"?"The provider did not offer a renewal time. ":"")+"Next provider check: "+pretty(wait)+". Rootwell will respect the saved wait.":s.state==="error"?"The provider check failed. Saved timing is a local estimate, not a new certificate.":s.source==="ari"?"Provider recommendation saved. No certificate has been renewed.":s.prepared?"Using the saved lifetime estimate. No certificate has been renewed.":"You can request a recommended time from the test provider.";
    el("renewal-time-technical").textContent="Saved state: "+s.state+" · generation "+generation+(s.fallback_at?" · local estimate "+pretty(s.fallback_at):"")+(s.checked_at?" · provider information checked "+pretty(s.checked_at):"")+". This is not issuer trust, revocation or deployment verification.";
    message.textContent="Saved timing checked. Automatic renewal is not enabled.";result.hidden=false;
    const interrupt=s.can_interrupt;form.hidden=!interrupt&&!s.can_read;el("renewal-time-privacy").hidden=interrupt;
    el("renewal-time-consent-label").textContent=interrupt?"Finish only the interrupted local check; keep its wait and retry count":"Allow this one provider timing check";
    submit.textContent=interrupt?"Finish interrupted check":"Check renewal time";
    clearTimeout(stale);stale=setTimeout(resetStatus,60000);enable();
  };
  const run=async mode=>{
    if(active||document.hidden||!certificates.has(select.value)||mode!=="status"&&(!snapshot||!consent.checked||!password.value))return;
    const chosen=select.value,expected=generation,current=++epoch,controller=new AbortController(),began=Date.now();active=controller;activeMutation=mode!=="status";
    const input={provider:"letsencrypt-staging",fingerprint:chosen,expected_generation:expected};if(mode!=="status"){input.password=password.value;input.confirm=true;}
    clearTimeout(stale);wipe();form.hidden=true;result.hidden=true;snapshot=null;enable();message.textContent=mode==="status"?"Reading saved timing — no provider connection…":mode==="interrupt"?"Finishing the interrupted local check — no provider connection…":"Checking the recommended renewal time…";
    const timeout=setTimeout(()=>{if(current===epoch)resetStatus(true);},25000);
    try {
      const response=await fetch("/api/acme/renewal-timing/"+mode,{method:"POST",credentials:"same-origin",cache:"no-store",redirect:"error",signal:controller.signal,headers:{"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify(input)});input.password="";
      if(response.status!==200||response.headers.get("cache-control")!=="no-store"||response.headers.get("content-type")?.split(";")[0].trim().toLowerCase()!=="application/json"||!response.body)throw new Error();
      const reader=response.body.getReader(),decoder=new TextDecoder("utf-8",{fatal:true});let text="",size=0;
      try{for(;;){const part=await reader.read();if(part.done)break;size+=part.value.byteLength;if(size>16384||current!==epoch||controller.signal.aborted||document.hidden)throw new Error();text+=decoder.decode(part.value,{stream:true});}text+=decoder.decode();}finally{await reader.cancel();reader.releaseLock();}
      const d=validate(JSON.parse(text),mode,chosen,expected),elapsed=Date.now()-began;
      if(current!==epoch||controller.signal.aborted||document.hidden||select.value!==chosen||elapsed<0||elapsed>=25000||Math.abs(Date.now()-Date.parse(d.checked_at))>=120000)throw new Error();
      render(d);if(mode!=="status")window.dispatchEvent(new Event("rootwell-timing-changed"));
    }catch{if(current===epoch&&!document.hidden)resetStatus(true);}
    finally{input.password="";clearTimeout(timeout);controller.abort();if(current===epoch){active=null;activeMutation=false;wipe();enable();}}
  };
  refresh.addEventListener("click",()=>run("status"));form.addEventListener("submit",event=>{event.preventDefault();return run(snapshot?.can_interrupt?"interrupt":"check");});
  select.addEventListener("change",()=>{resetStatus();globalThis.rootwellTimingWatch?.setSource(select.value,generation);});password.addEventListener("input",()=>{if(active)resetStatus();enable();});consent.addEventListener("change",()=>{if(active)resetStatus();enable();});
  window.addEventListener("rootwell-watch-changed",invalidate);
  document.addEventListener("visibilitychange",()=>{if(document.hidden)invalidate();});window.addEventListener("pagehide",invalidate);window.addEventListener("rootwell-dns-changed",invalidate);
  for(const id of ["acme-order-form","dns-config-form","dns-operation-form","acme-account-form","acme-registration-form"])el(id)?.addEventListener("submit",invalidate);
  Object.defineProperty(globalThis,"rootwellRenewalTiming",{value:Object.freeze({setCertificates,invalidate})});
  try{const text=el("acme-renewal-source")?.textContent||"";if(text){if(text.length>4096)throw new Error();const d=JSON.parse(text);if(JSON.stringify(d)!==text||!keys(d,"schema_version,generation,fingerprint,domains")||d.schema_version!=="rootwell.acme.renewal-selection.v1"||!fp(d.fingerprint)||!Array.isArray(d.domains)||!d.domains.length||d.domains.length>8||!d.domains.every(domain)||d.domains.some((n,i)=>i>0&&d.domains[i-1]>=n))throw new Error();setCertificates([{fingerprint:d.fingerprint,name:d.domains[0],state:"selected"}],d.generation);}}catch{invalidate();}
  enable();
})();
