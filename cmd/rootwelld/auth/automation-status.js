(() => {
  "use strict";
  const el=id=>document.getElementById(id), button=el("automation-status-refresh"), message=el("automation-status-message"), result=el("automation-status-result"), rows=el("automation-status-certificates");
  let active=null, epoch=0;
  const keys=(v,n)=>v && typeof v==="object" && !Array.isArray(v) && Object.keys(v).sort().join(",")===n.split(",").sort().join(",");
  const date=v=>typeof v==="string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v) && Number.isFinite(Date.parse(v)) && new Date(v).toISOString()===v.replace("Z",".000Z");
  const count=(v,max)=>Number.isSafeInteger(v)&&v>=0&&v<=max;
  const pretty=v=>new Intl.DateTimeFormat("en-GB",{day:"numeric",month:"short",year:"numeric",hour:"2-digit",minute:"2-digit",timeZone:"UTC"}).format(new Date(v))+" UTC";
  const states={manual:"Renew with your issuer",waiting:"Not due yet",due:"Ready for renewal review",expired:"Expired — renewal needs attention","not-yet-valid":"Not valid yet — check your clock",superseded:"A newer certificate was saved — original retained"};
  const validate=d=>{
    if(!keys(d,"schema_version,provider,network_used,automatic_renewal,unlock_expires,generation,checked_at,request,dns,dns_wait_until,account_ready,dns_saved,capacity,certificates") || d.schema_version!=="rootwell.automation.status.v1" || d.provider!=="letsencrypt-staging" || d.network_used!==false || d.automatic_renewal!==false || !count(d.generation,1000000) || d.generation<1 || !date(d.checked_at) || !date(d.unlock_expires) || d.unlock_expires<=d.checked_at || Date.parse(d.unlock_expires)-Date.parse(d.checked_at)>43200000 || !["none","active","close-needed","unknown","capacity"].includes(d.request) || !["none","cleanup-needed","unknown","maintenance","clock-unavailable"].includes(d.dns) || typeof d.account_ready!=="boolean" || typeof d.dns_saved!=="boolean" || d.dns_wait_until!==""&&(!date(d.dns_wait_until)||d.dns_wait_until<=d.checked_at||d.dns!=="unknown"))throw new Error();
    const c=d.capacity;
    if(!keys(c,"events_free,events_reserved,archives_free,records_free,generations_free,bytes_free") || !count(c.events_free,1024) || !count(c.events_reserved,256) || c.events_free+c.events_reserved>1024 || 1024-c.events_free-c.events_reserved>d.generation-1 || !count(c.archives_free,32) || !count(c.records_free,500) || !count(c.generations_free,1000000-d.generation) || c.generations_free!==Math.max(0,1000000-d.generation-c.events_reserved) || !count(c.bytes_free,100663296) || !Array.isArray(d.certificates) || d.certificates.length>500 || d.certificates.length+c.records_free!==500)throw new Error();
    const seen=new Set();
    for(const r of d.certificates){
      if(!keys(r,"fingerprint,name,not_after,review_at,state") || typeof r.fingerprint!=="string" || !/^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(r.fingerprint) || seen.has(r.fingerprint) || typeof r.name!=="string" || !r.name || r.name.length>255 || /[\u0000-\u001f\u007f]/.test(r.name) || !date(r.not_after) || !Object.hasOwn(states,r.state) || (r.state==="manual" ? r.review_at!=="" : !date(r.review_at)||r.review_at>=r.not_after))throw new Error();
      if(r.state==="due" && !(r.review_at<=d.checked_at&&d.checked_at<r.not_after) || r.state==="expired" && r.not_after>d.checked_at || r.state==="waiting" && r.review_at<=d.checked_at)throw new Error();
      seen.add(r.fingerprint);
    }
    return d;
  };
  const clear=(timing=true)=>{++epoch;active?.abort();active=null;button.disabled=false;result.hidden=true;rows.replaceChildren();for(const id of ["automation-status-next","automation-status-capacity","automation-status-unlock"])el(id).textContent="";message.textContent="Saved status is not current. Check renewal readiness again. Nothing was renewed.";if(timing!==false)globalThis.rootwellRenewalTiming?.invalidate();};
  const render=d=>{
    const c=d.capacity, due=d.certificates.filter(r=>r.state==="due"||r.state==="expired").length;
    message.textContent=due?due+" test certificate"+(due===1?" needs":"s need")+" renewal review. Automatic renewal is not enabled.":"Saved status checked. Automatic renewal is not enabled.";
    const next=d.dns==="clock-unavailable"?"Check the server clock before continuing.":d.dns==="maintenance"?"DNS work is blocked. Keep this saved request and inspect the provider; reviewed operator maintenance is required. Never restore an old backup to retry.":d.dns==="unknown"?"A DNS operation is unconfirmed. Use the Cloudflare section's read-only result check; do not repeat a create or deletion."+(d.dns_wait_until?" Wait until "+d.dns_wait_until+".":""):d.dns==="cleanup-needed"?"Rootwell-owned temporary DNS records still need cleanup in the Cloudflare section.":d.request==="unknown"?"The CA request is unconfirmed. Refresh the same saved request; do not start another.":d.request==="capacity"||!c.events_free||!c.archives_free||!c.records_free||!c.generations_free||!c.bytes_free?"Storage headroom is limited. Make a full backup and arrange reviewed maintenance. Nothing is pruned automatically.":d.request==="close-needed"?"Close the completed or expired request before preparing another. Certificates and keys stay saved.":d.request==="active"?"Continue the saved certificate request below before starting another.":!d.account_ready?"Prepare and register your test account below; terms acceptance is always your decision.":"Choose a saved test certificate in Certificates, then select Renew test certificate.";
    el("automation-status-next").textContent=next;
    el("automation-status-capacity").textContent=c.events_free+" unreserved activity slots · "+c.events_reserved+" reserved for pending work · "+c.archives_free+" request archive slots · "+c.records_free+" certificate slots. Headroom is not a guarantee that a future operation fits. History and archives are never silently cleared.";
    rows.replaceChildren();for(const r of d.certificates){const li=document.createElement("li");li.textContent=r.name+" — "+states[r.state]+" · expires "+pretty(r.not_after)+(r.review_at?" · review from "+pretty(r.review_at):"");rows.append(li);}
    if(!d.certificates.length){const li=document.createElement("li");li.textContent="No saved certificates yet.";rows.append(li);}
    el("automation-status-unlock").textContent="Session access ends "+pretty(d.unlock_expires)+". Logout, lock or restart stops session-bound work; no background password is saved. Check again after one minute for current status.";
    result.hidden=false;
    globalThis.rootwellRenewalTiming?.setCertificates(d.certificates,d.generation);
  };
  button.addEventListener("click",async()=>{
    if(active||document.hidden)return;
    clear();const current=epoch, controller=new AbortController(), began=Date.now();active=controller;button.disabled=true;
    message.textContent="Reading saved renewal status… No CA or DNS connection.";
    const timeout=setTimeout(()=>{if(current===epoch)clear();},10000);
    try{
      const response=await fetch("/api/automation/status",{method:"POST",credentials:"same-origin",cache:"no-store",redirect:"error",signal:controller.signal,headers:{"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify({provider:"letsencrypt-staging"})});
      if(response.status!==200||response.headers.get("cache-control")!=="no-store"||response.headers.get("content-type")?.split(";")[0].trim().toLowerCase()!=="application/json"||!response.body)throw new Error();
      const reader=response.body.getReader(),decoder=new TextDecoder("utf-8",{fatal:true});let text="",size=0;
      try{while(true){const {value,done}=await reader.read();if(done)break;size+=value.byteLength;if(size>262144||document.hidden||current!==epoch||controller.signal.aborted)throw new Error();text+=decoder.decode(value,{stream:true});}text+=decoder.decode();}finally{await reader.cancel();reader.releaseLock();}
      const data=validate(JSON.parse(text)), elapsed=Date.now()-began;
      if(current!==epoch||document.hidden||controller.signal.aborted||elapsed<0||elapsed>=10000||Math.abs(Date.now()-Date.parse(data.checked_at))>=120000)throw new Error();
      render(data);setTimeout(()=>{if(current===epoch)clear();},60000);
    }catch{if(current===epoch){clear();message.textContent="Saved status unavailable. Check your login, server clock and Linux storage, then try again. No renewal was attempted.";}}
    finally{clearTimeout(timeout);if(current===epoch){active=null;button.disabled=false;}}
  });
  document.addEventListener("visibilitychange",()=>{if(document.hidden)clear();});
  window.addEventListener("pagehide",clear);
  window.addEventListener("rootwell-dns-changed",clear);
  window.addEventListener("rootwell-timing-changed",()=>clear(false));
  for(const id of ["acme-order-form","dns-config-form","dns-operation-form","acme-account-form","acme-registration-form"])el(id)?.addEventListener("submit",clear);
})();
