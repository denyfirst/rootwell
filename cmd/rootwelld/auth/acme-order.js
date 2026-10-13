(() => {
  "use strict";
  const el=id=>document.getElementById(id), refresh=el("acme-order-refresh"), status=el("acme-order-status"), form=el("acme-order-form"), names=el("acme-order-domains");
  const namesRow=el("acme-order-names-row"), consent=el("acme-order-consent"), label=el("acme-order-consent-label"), password=el("acme-order-password"), submit=el("acme-order-submit"), records=el("acme-order-records"), resumeChoice=el("acme-order-resume-choice");
  let snapshot=null, active=null, generation=0, action="start";
  const uncertain="Outcome not confirmed. Check saved request first. A sent request cannot be undone. Do not resend it or create another request; only read the same saved result.";
  const date=value=>typeof value==="string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).getUTCFullYear()>=2020 && new Date(value).toISOString()===value.replace("Z",".000Z");
  const domain=value=>typeof value==="string" && value.length<=255 && /^(?:\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(value) && value.includes(".") && !value.includes("..");
  const suppliedNames=()=>names.value.split(/\r?\n/).map(n=>n.trim().toLowerCase()).filter(Boolean).sort();
  const usable=()=>snapshot && date(snapshot.expires) && Date.now()<Date.parse(snapshot.expires) && (!snapshot.issuance.expires || date(snapshot.issuance.expires) && Date.now()<Date.parse(snapshot.issuance.expires));
  const validationStates=["validation-pending","validation-waiting","validation-failed","domain-verified"];
  const allowedAction=()=>snapshot && (action==="close-request" ? snapshot.new_request.available : action==="certificate-refresh" ? ["issuance-pending","not-issued","awaiting-certificate","issuance-failed"].includes(snapshot.issuance.state) && usable() : snapshot.issuance.state==="not-started" && (action==="issue" ? snapshot.can_issue && usable() : action==="start" ? snapshot.state==="not-started" && snapshot.new_request.reason==="not-started" : action==="ack" ? snapshot.state==="dns-ready" && usable() : action==="validate" ? snapshot.state==="dns-acknowledged" && usable() : action==="prepare-key" ? snapshot.state==="domain-verified" && snapshot.domain_verified && !snapshot.certificate_key.prepared && usable() : action==="refresh" ? validationStates.includes(snapshot.state) && usable() : ["order-known","dns-ready","dns-acknowledged"].includes(snapshot.state)));
  const enable=()=>{
    refresh.disabled=!!active; names.disabled=!!active; consent.disabled=!!active; password.disabled=!!active; resumeChoice.disabled=!!active;
    submit.disabled=!!active || document.hidden || !allowedAction() || !consent.checked || !password.value || (action==="start" && !suppliedNames().length);
  };
  const clearInputs=()=>{password.value="";consent.checked=false;};
  const invalidate=()=>{
    generation++;active?.abort();snapshot=null;clearInputs();form.hidden=true;records.hidden=true;records.replaceChildren();resumeChoice.hidden=true;status.textContent=uncertain;enable();
  };
  const valid=(data,mode)=>{
    if(!data || Array.isArray(data) || Object.keys(data).length!==14 || data.schema_version!=="rootwell.acme.manual-dns.v6" || data.provider!=="letsencrypt-staging" || typeof data.can_issue!=="boolean" || typeof data.domain_verified!=="boolean" || data.domain_verified && data.state!=="domain-verified" || !Number.isSafeInteger(data.generation) || data.generation<1 || data.generation>1000000 || !["not-started","request-pending","order-known","dns-ready","dns-acknowledged",...validationStates].includes(data.state) || data.saved!==(data.state!=="not-started") || data.network_used!==["start","resume","validate","refresh","issue","certificate-refresh"].includes(mode) || !Array.isArray(data.domains) || !Array.isArray(data.records))return false;
    const next=data.new_request;
    if(!next || Array.isArray(next) || Object.keys(next).sort().join(",")!=="available,closed_count,reason" || typeof next.available!=="boolean" || !Number.isSafeInteger(next.closed_count) || next.closed_count<0 || next.closed_count>32 || !["not-started","unknown-order","active","complete","expired","capacity","clock-unavailable"].includes(next.reason) || next.available!==["complete","expired"].includes(next.reason))return false;
    if(next.reason==="not-started" && data.state!=="not-started" || next.reason==="unknown-order" && !["request-pending","order-known"].includes(data.state))return false;
    const key=data.certificate_key;
    const issuance=data.issuance;
    if(!issuance || Array.isArray(issuance) || Object.keys(issuance).sort().join(",")!=="checked_at,expires,observation,started_at,state" || !["not-started","issuance-pending","not-issued","awaiting-certificate","issuance-failed","certificate-saved","saved-certificate-deleted"].includes(issuance.state))return false;
    if(issuance.state==="not-started") {if(issuance.started_at!=="" || issuance.checked_at!=="" || issuance.observation!=="" || issuance.expires!=="")return false;}
    else {
      if(data.state!=="domain-verified" || !date(issuance.started_at) || !date(issuance.expires) || issuance.expires>data.expires || issuance.expires<=issuance.started_at)return false;
      if(issuance.state==="issuance-pending") {if(issuance.checked_at!=="" || issuance.observation!=="")return false;}
      else if(!date(issuance.checked_at) || issuance.checked_at<issuance.started_at || issuance.checked_at>=issuance.expires ||
        !({"not-issued":["pending","ready"],"awaiting-certificate":["processing"],"issuance-failed":["invalid"],"certificate-saved":["saved"],"saved-certificate-deleted":["saved"]}[issuance.state]?.includes(issuance.observation)))return false;
      if(!key || key.prepared!==(issuance.state!=="saved-certificate-deleted"))return false;
    }
    if(!key || Array.isArray(key) || Object.keys(key).length!==3 || typeof key.prepared!=="boolean" || (key.prepared ? !validationStates.includes(data.state) || !date(key.prepared_at) || typeof key.fingerprint!=="string" || !/^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/.test(key.fingerprint) : key.fingerprint!=="" || key.prepared_at!==""))return false;
    if(data.can_issue!==(data.domain_verified && key.prepared && issuance.state==="not-started"))return false;
    if(next.reason==="complete" && !["certificate-saved","saved-certificate-deleted"].includes(issuance.state) || next.reason==="expired" && (!date(data.expires) || ["certificate-saved","saved-certificate-deleted"].includes(issuance.state)) || next.available && next.closed_count>=32)return false;
    if(issuance.state!=="not-started" && key.prepared && issuance.started_at<key.prepared_at)return false;
    if(data.state==="not-started")return data.domains.length===0 && data.records.length===0 && data.expires==="";
    if(data.domains.length<1 || data.domains.length>8 || !data.domains.every(domain) || new Set(data.domains).size!==data.domains.length || data.domains.some((n,i)=>i>0 && data.domains[i-1]>=n))return false;
    if(data.state==="request-pending" || data.state==="order-known")return data.expires==="" && data.records.length===0;
    return date(data.expires) && data.records.length===data.domains.length && data.records.every((r,i)=>r && Object.keys(r).length===4 && r.domain===data.domains[i] && r.name==="_acme-challenge."+r.domain.replace(/^\*\./,"") && typeof r.required==="boolean" && (r.required ? typeof r.value==="string" && /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(r.value) : r.value===""));
  };
  const choose=mode=>{
    action=mode;clearInputs();namesRow.hidden=mode!=="start";
    label.textContent=mode==="issue"?"Send the saved signed request for "+snapshot.domains.join(", ")+" to Let's Encrypt staging once; check and save the test certificate with its same private key on my Rootwell. The private key stays here.":mode==="certificate-refresh"?"Read the certificate result for "+snapshot.domains.join(", ")+" from the same staging request; never resend or create another request. Save only a checked matching test certificate.":mode==="prepare-key"?"Create and save one certificate key and signed request for these domains on my Rootwell — no CA connection or certificate yet":mode==="ack"?"I have added every required TXT value shown above. This is my acknowledgement, not CA verification.":mode==="validate"?"Ask Let's Encrypt staging to check the acknowledged DNS records for this saved request":mode==="refresh"?"Read the CA result for this same request — do not repeat validation or create another request":mode==="resume"?"Allow reading this same saved request from Let's Encrypt staging — no new request":"I control these domains and allow sending their names to Let's Encrypt staging";
    submit.textContent=mode==="issue"?"Get test certificate":mode==="certificate-refresh"?"Check certificate result":mode==="prepare-key"?"Prepare certificate key":mode==="ack"?"Save my acknowledgement":mode==="validate"?"Ask CA to check DNS":mode==="refresh"?"Refresh CA result":mode==="resume"?"Refresh the saved DNS request":"Get DNS records";
    if(mode==="close-request"){
      label.textContent="Keep my saved certificates, keys and notes. Close this old request locally so it can never resume; prepare for a separate new request. This does not cancel or revoke anything at the CA, and an expired request may still have an unknown CA outcome.";
      submit.textContent="Prepare a new request";
    }
    form.hidden=false;enable();
  };
  const render=data=>{
    snapshot=data;clearInputs();records.replaceChildren();records.hidden=true;resumeChoice.hidden=true;form.hidden=true;
    if(["clock-unavailable","capacity"].includes(data.new_request.reason)){
      status.textContent=data.new_request.reason==="clock-unavailable"?"The server clock moved backwards. A new request is blocked; correct the clock and check saved status again. Saved certificates and keys remain unchanged.":"The saved request history or storage write limit is reached. A new request is blocked; existing certificates and keys remain unchanged. Do not delete certificates to reset this limit.";
      if(data.issuance.state==="certificate-saved"){const link=document.createElement("a");link.href="/certificates";link.textContent="Open Certificates";records.append(link);records.hidden=false;}
      enable();return;
    }
    if(data.new_request.available){
      status.textContent=data.new_request.reason==="complete"?"This request is complete. Your saved certificates, private keys and notes will stay in Certificates. You can close this request and prepare a separate new one — nothing connects automatically.":"This request's saved deadline has expired. Its CA outcome may still be unknown. You can close it locally and prepare a separate new request; the old one will never be resent or resumed.";
      if(data.issuance.state==="saved-certificate-deleted")status.textContent="This request's saved certificate and key were removed. Other saved certificates and notes stay unchanged. You can close this old request and prepare a separate new one — nothing connects automatically.";
      const domains=document.createElement("p");domains.textContent="Previous domains: "+data.domains.join(", ");records.append(domains);records.hidden=false;
      if(data.issuance.state==="certificate-saved"){const link=document.createElement("a");link.href="/certificates";link.textContent="Open Certificates";records.append(link);}
      choose("close-request");return;
    }
    if(data.issuance.state!=="not-started") {
      status.textContent=data.issuance.state==="certificate-saved"?"Your test certificate and matching private key are saved in Certificates. This is test-only, not production trust or deployment. Make a new full backup.":data.issuance.state==="saved-certificate-deleted"?"The saved test certificate and key were removed from this store. This request stays closed; it will not create another key or certificate.":"Your certificate request has started, but no certificate is saved yet. Do not repeat DNS validation, prepare another key or resend this request. Check certificate result to read only the same request; nothing polls automatically.";
      if(data.issuance.state==="certificate-saved") {const link=document.createElement("a");link.href="/certificates";link.textContent="Open Certificates";records.append(link);records.hidden=false;}
      else if(data.issuance.state!=="saved-certificate-deleted") {
        if(usable())choose("certificate-refresh");
        else status.textContent+=" This saved request has expired; reading and replacement are blocked in this development version.";
      }
      enable();return;
    }
    if(data.state==="not-started"){
      status.textContent="No saved DNS request. Register your test account above first, then enter the domains you control. This contacts staging and saves one request.";choose("start");
    }else if(data.state==="request-pending"){
      status.textContent="The creation outcome is uncertain and no safe request address was saved. Automatic recreation and continuation are blocked. Keep this saved state and backup; reconciliation support is needed.";
    }else if(data.state==="order-known"){
      status.textContent="Your request was saved, but its DNS records were not confirmed. Continue the same request to read them — no new request is created.";choose("resume");
    }else{
      records.hidden=false;
      const heading=document.createElement("p");heading.textContent="Domains: "+data.domains.join(", ")+" · Use before "+data.expires;records.append(heading);
      for(const r of data.certificate_key.prepared?[]:data.records){
        const card=document.createElement("div");card.className="storage-note";
        for(const line of r.required?["Domain: "+r.domain,"Type: TXT","Name: "+r.name,"Value: "+r.value]:["Domain: "+r.domain,"No TXT required in this response: the CA returned an existing valid authorization."]){const text=document.createElement("p");text.textContent=line;card.append(text);}
        records.append(card);
      }
      resumeChoice.hidden=validationStates.includes(data.state);
      if(!usable())status.textContent=validationStates.includes(data.state)?"This saved CA check has expired. It no longer confirms domain verification. Keep your saved state and backup; CA refresh and replacement are unavailable in this development version.":"These saved instructions have expired. Do not use or acknowledge them. You may read the same request again; no replacement request is created.";
      else if(data.state==="dns-acknowledged"){status.textContent="Your acknowledgement is saved encrypted. CA verification has not been requested. No certificate was issued. Allow the CA check below when your DNS records are ready.";choose("validate");}
      else if(validationStates.includes(data.state)){
        status.textContent=data.state==="validation-pending"?"The validation outcome is not confirmed. Only read the same request's CA result; validation will not be repeated. Some challenges may not have been sent.":data.state==="validation-failed"?"The CA did not approve this request. Keep your saved state; automatic retry and replacement are blocked. You can refresh the CA result.":data.state==="domain-verified" && data.domain_verified?"The CA confirmed every domain and marked this request ready. No certificate was issued yet. Make a new complete backup.":"CA verification is not yet confirmed complete. Refresh the CA result later; no automatic polling or repeat validation.";
        if(data.certificate_key.prepared){status.textContent="Your domains are confirmed and your certificate key and signed request are saved encrypted. Next: get your test certificate. The private key stays on Rootwell; no certificate has been requested or issued yet.";}
        choose(data.can_issue?"issue":data.state==="domain-verified" && data.domain_verified && !data.certificate_key.prepared?"prepare-key":"refresh");
      }
      else{status.textContent="Add every required TXT value in your DNS provider, then acknowledge below. If Names repeat, keep both Values. No DNS changes are made by Rootwell.";choose("ack");}
    }
    enable();
  };
  const read=async(response,current,controller)=>{
    if(response.status!==200 || response.headers.get("cache-control")!=="no-store" || response.headers.get("content-type")?.split(";")[0].trim().toLowerCase()!=="application/json" || !response.body)throw new Error();
    const reader=response.body.getReader(),decoder=new TextDecoder("utf-8",{fatal:true});let text="",size=0;
    try{while(true){const {value,done}=await reader.read();if(current!==generation || document.hidden || controller.signal.aborted)throw new Error();if(done)break;if(!value || value.byteLength===0)throw new Error();size+=value.byteLength;if(size>8192)throw new Error();text+=decoder.decode(value,{stream:true});}text+=decoder.decode();}
    finally{void reader.cancel().catch(()=>{});reader.releaseLock();}
    const data=JSON.parse(text);if(JSON.stringify(data)!==text.trim())throw new Error();return data;
  };
  const run=async mode=>{
    if(active || document.hidden || el("acme-provider").value!=="letsencrypt-staging")return;
    if(["ack","validate","refresh","prepare-key","issue","certificate-refresh"].includes(mode) && !usable()){status.textContent="This saved request has expired. Check saved status; do not use stale records or verification.";enable();return;}
    if(mode!=="status" && (submit.disabled || !snapshot || !consent.checked || !password.value))return;
    const expected=snapshot?.generation,original=snapshot?.domains?.slice(),originalRecords=JSON.stringify(snapshot?.records),originalExpiry=snapshot?.expires,originalKey=JSON.stringify(snapshot?.certificate_key),originalIssuance=snapshot?.issuance,closedCount=snapshot?.new_request.closed_count,requested=suppliedNames();
    const input={provider:"letsencrypt-staging"};if(mode!=="status"){input.confirm=true;input.expected_generation=expected;input.password=password.value;}if(mode==="start")input.domains=requested;
    const current=++generation,controller=new AbortController();active=controller;snapshot=null;clearInputs();records.hidden=true;records.replaceChildren();form.hidden=true;resumeChoice.hidden=true;enable();
    status.textContent=mode==="issue"?"Requesting your test certificate once, then checking it before saving… The private key stays on Rootwell.":mode==="certificate-refresh"?"Reading the same certificate result — no resend, new request or automatic polling…":mode==="prepare-key"?"Preparing and saving your certificate key locally — no provider connection…":mode==="status"?"Reading your saved DNS request…":mode==="ack"?"Saving your acknowledgement locally — no provider connection…":mode==="validate"?"Asking staging to check the acknowledged DNS records…":mode==="refresh"?"Reading the same request's CA result — no repeat validation…":"Reading DNS records from staging… The account private key stays on Rootwell.";
    if(mode==="close-request")status.textContent="Closing only the old request locally — saved certificates and keys stay unchanged. No CA connection…";
    let timer;
    const deadline=new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(new Error());},30000);});
    try{
      const work=(async()=>{
        const options={method:"POST",credentials:"same-origin",cache:"no-store",redirect:"error",signal:controller.signal,headers:{"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify(input)};
        input.password="";const pending=fetch("/api/acme/order/"+mode,options);options.body="";
        const response=await pending;return read(response,current,controller);
      })();
      const data=await Promise.race([work,deadline]);
      if(current!==generation || document.hidden || controller.signal.aborted)return;
      if(mode==="close-request"){
        if(!valid(data,mode) || data.generation!==expected+1 || data.state!=="not-started" || data.certificate_key.prepared || data.issuance.state!=="not-started" || data.new_request.closed_count!==closedCount+1 || data.new_request.reason!=="not-started")throw new Error();
        names.value="";render(data);status.textContent="Old request closed locally. Your saved certificates, keys and notes are unchanged. Enter the domains for a new request below; sending them to staging requires new consent and your password. Make a new full backup.";return;
      }
      const certificateMode=["issue","certificate-refresh"].includes(mode);
      const expectedStates=certificateMode || mode==="prepare-key"?["domain-verified"]:["validate","refresh"].includes(mode)?["validation-waiting","validation-failed","domain-verified"]:[mode==="ack"?"dns-acknowledged":"dns-ready"];
      if(!valid(data,mode) || mode!=="status" && (data.generation<=expected || data.domains.join("\n")!==(mode==="start"?requested:original).join("\n") || !expectedStates.includes(data.state)))throw new Error();
      if(mode!=="status" && data.new_request.closed_count!==closedCount)throw new Error();
      if(["validate","refresh"].includes(mode) && (JSON.stringify(data.records)!==originalRecords || data.expires>originalExpiry))throw new Error();
      if(mode==="prepare-key" && (!data.certificate_key.prepared || !data.domain_verified || JSON.stringify(data.records)!==originalRecords || data.expires!==originalExpiry || data.generation!==expected+1))throw new Error();
      if(certificateMode && (JSON.stringify(data.records)!==originalRecords || data.expires!==originalExpiry || !data.domain_verified || !["awaiting-certificate","certificate-saved",...(mode==="certificate-refresh"?["not-issued","issuance-failed"]:[])].includes(data.issuance.state) || data.generation!==expected+(mode==="issue"?2:1)))throw new Error();
      if(mode==="certificate-refresh" && (data.issuance.started_at!==originalIssuance.started_at || data.issuance.expires>originalIssuance.expires))throw new Error();
      if(mode!=="status" && mode!=="prepare-key" && JSON.stringify(data.certificate_key)!==originalKey)throw new Error();
      render(data);
    }catch{if(current===generation){snapshot=null;status.textContent=uncertain+" Linux or Linux Docker, a ready session and your current password are required. If limited, wait before checking again.";}}
    finally{input.password="";clearTimeout(timer);if(active===controller)active=null;enable();}
  };
  refresh.addEventListener("click",()=>run("status"));
  form.addEventListener("submit",event=>{event.preventDefault();return run(action);});
  resumeChoice.addEventListener("click",()=>{if(!active && snapshot && ["order-known","dns-ready","dns-acknowledged"].includes(snapshot.state)){choose("resume");resumeChoice.hidden=true;}});
  names.addEventListener("input",()=>{if(active)invalidate();else{clearInputs();enable();}});
  for(const field of [password,consent])field.addEventListener(field===consent?"change":"input",()=>{if(active)invalidate();else enable();});
  el("acme-provider").addEventListener("change",invalidate);el("acme-clear").addEventListener("click",()=>{names.value="";invalidate();});
  document.addEventListener("visibilitychange",()=>{if(document.hidden)invalidate();});window.addEventListener("pagehide",invalidate);enable();
})();
