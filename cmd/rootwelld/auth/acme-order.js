(() => {
  "use strict";
  const el=id=>document.getElementById(id), refresh=el("acme-order-refresh"), status=el("acme-order-status"), form=el("acme-order-form"), names=el("acme-order-domains");
  const namesRow=el("acme-order-names-row"), consent=el("acme-order-consent"), label=el("acme-order-consent-label"), password=el("acme-order-password"), submit=el("acme-order-submit"), records=el("acme-order-records"), resumeChoice=el("acme-order-resume-choice");
  let snapshot=null, active=null, generation=0, action="start";
  const uncertain="Outcome not confirmed. Check saved DNS request first. Do not create another request; continue only the saved one.";
  const date=value=>typeof value==="string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).getUTCFullYear()>=2020 && new Date(value).toISOString()===value.replace("Z",".000Z");
  const domain=value=>typeof value==="string" && value.length<=255 && /^(?:\*\.)?[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(value) && value.includes(".") && !value.includes("..");
  const suppliedNames=()=>names.value.split(/\r?\n/).map(n=>n.trim().toLowerCase()).filter(Boolean).sort();
  const usable=()=>snapshot && date(snapshot.expires) && Date.now()<Date.parse(snapshot.expires);
  const validationStates=["validation-pending","validation-waiting","validation-failed","domain-verified"];
  const allowedAction=()=>snapshot && (action==="start" ? snapshot.state==="not-started" : action==="ack" ? snapshot.state==="dns-ready" && usable() : action==="validate" ? snapshot.state==="dns-acknowledged" && usable() : action==="prepare-key" ? snapshot.state==="domain-verified" && snapshot.domain_verified && !snapshot.certificate_key.prepared && usable() : action==="refresh" ? validationStates.includes(snapshot.state) && usable() : ["order-known","dns-ready","dns-acknowledged"].includes(snapshot.state));
  const enable=()=>{
    refresh.disabled=!!active; names.disabled=!!active; consent.disabled=!!active; password.disabled=!!active; resumeChoice.disabled=!!active;
    submit.disabled=!!active || document.hidden || !allowedAction() || !consent.checked || !password.value || (action==="start" && !suppliedNames().length);
  };
  const clearInputs=()=>{password.value="";consent.checked=false;};
  const invalidate=()=>{
    generation++;active?.abort();snapshot=null;clearInputs();form.hidden=true;records.hidden=true;records.replaceChildren();resumeChoice.hidden=true;status.textContent=uncertain;enable();
  };
  const valid=(data,mode)=>{
    if(!data || Array.isArray(data) || Object.keys(data).length!==12 || data.schema_version!=="rootwell.acme.manual-dns.v3" || data.provider!=="letsencrypt-staging" || data.can_issue!==false || typeof data.domain_verified!=="boolean" || data.domain_verified && data.state!=="domain-verified" || !Number.isSafeInteger(data.generation) || data.generation<1 || data.generation>1000000 || !["not-started","request-pending","order-known","dns-ready","dns-acknowledged",...validationStates].includes(data.state) || data.saved!==(data.state!=="not-started") || data.network_used!==["start","resume","validate","refresh"].includes(mode) || !Array.isArray(data.domains) || !Array.isArray(data.records))return false;
    const key=data.certificate_key;
    if(!key || Array.isArray(key) || Object.keys(key).length!==3 || typeof key.prepared!=="boolean" || (key.prepared ? !validationStates.includes(data.state) || !date(key.prepared_at) || typeof key.fingerprint!=="string" || !/^(?:[A-F0-9]{2}:){31}[A-F0-9]{2}$/.test(key.fingerprint) : key.fingerprint!=="" || key.prepared_at!==""))return false;
    if(data.state==="not-started")return data.domains.length===0 && data.records.length===0 && data.expires==="";
    if(data.domains.length<1 || data.domains.length>8 || !data.domains.every(domain) || new Set(data.domains).size!==data.domains.length || data.domains.some((n,i)=>i>0 && data.domains[i-1]>=n))return false;
    if(data.state==="request-pending" || data.state==="order-known")return data.expires==="" && data.records.length===0;
    return date(data.expires) && data.records.length===data.domains.length && data.records.every((r,i)=>r && Object.keys(r).length===4 && r.domain===data.domains[i] && r.name==="_acme-challenge."+r.domain.replace(/^\*\./,"") && typeof r.required==="boolean" && (r.required ? typeof r.value==="string" && /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(r.value) : r.value===""));
  };
  const choose=mode=>{
    action=mode;clearInputs();namesRow.hidden=mode!=="start";
    label.textContent=mode==="prepare-key"?"Create and save one certificate key and signed request for these domains on my Rootwell — no CA connection or certificate yet":mode==="ack"?"I have added every required TXT value shown above. This is my acknowledgement, not CA verification.":mode==="validate"?"Ask Let's Encrypt staging to check the acknowledged DNS records for this saved request":mode==="refresh"?"Read the CA result for this same request — do not repeat validation or create another request":mode==="resume"?"Allow reading this same saved request from Let's Encrypt staging — no new request":"I control these domains and allow sending their names to Let's Encrypt staging";
    submit.textContent=mode==="prepare-key"?"Prepare certificate key":mode==="ack"?"Save my acknowledgement":mode==="validate"?"Ask CA to check DNS":mode==="refresh"?"Refresh CA result":mode==="resume"?"Refresh the saved DNS request":"Get DNS records";
    form.hidden=false;enable();
  };
  const render=data=>{
    snapshot=data;clearInputs();records.replaceChildren();records.hidden=true;resumeChoice.hidden=true;form.hidden=true;
    if(data.state==="not-started"){
      status.textContent="No saved DNS request. Register your test account above first, then enter the domains you control. This contacts staging and saves one request.";choose("start");
    }else if(data.state==="request-pending"){
      status.textContent="The creation outcome is uncertain and no safe request address was saved. Automatic recreation and continuation are blocked. Keep this saved state and backup; reconciliation support is needed.";
    }else if(data.state==="order-known"){
      status.textContent="Your request was saved, but its DNS records were not confirmed. Continue the same request to read them — no new request is created.";choose("resume");
    }else{
      records.hidden=false;
      const heading=document.createElement("p");heading.textContent="Domains: "+data.domains.join(", ")+" · Use before "+data.expires;records.append(heading);
      for(const r of data.records){
        const card=document.createElement("div");card.className="storage-note";
        for(const line of r.required?["Domain: "+r.domain,"Type: TXT","Name: "+r.name,"Value: "+r.value]:["Domain: "+r.domain,"No TXT required in this response: the CA returned an existing valid authorization."]){const text=document.createElement("p");text.textContent=line;card.append(text);}
        records.append(card);
      }
      resumeChoice.hidden=validationStates.includes(data.state);
      if(!usable())status.textContent=validationStates.includes(data.state)?"This saved CA check has expired. It no longer confirms domain verification. Keep your saved state and backup; CA refresh and replacement are unavailable in this development version.":"These saved instructions have expired. Do not use or acknowledge them. You may read the same request again; no replacement request is created.";
      else if(data.state==="dns-acknowledged"){status.textContent="Your acknowledgement is saved encrypted. CA verification has not been requested. No certificate was issued. Allow the CA check below when your DNS records are ready.";choose("validate");}
      else if(validationStates.includes(data.state)){
        status.textContent=data.state==="validation-pending"?"The validation outcome is not confirmed. Only read the same request's CA result; validation will not be repeated. Some challenges may not have been sent.":data.state==="validation-failed"?"The CA did not approve this request. Keep your saved state; automatic retry and replacement are blocked. You can refresh the CA result.":data.state==="domain-verified" && data.domain_verified?"The CA confirmed every domain and marked this request ready. No certificate was issued yet. Make a new complete backup.":"CA verification is not yet confirmed complete. Refresh the CA result later; no automatic polling or repeat validation.";
        if(data.certificate_key.prepared){status.textContent+=" Your certificate key and signed request are saved encrypted. No certificate has been requested or issued. Keep the same key and make a new complete backup.";}
        choose(data.state==="domain-verified" && data.domain_verified && !data.certificate_key.prepared?"prepare-key":"refresh");
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
    if(["ack","validate","refresh","prepare-key"].includes(mode) && !usable()){status.textContent="This saved request has expired. Check saved status; do not use stale records or verification.";enable();return;}
    if(mode!=="status" && (submit.disabled || !snapshot || !consent.checked || !password.value))return;
    const expected=snapshot?.generation,original=snapshot?.domains?.slice(),originalRecords=JSON.stringify(snapshot?.records),originalExpiry=snapshot?.expires,originalKey=JSON.stringify(snapshot?.certificate_key),requested=suppliedNames();
    const input={provider:"letsencrypt-staging"};if(mode!=="status"){input.confirm=true;input.expected_generation=expected;input.password=password.value;}if(mode==="start")input.domains=requested;
    const current=++generation,controller=new AbortController();active=controller;snapshot=null;clearInputs();records.hidden=true;records.replaceChildren();form.hidden=true;resumeChoice.hidden=true;enable();
    status.textContent=mode==="prepare-key"?"Preparing and saving your certificate key locally — no provider connection…":mode==="status"?"Reading your saved DNS request…":mode==="ack"?"Saving your acknowledgement locally — no provider connection…":mode==="validate"?"Asking staging to check the acknowledged DNS records…":mode==="refresh"?"Reading the same request's CA result — no repeat validation…":"Reading DNS records from staging… The account private key stays on Rootwell.";
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
      const expectedStates=mode==="prepare-key"?["domain-verified"]:["validate","refresh"].includes(mode)?["validation-waiting","validation-failed","domain-verified"]:[mode==="ack"?"dns-acknowledged":"dns-ready"];
      if(!valid(data,mode) || mode!=="status" && (data.generation<=expected || data.domains.join("\n")!==(mode==="start"?requested:original).join("\n") || !expectedStates.includes(data.state)))throw new Error();
      if(["validate","refresh"].includes(mode) && (JSON.stringify(data.records)!==originalRecords || data.expires>originalExpiry))throw new Error();
      if(mode==="prepare-key" && (!data.certificate_key.prepared || !data.domain_verified || JSON.stringify(data.records)!==originalRecords || data.expires!==originalExpiry || data.generation!==expected+1))throw new Error();
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
