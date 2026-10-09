(() => {
  "use strict";
  const el = id => document.getElementById(id);
  const refresh=el("acme-registration-refresh"), controls=el("acme-registration-controls"), previewButton=el("acme-registration-preview"), status=el("acme-registration-status");
  const network=el("acme-registration-network"), terms=el("acme-registration-terms"), link=el("acme-registration-link"), form=el("acme-registration-form"), agreement=el("acme-registration-agreement");
  const agree=el("acme-registration-agree"), password=el("acme-registration-password"), submit=el("acme-registration-submit"), help=el("acme-registration-action-help");
  let snapshot=null, preview=null, active=null, generation=0, expiryTimer=null;
  const fingerprint=/^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/;
  const date=value=>typeof value==="string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).getUTCFullYear()>=2020 && new Date(value).toISOString()===value.replace("Z",".000Z");
  const termsURL=value=>typeof value==="string" && value.length<=1024 && /^https:\/\/letsencrypt\.org\/documents\/[A-Za-z0-9_-][A-Za-z0-9_.-]*$/.test(value) && !value.includes("..");
  const enable=()=>{
    const pending=snapshot?.registration_state==="registration-pending";
    previewButton.hidden=pending; previewButton.disabled=!!active || snapshot?.registration_state!=="not-registered" || !network.checked || document.hidden;
    submit.disabled=!!active || !network.checked || !password.value || document.hidden || !(pending || snapshot?.registration_state==="not-registered" && preview && Date.now()<Date.parse(preview.expires_at) && agree.checked);
  };
  const clearPreview=()=>{preview=null;clearTimeout(expiryTimer);expiryTimer=null;terms.hidden=true;link.removeAttribute("href");agree.checked=false;password.value="";};
  const reset=()=>{
    generation++;active?.abort();active=null;snapshot=null;clearPreview();network.checked=false;network.disabled=false;refresh.disabled=false;
    controls.hidden=true;form.hidden=true;status.textContent="Check saved registration status before proceeding.";enable();
  };
  const render=data=>{
    snapshot=data;clearPreview();network.checked=false;
    const pending=data.registration_state==="registration-pending";
    controls.hidden=!data.saved || data.registration_state==="registered";form.hidden=!pending;agreement.hidden=pending;
    submit.textContent=pending?"Check existing account":"Register test account";
    help.textContent=pending?"Only checks for an existing account with this same key. It does not create an account or accept new terms.":"The saved key will not be replaced. Refresh status after an interrupted request before trying anything else.";
    status.textContent=!data.saved?"Prepare and save your test account key above first.":data.registration_state==="registered"?"Test account registered and saved encrypted. Make a new complete backup. Certificate requests are not enabled yet.":pending?"Registration outcome is not confirmed. Check the existing account using the same saved key; do not create a new key or blindly register again.":"Saved key is ready. Allow a staging connection to see current provider terms before registering.";
    enable();
  };
  const read=async(response,current,controller)=>{
    if(!response.ok || response.headers.get("cache-control")!=="no-store" || response.headers.get("content-type")?.split(";")[0].trim().toLowerCase()!=="application/json" || !response.body)throw new Error();
    const reader=response.body.getReader(), decoder=new TextDecoder("utf-8",{fatal:true});let text="",size=0;
    try{while(true){const {value,done}=await reader.read();if(done)break;size+=value.byteLength;if(size>4096 || current!==generation || document.hidden || controller.signal.aborted)throw new Error();text+=decoder.decode(value,{stream:true});}text+=decoder.decode();}
    finally{await reader.cancel();reader.releaseLock();}
    const data=JSON.parse(text);if(!data || Array.isArray(data) || JSON.stringify(data)!==text.trim() || data.provider!=="letsencrypt-staging" || data.can_issue!==false || !Number.isSafeInteger(data.generation) || data.generation<1 || data.generation>1000000)throw new Error();return data;
  };
  const validSaved=data=>Object.keys(data).length===12 && data.schema_version==="rootwell.acme.account-key.v1" && data.network_used===false && ["not-registered","registration-pending","registered"].includes(data.registration_state) && data.account_created===(data.registration_state==="registered") && data.terms_accepted===(data.registration_state==="registered") && (data.state==="not-prepared" && data.registration_state==="not-registered" && data.saved===false && data.fingerprint==="" && data.prepared_at==="" || data.state==="key-prepared" && data.saved===true && data.generation>=2 && fingerprint.test(data.fingerprint) && date(data.prepared_at));
  const run=async mode=>{
    if(active || document.hidden || el("acme-provider").value!=="letsencrypt-staging")return;
    if(mode!=="status" && (!snapshot?.saved || !network.checked))return;
    if(mode==="preview" && snapshot.registration_state!=="not-registered")return;
    if(mode==="register" && (snapshot.registration_state!=="not-registered" || !preview || !agree.checked || !password.value || Date.now()>=Date.parse(preview.expires_at)))return;
    if(mode==="reconcile" && (snapshot.registration_state!=="registration-pending" || !password.value))return;
    const expected=snapshot?.generation, originalFingerprint=snapshot?.fingerprint;
    const input={provider:"letsencrypt-staging"};if(mode!=="status"){input.confirm=true;input.expected_generation=expected;}
    if(mode==="register" || mode==="reconcile")input.password=password.value;
    if(mode==="register"){input.preview=preview.preview;input.terms_agreed=true;}
    const current=++generation, controller=new AbortController();active=controller;
    snapshot=null;clearPreview();network.checked=false;network.disabled=true;refresh.disabled=true;controls.hidden=true;form.hidden=true;enable();
    const uncertain="Outcome could not be confirmed. Refresh saved registration status first; if pending, check the existing account with the same key.";
    status.textContent=mode==="status"?"Reading local registration status…":mode==="preview"?"Checking the current provider terms link… Nothing is registered.":mode==="reconcile"?"Checking for an existing account with the same saved key…":"Registering your test account… The private key stays on Rootwell.";
    const timer=setTimeout(()=>{if(current===generation){reset();status.textContent=uncertain;}},15000);
    try{
      const request={method:"POST",credentials:"same-origin",cache:"no-store",redirect:"error",signal:controller.signal,headers:{"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify(input)};
      input.password="";input.preview="";
      const pending=fetch(mode==="status"?"/api/acme/account/status":"/api/acme/registration/"+mode,request);request.body="";
      const response=await pending;if(current!==generation || document.hidden || controller.signal.aborted)return;
      if(response.status===401 || response.status===403){status.textContent="Password or session not accepted. Sign in if needed, then refresh status.";return;}
      if(response.status===429){status.textContent="Operation limited. Wait before checking again; refresh saved status first.";return;}
      if(response.status===409){status.textContent="Saved status or provider preview changed. Refresh status and confirm current terms again.";return;}
      if(response.status===503){status.textContent="Storage unavailable or outcome uncertain. Linux or Linux Docker is required. Refresh saved status before retrying.";return;}
      const data=await read(response,current,controller);if(response.status!==200)throw new Error();
      if(mode==="status"){if(!validSaved(data))throw new Error();render(data);}
      else if(mode==="preview"){
        if(Object.keys(data).length!==9 || data.schema_version!=="rootwell.acme.registration-preview.v1" || data.generation!==expected || data.fingerprint!==originalFingerprint || data.network_used!==true || !termsURL(data.terms_url) || typeof data.preview!=="string" || !/^[A-Za-z0-9_-]{43}$/.test(data.preview) || !date(data.expires_at) || Date.parse(data.expires_at)<=Date.now() || Date.parse(data.expires_at)>Date.now()+301000)throw new Error();
        snapshot={saved:true,registration_state:"not-registered",generation:expected,fingerprint:originalFingerprint};preview=data;
        controls.hidden=false;form.hidden=false;agreement.hidden=false;terms.hidden=false;link.href=data.terms_url;
        network.checked=false;status.textContent="Current terms link checked. Read it, explicitly agree, allow registration and enter your Rootwell password. This preview expires in five minutes.";
        expiryTimer=setTimeout(()=>{reset();status.textContent="Provider preview expired. Check saved status and current terms again.";},Math.max(1,Date.parse(data.expires_at)-Date.now()));
      }else{
        if(Object.keys(data).length!==8 || data.schema_version!=="rootwell.acme.registration.v1" || data.network_used!==true || data.saved!==true || data.fingerprint!==originalFingerprint || data.generation!==expected+(mode==="register"?2:1) || !["registered","not-registered"].includes(data.state) || mode==="register" && data.state!=="registered")throw new Error();
        status.textContent=data.state==="registered"?"Test account registered and saved encrypted. Make a new complete backup. Certificate requests are not enabled yet.":"The provider confirmed no account for this key. The key is unchanged. Make a new complete backup, then refresh status and current terms before registering.";
      }
    }catch{if(current===generation && !document.hidden)status.textContent=uncertain;}
    finally{input.password="";input.preview="";clearTimeout(timer);if(current===generation){active=null;network.disabled=false;refresh.disabled=false;password.value="";enable();}}
  };
  refresh.addEventListener("click",()=>run("status"));previewButton.addEventListener("click",()=>run("preview"));
  form.addEventListener("submit",event=>{event.preventDefault();return run(snapshot?.registration_state==="registration-pending"?"reconcile":"register");});
  for(const [control,event] of [[password,"input"],[network,"change"],[agree,"change"]])control.addEventListener(event,()=>{if(active)reset();enable();});
  el("acme-provider").addEventListener("change",reset);el("acme-clear").addEventListener("click",reset);
  document.addEventListener("visibilitychange",()=>{if(document.hidden)reset();});window.addEventListener("pagehide",reset);
  reset();
})();
