(() => {
  "use strict";
  const el = id => document.getElementById(id);
  const form=el("dns-config-form"), refresh=el("dns-config-refresh"), button=el("dns-config-submit"), action=el("dns-config-action");
  const zone=el("dns-config-zone"), zoneID=el("dns-config-zone-id"), token=el("dns-config-token"), password=el("dns-config-password"), consent=el("dns-config-consent"), status=el("dns-config-status");
  let snapshot=null, active=null, generation=0;
  const zoneValid = value => typeof value === "string" && value.length<=253 && value.includes(".") && value.split(".").every(p=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(p)) && !/\.(local|localhost|internal|invalid|test|example)$/.test(value);
  const wipe = () => { token.value=""; password.value=""; consent.checked=false; zoneID.value=""; zone.value=""; };
  const enable = () => {
    const removing=action.value==="remove";
    button.disabled=!!active || document.hidden || !snapshot?.can_change || !password.value || !consent.checked ||
      (removing ? snapshot.state!=="saved" : !zoneValid(zone.value) || !/^[0-9a-f]{32}$/.test(zoneID.value) || !/^[A-Za-z0-9_-]{40,256}$/.test(token.value));
  };
  const mode = () => {
    const removing=action.value==="remove";
    el("dns-config-fields").hidden=removing;
    button.textContent=removing ? "Remove saved token" : snapshot?.state==="saved" ? "Replace encrypted settings" : "Save encrypted settings";
    el("dns-config-consent-label").textContent=removing ? "Remove this token from my current Rootwell store" : snapshot?.state==="saved" ? "Replace my existing saved DNS settings with these values" : "Save these DNS settings encrypted on my Rootwell";
    el("dns-config-change-help").textContent=removing ? "This removes the local credential, not provider DNS records. It does not revoke the token in Cloudflare or erase old backups." : "Only local settings are saved. Existing certificate keys and notes stay unchanged.";
    enable();
  };
  const reset = () => {
    ++generation; active?.abort(); active=null; snapshot=null; wipe(); action.value="save";
    form.hidden=true; refresh.disabled=false; el("dns-config-remove-option").disabled=true;
    status.textContent="Settings not checked. Check saved settings before making a change."; mode();
  };
  const render = data => {
    snapshot=data; form.hidden=!data.can_change; action.value="save";
    el("dns-config-remove-option").disabled=data.state!=="saved";
    status.textContent=data.state==="saved" ? "Token saved encrypted for "+data.zone_name+". Saved: "+data.saved_at+". Not yet checked with Cloudflare. "+(data.can_change ? "Make a new complete backup after changes." : "Close your saved certificate request before changing these settings.") : "No Cloudflare token saved. Manual DNS is available; these settings are optional.";
    mode();
  };
  const read = async (response, current, controller) => {
    if(response.status!==200 || response.headers.get("cache-control")!=="no-store" || response.headers.get("content-type")?.split(";")[0].trim().toLowerCase()!=="application/json" || !response.body) throw new Error();
    const reader=response.body.getReader(), decoder=new TextDecoder("utf-8",{fatal:true}); let text="", size=0;
    try {
      while(true) {
        const {value,done}=await reader.read(); if(done) break;
        size+=value.byteLength; if(size>4096 || current!==generation || document.hidden || controller.signal.aborted) throw new Error();
        text+=decoder.decode(value,{stream:true});
      }
      text+=decoder.decode();
    } finally { await reader.cancel(); reader.releaseLock(); }
    const data=JSON.parse(text), date=data?.saved_at;
    if(!data || Array.isArray(data) || Object.keys(data).length!==10 || data.schema_version!=="rootwell.dns.config.v1" || data.provider!=="cloudflare" ||
       !Number.isSafeInteger(data.generation) || data.generation<1 || data.generation>1000000 || typeof data.can_change!=="boolean" ||
       data.network_used!==false || data.token_verified!==false || data.dns_changed!==false ||
       !(data.state==="not-configured" && data.zone_name==="" && date==="" && data.can_change===true ||
         data.state==="saved" && data.generation>=2 && zoneValid(data.zone_name) && typeof date==="string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(date) && Number.isFinite(Date.parse(date)) &&
         new Date(date).getUTCFullYear()>=2020 && new Date(date).getUTCFullYear()<=2100 && new Date(date).toISOString()===date.replace("Z",".000Z"))) throw new Error();
    return data;
  };
  const run = async change => {
    if(active || document.hidden) return;
    enable(); if(change && button.disabled) return;
    const selected=change?action.value:"status", expected=snapshot?.generation;
    const input=change ? {provider:"cloudflare",password:password.value,expected_generation:expected,confirm:true} : {provider:"cloudflare"};
    if(selected==="save") { input.zone_id=zoneID.value; input.zone_name=zone.value; input.token=token.value; }
    const current=++generation, controller=new AbortController(); active=controller; snapshot=null; wipe(); form.hidden=true; refresh.disabled=true; button.disabled=true;
    const uncertain="Settings could not be confirmed. Check saved settings before retrying; a change may already have been saved.";
    status.textContent=change?"Updating encrypted local settings… No Cloudflare connection.":"Reading local saved settings…";
    const started=Date.now();
    const timer=setTimeout(()=>{if(current===generation){reset();status.textContent=uncertain;}},15000);
    try {
      const request={method:"POST",credentials:"same-origin",cache:"no-store",redirect:"error",signal:controller.signal,
        headers:{"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify(input)};
      input.password=""; input.token="";
      const pending=fetch("/api/dns/cloudflare/"+selected,request); request.body="";
      const response=await pending;
      if(current!==generation || document.hidden || controller.signal.aborted || Date.now()-started<0 || Date.now()-started>=15000) throw new Error();
      if(response.status===401 || response.status===403) { status.textContent="Password or session not accepted. Sign in if needed, then check saved settings."; return; }
      if(response.status===429) { status.textContent="Too many password attempts. Wait one minute, then check saved settings."; return; }
      if(response.status===409) { status.textContent="The store changed, is not initialized, or a saved request blocks this change. Check saved settings; close the request before replacing or removing an existing token."; return; }
      if(response.status===503) { status.textContent="Storage unavailable or outcome uncertain. DNS credential storage requires Linux or Linux Docker. Check saved settings before retrying."; return; }
      const data=await read(response,current,controller);
      if(change && (data.generation!==expected+1 || data.state!==(selected==="remove"?"not-configured":"saved"))) throw new Error();
      if(current!==generation || document.hidden || controller.signal.aborted || Date.now()-started<0 || Date.now()-started>=15000) throw new Error();
      render(data);
    } catch { if(current===generation && !document.hidden) status.textContent=uncertain; }
    finally { input.password="";input.token="";clearTimeout(timer); if(current===generation){active=null;wipe();refresh.disabled=false;enable();} }
  };
  refresh.addEventListener("click",()=>run(false)); form.addEventListener("submit",event=>{event.preventDefault();return run(true);});
  for(const input of [zone,zoneID,token,password]) input.addEventListener("input",()=>{if(active)reset();enable();});
  consent.addEventListener("change",()=>{if(active)reset();enable();});
  action.addEventListener("change",()=>{if(active)reset();token.value="";password.value="";consent.checked=false;mode();});
  el("acme-clear").addEventListener("click",reset); el("acme-provider").addEventListener("change",reset);
  document.addEventListener("visibilitychange",()=>{if(document.hidden)reset();}); window.addEventListener("pagehide",reset);
  window.addEventListener("rootwell-dns-changed",reset);
  reset();
})();
