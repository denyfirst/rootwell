(() => {
  "use strict";
  const el=id=>document.getElementById(id), refresh=el("dns-operation-refresh"), status=el("dns-operation-status"), rows=el("dns-operation-records"), form=el("dns-operation-form"), select=el("dns-operation-domain"), password=el("dns-operation-password"), consent=el("dns-operation-consent"), exclusive=el("dns-operation-exclusive"), button=el("dns-operation-submit");
  const uncertain="DNS outcome not confirmed. Read saved DNS status first; do not repeat a create or deletion. A sent operation cannot be undone.";
  let snapshot=null, active=null, generation=0, received=0;
  const wipe=()=>{password.value="";consent.checked=false;exclusive.checked=false;};
  const date=v=>typeof v==="string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(v) && Number.isFinite(Date.parse(v)) && new Date(v).getUTCFullYear()>=2020 && new Date(v).getUTCFullYear()<=2100 && new Date(v).toISOString()===v.replace("Z",".000Z");
  const domain=v=>typeof v==="string" && v.length<=255 && v.replace(/^\*\./,"").includes(".") && v.replace(/^\*\./,"").split(".").every(p=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(p));
  const keys=(v,n)=>v && !Array.isArray(v) && Object.keys(v).sort().join(",")===n.split(",").sort().join(",");
  const validate=(d,mode)=>{
    if(!keys(d,"schema_version,provider,generation,network_used,zone_name,server_time,can_prepare,pending_domains,prepared,prepared_at,expires,records") || d.schema_version!=="rootwell.dns.operation.v1" || d.provider!=="cloudflare" || !Number.isSafeInteger(d.generation) || d.generation<1 || d.generation>1000000 || d.network_used!==(mode!=="status") || !date(d.server_time) || typeof d.can_prepare!=="boolean" || typeof d.prepared!=="boolean" || typeof d.zone_name!=="string" || d.zone_name!=="" && (!domain(d.zone_name) || d.zone_name.startsWith("*.")) || !Array.isArray(d.records) || d.records.length>8 || !Array.isArray(d.pending_domains) || d.pending_domains.length>8 || !d.pending_domains.every(domain) || d.pending_domains.some((n,i)=>i>0&&d.pending_domains[i-1]>=n)) throw new Error();
    if(!d.prepared){if(d.prepared_at!=="" || d.records.length || d.can_prepare && (!d.zone_name || !d.pending_domains.length || !date(d.expires) || d.expires<=d.server_time || d.pending_domains.some(n=>n.replace(/^\*\./,"")!==d.zone_name && !n.endsWith("."+d.zone_name))) || !d.can_prepare && (d.pending_domains.length || d.expires!==""))throw new Error();return d;}
    if(!d.zone_name || d.can_prepare || d.pending_domains.length || !date(d.prepared_at) || !date(d.expires) || d.prepared_at>=d.expires || d.prepared_at>d.server_time || !d.records.length) throw new Error();
    for(let i=0;i<d.records.length;i++){
      const r=d.records[i];
      const metadata={...r};delete metadata.recovery;
      if(Object.hasOwn(r,"recovery") && (!keys(r.recovery,"attempts,not_before,blocked") || !["creating","deleting"].includes(r.state) || (r.state==="creating"?r.attempts!==6||r.blocked:r.cleanup_attempts!==6||r.cleanup_blocked) || !Number.isInteger(r.recovery.attempts) || r.recovery.attempts<1 || r.recovery.attempts>6 || !date(r.recovery.not_before) || typeof r.recovery.blocked!=="boolean"))throw new Error();
      if(!keys(metadata,"domain,name,state,attempts,not_before,blocked,cleanup_attempts,cleanup_not_before,cleanup_blocked,checked_at") || !domain(r.domain) || i>0 && d.records[i-1].domain>=r.domain || r.name!=="_acme-challenge."+r.domain.replace(/^\*\./,"") || !(r.domain.replace(/^\*\./,"")===d.zone_name || r.domain.endsWith("."+d.zone_name)) || !["new","creating","borrowed","created","deleting","deleted"].includes(r.state) || !Number.isInteger(r.attempts) || r.attempts<0 || r.attempts>6 || !Number.isInteger(r.cleanup_attempts) || r.cleanup_attempts<0 || r.cleanup_attempts>6 || typeof r.blocked!=="boolean" || typeof r.cleanup_blocked!=="boolean" || r.blocked && r.state!=="creating" || r.cleanup_blocked && r.state!=="deleting") throw new Error();
      if(r.state==="new" ? r.attempts!==0 || r.not_before!=="" || r.blocked : r.attempts<1 || !date(r.not_before))throw new Error();
      if(["deleting","deleted"].includes(r.state) ? r.cleanup_attempts<1 || !date(r.cleanup_not_before) : r.cleanup_attempts!==0 || r.cleanup_not_before!=="" || r.cleanup_blocked)throw new Error();
      if(["new","creating"].includes(r.state) ? r.checked_at!=="" : !date(r.checked_at) || r.checked_at<d.prepared_at || r.checked_at>d.server_time)throw new Error();
    }
    return d;
  };
  const selected=()=>{
    if(!snapshot || !/^[0-7]$/.test(select.value))return null;
    const index=Number(select.value), list=snapshot.prepared?snapshot.records:snapshot.pending_domains.map(domain=>({domain,state:"new",attempts:0,not_before:"",blocked:false,cleanup_attempts:0,cleanup_not_before:"",cleanup_blocked:false}));
    return index<list.length?{row:list[index],index}:null;
  };
  const choice=()=>{
    const s=selected();if(!s)return null;
    const r=s.row, cleanup=r.state==="created"||r.state==="deleting", normalAttempts=cleanup?r.cleanup_attempts:r.attempts, normalWait=cleanup?r.cleanup_not_before:r.not_before;
    const mode=r.state==="new"?"add":r.state==="created"?"cleanup":["creating","deleting"].includes(r.state)?normalAttempts===6?"recover":"check":"";
    const blocked=(cleanup?r.cleanup_blocked:r.blocked)||!!r.recovery?.blocked, attempts=mode==="recover"?(r.recovery?.attempts||0):normalAttempts, wait=r.recovery?.not_before>normalWait?r.recovery.not_before:normalWait;
    const elapsed=Date.now()-received, now=Date.parse(snapshot.server_time)+elapsed;
    const allowed=!!mode && !blocked && attempts<6 && elapsed>=0 && Math.abs(Date.now()-now)<120000 && (!wait || now>=Date.parse(wait)) && (mode!=="add" || now<Date.parse(snapshot.expires));
    return {...s,mode,allowed,blocked,attempts,wait};
  };
  const enable=()=>{const c=choice();button.disabled=!!active || document.hidden || !c?.allowed || !password.value || password.value.length>256 || !consent.checked || c.mode==="cleanup"&&!exclusive.checked;refresh.disabled=!!active;select.disabled=!!active;};
  const details=()=>{
    wipe();const c=choice();el("dns-operation-exclusive-row").hidden=c?.mode!=="cleanup";
    button.textContent=c?.mode==="add"?"Add DNS record":c?.mode==="cleanup"?"Clean up this record":c?.mode==="recover"?"Check recovery result":"Check result";
    el("dns-operation-consent-label").textContent=c?.mode==="add"?"Allow my Rootwell to add this certificate request's exact TXT record in Cloudflare":c?.mode==="cleanup"?"Remove only this Rootwell-owned temporary DNS record; it is no longer needed":"Allow a read-only Cloudflare check of this saved DNS operation — no create or deletion";
    el("dns-operation-help").textContent=!c?"":!c.mode?"This record needs no action. Existing records are left alone; confirmed cleanup stays saved.":c.blocked||c.attempts>=6?"Further checks are blocked. Inspect Cloudflare and keep this saved scope for reviewed operator maintenance. Do not reset it or restore an older backup to retry.":!c.allowed?"Not ready yet. Respect the provider wait and check your clock. Read saved DNS status again after "+(c.wait||"the request is ready")+".":c.mode==="recover"?"Ordinary checks are exhausted. Recovery check "+(c.attempts+1)+" of 6 only reads Cloudflare; it never adds or deletes a record. "+(c.row.state==="deleting"?"If the record is still there, inspect it in Cloudflare. Remove it manually only if you can independently identify this exact temporary record; otherwise leave it alone. Then check again.":"If no owned record is confirmed, keep this request saved and inspect Cloudflare. An empty result does not prove a delayed creation cannot appear later."):c.mode==="add"?"Only this saved CA record can be added. Existing matching records will be left alone.":c.mode==="cleanup"?"Use this after validation/issuance. Exclusive editing is required: Cloudflare cannot atomically protect the record from another tool's concurrent edits.":"This only reads the existing operation, even after its certificate request expires. An uncertain create or deletion is never repeated.";
    enable();
  };
  const reset=()=>{++generation;active?.abort();active=null;snapshot=null;wipe();form.hidden=true;rows.hidden=true;rows.replaceChildren();select.replaceChildren();status.textContent=uncertain;enable();};
  const labels={new:"Ready to add",creating:"Addition not confirmed — check result",borrowed:"Already existed — left alone",created:"Added by Rootwell — cleanup available",deleting:"Cleanup not confirmed — check result",deleted:"Cleanup confirmed by provider"};
  const render=d=>{
    snapshot=d;received=Date.now();rows.replaceChildren();select.replaceChildren();wipe();
    const list=d.prepared?d.records:d.pending_domains.map(domain=>({domain,state:"new"}));
    list.forEach((r,index)=>{const li=document.createElement("li");li.textContent=r.domain+" — "+labels[r.state];rows.append(li);const option=document.createElement("option");option.value=String(index);option.textContent=r.domain;select.append(option);});
    select.value=list.length?"0":"";rows.hidden=!list.length;form.hidden=!list.length;
    status.textContent=d.prepared?"Saved DNS work for "+d.zone_name+". These are provider observations, not domain verification. Choose a domain below. Make a new full backup after changes.":d.can_prepare?"Ready to add the saved certificate request's DNS records for "+d.zone_name+". Each click handles one domain. Nothing runs automatically.":!d.zone_name?"No Cloudflare token saved. Save optional settings above, or keep using manual DNS.":"No pending DNS records to add. Get a saved DNS request first, or continue its CA verification. Nothing contacted Cloudflare.";
    details();
  };
  const read=async(response,current,controller,mode)=>{
    if(response.status!==200 || response.headers.get("cache-control")!=="no-store" || response.headers.get("content-type")?.split(";")[0].trim().toLowerCase()!=="application/json" || !response.body)throw new Error();
    const reader=response.body.getReader(), decoder=new TextDecoder("utf-8",{fatal:true});let text="",size=0;
    try{while(true){const {value,done}=await reader.read();if(done)break;size+=value.byteLength;if(size>16384 || current!==generation || document.hidden || controller.signal.aborted)throw new Error();text+=decoder.decode(value,{stream:true});}text+=decoder.decode();}finally{await reader.cancel();reader.releaseLock();}
    return validate(JSON.parse(text),mode);
  };
  const run=async(change)=>{
    if(active || document.hidden)return;enable();if(change&&button.disabled)return;
    const c=choice(), mode=change?c.mode:"status", expected=snapshot?.generation, domainBefore=c?.row.domain, original=snapshot;
    const input=change?{provider:"cloudflare",password:password.value,expected_generation:expected,index:c.index,confirm:true}:{provider:"cloudflare"};if(mode==="cleanup")input.exclusive=true;
    const current=++generation,controller=new AbortController(),started=Date.now();active=controller;snapshot=null;wipe();form.hidden=true;rows.hidden=true;rows.replaceChildren();enable();status.textContent=change?"Contacting Cloudflare for this one record…":"Reading encrypted local DNS status… No provider connection.";
    const timeout=setTimeout(()=>{if(current===generation)reset();},30000);
    try{
      const request={method:"POST",credentials:"same-origin",cache:"no-store",redirect:"error",signal:controller.signal,headers:{"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify(input)};input.password="";
      const pending=fetch("/api/acme/dns/"+mode,request);request.body="";const response=await pending;
      if(current!==generation || document.hidden || controller.signal.aborted || Date.now()-started<0 || Date.now()-started>=30000)throw new Error();
      if(response.status===401 || response.status===403){status.textContent="Password or session not accepted. Sign in if needed, then read saved DNS status.";return;}
      if(response.status===409 || response.status===429){status.textContent="The store changed, another operation is running, or a wait/budget blocks this action. Read saved DNS status before continuing.";return;}
      if(response.status===503){status.textContent="DNS operations need Linux or Linux Docker. If an operation was sent, its outcome may be uncertain. Read saved DNS status first.";return;}
      const data=await read(response,current,controller,mode);
      if(change && (data.generation<=expected || data.generation>expected+3 || !data.prepared || data.records[c.index]?.domain!==domainBefore))throw new Error();
      if(change){
        const r=data.records[c.index], allowedStates=mode==="add"?["creating","created","borrowed"]:mode==="cleanup"?["deleting","deleted"]:c.row.state==="creating"?["creating","created"]:["deleting","deleted"];
        if(!allowedStates.includes(r.state) || data.server_time<original.server_time || original.prepared && (data.generation!==expected+2 || data.prepared_at!==original.prepared_at || data.expires!==original.expires || data.zone_name!==original.zone_name || data.records.length!==original.records.length || data.records.some((row,i)=>i!==c.index && JSON.stringify(row)!==JSON.stringify(original.records[i]))) || !original.prepared && data.generation!==expected+3)throw new Error();
        if(data.zone_name!==original.zone_name || data.expires!==original.expires || !original.prepared && (JSON.stringify(data.records.map(row=>row.domain))!==JSON.stringify(original.pending_domains) || data.records.some((row,i)=>i!==c.index && row.state!=="new")))throw new Error();
        const cleanup=mode==="cleanup"||c.row.state==="deleting";
        if(mode==="recover"){
          if(r.attempts!==c.row.attempts || r.cleanup_attempts!==c.row.cleanup_attempts || r.not_before!==c.row.not_before || r.cleanup_not_before!==c.row.cleanup_not_before || r.blocked!==c.row.blocked || r.cleanup_blocked!==c.row.cleanup_blocked)throw new Error();
          if(r.state===c.row.state ? !r.recovery || r.recovery.attempts!==(c.row.recovery?.attempts||0)+1 : Object.hasOwn(r,"recovery"))throw new Error();
        }else if(cleanup ? r.cleanup_attempts!==c.row.cleanup_attempts+1 || r.attempts!==c.row.attempts : r.attempts!==c.row.attempts+1 || r.cleanup_attempts!==0)throw new Error();
      }
      if(current!==generation || document.hidden || controller.signal.aborted || Date.now()-started<0 || Date.now()-started>=30000)throw new Error();
      render(data);
      if(change)window.dispatchEvent(new Event("rootwell-dns-changed"));
    }catch{if(current===generation&&!document.hidden)status.textContent=uncertain;}
    finally{input.password="";clearTimeout(timeout);if(current===generation){active=null;wipe();enable();}}
  };
  refresh.addEventListener("click",()=>run(false));form.addEventListener("submit",event=>{event.preventDefault();return run(true);});
  select.addEventListener("change",()=>{if(active)reset();details();});password.addEventListener("input",()=>{if(active)reset();enable();});
  for(const input of [consent,exclusive])input.addEventListener("change",()=>{if(active)reset();enable();});
  for(const [id,event] of [["acme-clear","click"],["acme-provider","change"],["acme-order-refresh","click"],["acme-order-form","submit"],["dns-config-form","submit"]])el(id).addEventListener(event,reset);
  document.addEventListener("visibilitychange",()=>{if(document.hidden)reset();});window.addEventListener("pagehide",reset);
  reset();status.textContent="Read saved DNS status first. This does not contact Cloudflare.";
})();
