"use strict";
(function () {
  const el=id=>document.getElementById(id);
  const panel=el("comparison-panel"), input=el("comparison-file"), button=el("comparison-button"), status=el("comparison-status"), result=el("comparison-result");
  const background=el("background-status"), history=el("history-events"), historyStatus=el("history-status");
  const fp=/^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/;
  let serial=0, selected=null, controller=null, busy=false, activitySerial=0, activityController=null, events=[], page=0, staleTimer=null;
  const date=value=>typeof value==="string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0,19)+"Z"===value;
  async function json(response, signal, max=8*1024*1024) {
    if(!response.ok||!response.body?.getReader)throw new Error("Request not confirmed");
    const reader=response.body.getReader(), decoder=new TextDecoder("utf-8",{fatal:true});let text="",size=0;
    try { for(;;){const part=await reader.read();if(signal.aborted)throw new Error();if(part.done)break;size+=part.value.byteLength;if(size>max)throw new Error();text+=decoder.decode(part.value,{stream:true});}text+=decoder.decode();return JSON.parse(text); }
    finally {void reader.cancel().catch(()=>{});}
  }
  function clearComparison() {
    ++serial;controller?.abort();controller=null;busy=false;selected?.bytes.fill(0);selected=null;
    panel.hidden=true;input.value="";button.disabled=false;result.replaceChildren();status.textContent="";el("comparison-target").textContent="";
  }
  function invalidate() {
    clearComparison();++activitySerial;activityController?.abort();activityController=null;clearTimeout(staleTimer);events=[];page=0;history.replaceChildren();
    background.textContent="Background status must be refreshed.";historyStatus.textContent="Refresh activity to read authenticated history.";
  }
  async function open(record,generation) {
    clearComparison();if(document.hidden||!fp.test(record.fingerprint)||!Number.isSafeInteger(generation)||generation<1)return;
    const token=serial;controller=new AbortController();const active=controller;
    const deadline=setTimeout(()=>active.abort(),10000);
    panel.hidden=false;button.disabled=true;status.textContent="Reading the exact saved public snapshot…";
    panel.scrollIntoView?.({block:"start"});
    try {
      const response=await fetch("/api/inventory/comparison-source",{method:"POST",credentials:"same-origin",cache:"no-store",redirect:"error",signal:active.signal,
        headers:{"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify({fingerprint:record.fingerprint,expected_generation:generation})});
      const data=await json(response,active.signal,128*1024);
      if(token!==serial||document.hidden||active.signal.aborted)return;
      if(data?.schema_version!=="rootwell.inventory.comparison-source.v1"||data.fingerprint!==record.fingerprint||data.generation!==generation||typeof data.der!=="string"||data.der.length>87384||!data.der.length)throw new Error();
      const raw=atob(data.der),bytes=Uint8Array.from(raw,c=>c.charCodeAt(0));
      if(bytes.length<1||bytes.length>65536){bytes.fill(0);throw new Error();}
      selected={fingerprint:record.fingerprint,generation,bytes};
      el("comparison-target").textContent=(record.subject||"Saved certificate")+" · saved snapshot generation "+generation;
      button.disabled=false;status.textContent="Choose one new public certificate. Nothing has been uploaded or replaced.";
    } catch {if(token===serial&&!document.hidden){clearComparison();panel.hidden=false;status.textContent="Saved snapshot unavailable or changed. Refresh the inventory and select again.";}}
    finally {clearTimeout(deadline);active.abort();}
  }
  input.addEventListener("change",()=>{++serial;controller?.abort();busy=false;button.disabled=!selected;result.replaceChildren();status.textContent="Selection changed. Compare again; nothing was saved.";});
  el("comparison-close").addEventListener("click",clearComparison);
  button.addEventListener("click",async()=>{
    if(busy||!selected||document.hidden)return;
    const file=input.files?.[0];result.replaceChildren();
    if(input.files?.length!==1||!file||file.size<1||file.size>96*1024){status.textContent="Choose one public certificate up to 96 KiB. No PFX, private keys or multi-certificate bundles.";return;}
    const snapshot=selected,token=serial;controller=new AbortController();const active=controller;
    const current=()=>token===serial&&selected===snapshot&&!document.hidden&&!active.signal.aborted&&input.files?.length===1&&input.files[0]===file;
    busy=true;button.disabled=true;status.textContent="Comparing locally — no candidate upload…";
    const deadline=setTimeout(()=>{active.abort();if(token===serial){++serial;busy=false;button.disabled=false;status.textContent="Comparison timed out. Compare again; nothing was saved.";}},20000);
    let bytes;
    try {
      const engine=await globalThis.rootwellInventoryEngineReady;
      const entries=await globalThis.rootwellInventoryImport.preview([file],current);
      if(entries.length!==1)throw new Error();
      bytes=await globalThis.rootwellInventoryImport.prepare([file],[entries[0].sha256],current);
      if(!current())return;
      const raw=engine.compare(snapshot.bytes,bytes);
      if(typeof raw!=="string"||raw.length>4*1024*1024)throw new Error();
      const data=JSON.parse(raw),d=data?.result;
      if(data.schema_version!=="rootwell.public-comparison.v1"||data.ok!==true||data.error!==null||!d||d.verification!=="not-performed"||d.old_fingerprint!==snapshot.fingerprint||d.new_fingerprint!==entries[0].sha256||
        !["same_certificate","same_public_key","subject_changed","issuer_changed","expiry_extended","validity_changed"].every(key=>typeof d[key]==="boolean")||!date(d.old_expiry)||!date(d.new_expiry)||
        ![d.added_names,d.removed_names].every(names=>Array.isArray(names)&&names.length<=4096&&names.every(name=>typeof name==="string"&&name.length<=65540)))throw new Error();
      if(!current())return;
      const lines=[d.same_certificate?"This is exactly the same certificate.":"This is a different certificate.",d.same_public_key?"Public key is unchanged (not proof of private-key possession).":"Public key changed — confirm the matching private key before deployment.",
        "Expiry: "+d.old_expiry.slice(0,10)+" → "+d.new_expiry.slice(0,10)+(d.expiry_extended?" · extended":" · not extended"),
        d.subject_changed?"Subject changed.":"Subject unchanged.",d.issuer_changed?"Issuer changed (identity text is not trust).":"Issuer unchanged (not trust).",
        "Added names: "+(d.added_names.join(", ")||"None"),"Removed names: "+(d.removed_names.join(", ")||"None"),
        d.validity_changed?"Validity dates changed. Inspect the new certificate before use.":"Validity dates unchanged."];
      for(const line of lines){const item=document.createElement("li");item.textContent=line;result.appendChild(item);}
      status.textContent="Comparison finished locally. No save, replacement, trust verification or renewal was performed.";
    } catch {if(current())status.textContent="Comparison refused. Use exactly one supported public certificate; refresh the saved selection if needed. Nothing was saved.";}
    finally {bytes?.fill(0);clearTimeout(deadline);active.abort();if(token===serial){busy=false;button.disabled=!selected;}}
  });
  const actions=Object.freeze({import:"Certificates added","owner-changed":"Owner note changed","location-added":"Server note added","location-renamed":"Server note renamed","location-removed":"Server note removed","record-deleted":"Inventory record deleted","key-added":"Private key attached","acme-key-prepared":"Test account key prepared"});
  function drawHistory() {
    history.replaceChildren();const first=page*50,visible=events.slice().reverse().slice(first,first+50);
    for(const event of visible){const item=document.createElement("li");item.textContent=actions[event.action]+" · "+event.at+" · "+(event.action==="acme-key-prepared"?"Account key":event.fingerprints.length+" certificate(s)");
      const details=document.createElement("details"),summary=document.createElement("summary"),ids=document.createElement("small");summary.textContent="Technical identities · generation "+event.generation;ids.textContent=event.fingerprints.join(" · ");details.appendChild(summary);details.appendChild(ids);item.appendChild(details);history.appendChild(item);}
    historyStatus.textContent=events.length?"Showing "+(first+1)+"–"+(first+visible.length)+" of "+events.length+" recorded changes. History starts at generation "+events[0].generation+"; earlier activity is unknown.":"No recorded changes. Earlier versions did not record history.";
    el("history-previous").disabled=page===0;el("history-next").disabled=first+50>=events.length;
  }
  async function refreshActivity() {
    if(document.hidden)return;const token=++activitySerial;activityController?.abort();clearTimeout(staleTimer);
    activityController=new AbortController();const active=activityController,deadline=setTimeout(()=>active.abort(),10000);
    background.textContent="Reading authenticated background status…";
    try {
      const response=await fetch("/api/inventory/activity",{method:"GET",credentials:"same-origin",cache:"no-store",redirect:"error",headers:{"X-Rootwell-Request":"1"},signal:active.signal});
      const data=await json(response,active.signal);
      if(token!==activitySerial||document.hidden||active.signal.aborted)return;
      if(data?.schema_version!=="rootwell.inventory.activity.v1"||!Number.isSafeInteger(data.generation)||data.generation<1||!Array.isArray(data.events)||data.events.length>1024)throw new Error();
      let previous=0;
      for(const event of data.events){if(!Number.isSafeInteger(event.generation)||event.generation<2||event.generation>data.generation||(previous&&event.generation!==previous+1)||!date(event.at)||!Object.hasOwn(actions,event.action)||!Array.isArray(event.fingerprints)||event.fingerprints.length<1||event.fingerprints.length>64||event.fingerprints.some(id=>!fp.test(id))||new Set(event.fingerprints).size!==event.fingerprints.length||(event.action!=="import"&&event.fingerprints.length!==1))throw new Error();previous=event.generation;}
      if(previous&&previous!==data.generation)throw new Error();
      const m=data.monitoring;if(!m||!["ready","locked","unavailable","clock-unavailable","stale","not-running"].includes(m.status))throw new Error();
      if(m.status==="ready"){
        if(m.generation!==data.generation||!date(m.checked_at)||!date(m.expires_at)||Date.parse(m.expires_at)<=Date.parse(m.checked_at)||!Array.isArray(m.attention)||m.attention.length>500||m.attention.some(id=>!fp.test(id))||new Set(m.attention).size!==m.attention.length)throw new Error();
        background.textContent="Server checked at "+m.checked_at+" · "+m.attention.length+" certificate(s) need attention within 30 days. Runs without this page until session expiry at "+m.expires_at+". No external messages are sent.";
      } else background.textContent={locked:"Background checks paused: sign in again to unlock.",unavailable:"Background checks unavailable: inspect inventory storage before relying on reminders.","clock-unavailable":"Background checks paused: server clock moved backwards or is unavailable.",stale:"Background observation is out of date. Refresh after the next server check.","not-running":"Background worker is not running on this server. This is not a 24/7 monitoring claim."}[m.status];
      events=data.events;page=0;drawHistory();staleTimer=setTimeout(()=>{if(token===activitySerial)background.textContent="This background status view is old. Refresh activity for the current server result.";},120000);
    } catch {if(token===activitySerial&&!document.hidden){events=[];history.replaceChildren();historyStatus.textContent="History unavailable; no partial activity is shown.";background.textContent="Background status could not be confirmed. Refresh activity; do not assume monitoring is healthy.";}}
    finally {clearTimeout(deadline);active.abort();}
  }
  el("activity-refresh").addEventListener("click",refreshActivity);
  el("history-previous").addEventListener("click",()=>{if(page>0){page--;drawHistory();}});
  el("history-next").addEventListener("click",()=>{if((page+1)*50<events.length){page++;drawHistory();}});
  document.addEventListener("visibilitychange",()=>{if(document.hidden)invalidate();});window.addEventListener("pagehide",invalidate);
  Object.defineProperty(globalThis,"rootwellInventoryLifecycle",{value:Object.freeze({open,invalidate,refreshActivity,isOpen:()=>!panel.hidden})});
}());
