(() => {
  "use strict";
  const el=id=>document.getElementById(id),refresh=el("archive-status"),form=el("archive-form"),password=el("archive-password"),backup=el("archive-backup"),consent=el("archive-consent"),save=el("archive-save"),message=el("archive-message");
  let snapshot=null,active=null,epoch=0,stale=null;
  if(globalThis.location?.hash==="#history-storage"){for(const id of ["change-history","history-storage"])el(id).open=true;}
  const exact=(v,k)=>v&&typeof v==="object"&&!Array.isArray(v)&&Object.keys(v).sort().join(",")===k.split(",").sort().join(",");
  const count=(v,max)=>Number.isSafeInteger(v)&&v>=0&&v<=max;
  const date=v=>typeof v==="string"&&/^20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(v)&&Number.isFinite(Date.parse(v))&&new Date(v).toISOString()===v.replace("Z",".000Z");
  const wipe=()=>{password.value="";backup.checked=false;consent.checked=false;};
  const enable=()=>{refresh.disabled=!!active||document.hidden;save.disabled=!!active||!snapshot?.can_archive||!password.value||!backup.checked||!consent.checked||document.hidden;};
  const reset=()=>{++epoch;active?.abort();active=null;clearTimeout(stale);snapshot=null;wipe();form.hidden=true;message.textContent="Status is not current. Check history storage before another action. If an archive result was lost, check status instead of repeating it.";enable();};
  const validate=(d,write,expected)=>{
    if(!exact(d,"schema_version,checked_at,network_used,saved,status")||d.schema_version!=="rootwell.history-archive.v1"||!date(d.checked_at)||d.network_used!==false||d.saved!==write)throw new Error();
    const s=d.status;
    if(!exact(s,"generation,active_events,archived_events,pages_free,can_archive,reason")||!count(s.generation,1000000)||s.generation<1||!count(s.active_events,1024)||!count(s.archived_events,4096)||!count(s.pages_free,4)||typeof s.can_archive!=="boolean"||!["ready","not-needed","archive-limit","generation-limit"].includes(s.reason)||s.can_archive!==(s.reason==="ready")||s.archived_events<(4-s.pages_free)*512||s.archived_events>(4-s.pages_free)*1024||s.active_events+s.archived_events>s.generation-1)throw new Error();
    const reason=s.active_events<512?"not-needed":s.pages_free===0?"archive-limit":s.generation===1000000?"generation-limit":"ready";
    if(s.reason!==reason||write&&(s.generation!==expected.generation+1||s.active_events!==1||s.archived_events!==expected.archived_events+expected.active_events||s.pages_free!==expected.pages_free-1))throw new Error();
    return s;
  };
  const run=async write=>{
    if(active||document.hidden||write&&(!snapshot?.can_archive||!password.value||!backup.checked||!consent.checked))return;
    const expected=snapshot,input=write?{expected_generation:expected.generation,password:password.value,confirm:true,backup_confirmed:true,scope:"lossless-history-archive"}:{};
    const serial=++epoch,controller=new AbortController(),began=Date.now();active=controller;snapshot=null;wipe();form.hidden=true;enable();message.textContent=write?"Archiving encrypted activity locally…":"Reading history storage locally…";
    const deadline=setTimeout(()=>{if(serial===epoch)reset();},25000);
    try{
      const pending=fetch("/api/inventory/history/"+(write?"archive":"status"),{method:"POST",credentials:"same-origin",cache:"no-store",redirect:"error",signal:controller.signal,headers:{"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify(input)});input.password="";
      const response=await pending;if(response.status!==200||response.headers.get("cache-control")!=="no-store"||response.headers.get("content-type")?.split(";")[0].trim().toLowerCase()!=="application/json"||!response.body)throw new Error();
      const reader=response.body.getReader(),decoder=new TextDecoder("utf-8",{fatal:true});let text="",size=0;
      try{for(;;){const p=await reader.read();if(p.done)break;size+=p.value.byteLength;if(size>4096||serial!==epoch||controller.signal.aborted||document.hidden)throw new Error();text+=decoder.decode(p.value,{stream:true});}text+=decoder.decode();}finally{await reader.cancel();reader.releaseLock();}
      const d=JSON.parse(text),s=validate(d,write,expected);if(serial!==epoch||controller.signal.aborted||document.hidden||Date.now()-began<0||Date.now()-began>=25000||Math.abs(Date.now()-Date.parse(d.checked_at))>=120000)throw new Error();
      snapshot=s;active=null;
      message.textContent=(write?"Older activity archived. All events are retained. Make a new complete backup. ":"")+s.active_events+" active events · "+s.archived_events+" archived events · "+s.pages_free+" archive pages left. "+({ready:"You can archive this active log. All saved data and DNS waits stay unchanged; byte and generation limits still apply.","not-needed":"No archive is needed yet (available from 512 active events).","archive-limit":"Archive capacity is full. Nothing is deleted; further maintenance is required.","generation-limit":"The generation limit is reached. Archiving cannot reset it."}[s.reason]);
      form.hidden=!s.can_archive;enable();stale=setTimeout(reset,60000);
      if(write)globalThis.rootwellInventoryLifecycle?.refreshActivity();
    }catch{if(serial===epoch)reset();}
    finally{input.password="";clearTimeout(deadline);controller.abort();if(serial===epoch){active=null;wipe();enable();}}
  };
  refresh.addEventListener("click",()=>run(false));form.addEventListener("submit",e=>{e.preventDefault();return run(true);});
  password.addEventListener("input",()=>{if(active)reset();enable();});for(const field of [backup,consent])field.addEventListener("change",()=>{if(active)reset();enable();});
  document.addEventListener("visibilitychange",()=>{if(document.hidden)reset();});window.addEventListener("pagehide",reset);enable();
})();
