"use strict";
(function () {
  const byId=id=>document.getElementById(id), form=byId("acme-form"), domains=byId("acme-domains"), provider=byId("acme-provider"), challenge=byId("acme-challenge");
  const status=byId("acme-status"), result=byId("acme-result"), button=byId("acme-check"), names=byId("acme-names");
  const directory="https://acme-staging-v02.api.letsencrypt.org/directory";
  let serial=0, controller=null, busy=false;
  function controls(){button.disabled=busy||document.hidden||!domains.value.trim();}
  function invalidate(){serial++;controller?.abort();controller=null;busy=false;result.hidden=true;names.replaceChildren();byId("acme-directory").textContent="";byId("acme-method").textContent="";status.textContent="";controls();}
  function help(){byId("acme-help").textContent=challenge.value==="dns-01"?"You need permission to edit DNS records. No DNS API password is needed for this planned manual flow.":"Your website must serve a challenge file on public port 80. Rootwell's sign-in listener is not that web server. This flow is planned, not provisioned.";}
  function clear(){invalidate();domains.value="";provider.value="letsencrypt-staging";challenge.value="dns-01";help();controls();}
  for(const element of [domains,provider,challenge]) element.addEventListener(element===domains?"input":"change",()=>{invalidate();help();});
  byId("acme-clear").addEventListener("click",clear);
  async function read(response){
    if(!response.ok||response.headers.get("cache-control")!=="no-store"||!response.body) throw new Error();
    const reader=response.body.getReader(), chunks=[];let size=0,bytes;
    try { while(true){const p=await reader.read();if(p.done)break;size+=p.value.byteLength;if(size>16*1024){p.value.fill(0);throw new Error();}chunks.push(p.value);}bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes)); }
    finally {bytes?.fill(0);for(const c of chunks)c.fill(0);await reader.cancel().catch(()=>{});}
  }
  form.addEventListener("submit",async event=>{
    event.preventDefault();if(busy||document.hidden)return;
    invalidate();const raw=domains.value, p=provider.value, c=challenge.value;
    const selected=raw.split(/\r?\n/).map(n=>n.trim().toLowerCase()).filter(Boolean);
    if(raw.length>8192||selected.length<1||selected.length>32||selected.some(n=>n.length>253)||p!=="letsencrypt-staging"||!["dns-01","http-01"].includes(c)){status.textContent="Choose staging and 1–32 domain names, one per line.";return;}
    const ticket=++serial;controller=new AbortController();const own=controller;busy=true;controls();
    const current=()=>serial===ticket&&!document.hidden&&!own.signal.aborted&&domains.value===raw&&provider.value===p&&challenge.value===c;
    const timeout=setTimeout(()=>{if(serial===ticket){invalidate();status.textContent="Setup check timed out. Nothing was saved; try again.";}},10000);
    status.textContent="Checking setup on your own Rootwell… no CA connection.";
    try {
      const response=await fetch("/api/acme/plan",{method:"POST",credentials:"same-origin",cache:"no-store",signal:own.signal,headers:{"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify({provider:p,challenge:c,domains:selected})});
      const data=await read(response);if(!current())return;
      if(!data||Object.keys(data).sort().join(",")!=="account_created,can_issue,challenge,directory,domains,network_enabled,provider,saved,schema_version,state"||data.schema_version!=="rootwell.acme.setup.v1"||data.state!=="setup-checked"||data.provider!==p||data.directory!==directory||data.challenge!==c||data.network_enabled!==false||data.saved!==false||data.account_created!==false||data.can_issue!==false||!Array.isArray(data.domains)||JSON.stringify(data.domains)!==JSON.stringify(selected))throw new Error();
      for(const name of data.domains){const node=document.createElement("li");node.textContent=name;names.appendChild(node);}
      byId("acme-method").textContent=c==="dns-01"?"Planned proof: manually add DNS TXT record(s). No token has been created.":"Planned proof: publish a challenge file on your public website's port 80. No file has been created.";
      byId("acme-directory").textContent=directory;result.hidden=false;status.textContent="Setup syntax checked. Nothing saved or sent to a CA. Account integration comes next.";
    }catch{if(current()){invalidate();status.textContent="Setup not confirmed. Check unique ASCII domains (no URLs/IPs/internal names); wildcards need DNS TXT. Sign in again if your session expired. Nothing was saved.";}}
    finally{clearTimeout(timeout);if(serial===ticket){controller=null;busy=false;controls();}}
  });
  document.addEventListener("visibilitychange",()=>{if(document.hidden)clear();});window.addEventListener("pagehide",clear);
  help();controls();
})();
