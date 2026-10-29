import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import http from "node:http";

const child = spawn(process.execPath, [fileURLToPath(new URL("./inventory-demo.mjs", import.meta.url)), "--fixture-only", "--port", "0"],
  { stdio: ["ignore", "pipe", "pipe"] });
try {
  const address = await new Promise((resolve, reject) => {
    let output = "";
    const timeout = setTimeout(() => reject(new Error("demo did not start")), 5000);
    child.once("error", reject);
    child.once("exit", code => reject(new Error("demo exited: " + code)));
    child.stdout.on("data", chunk => {
      output += chunk.toString();
      const match = output.match(/http:\/\/127\.0\.0\.1:\d+\/inventory/);
      if (match) { clearTimeout(timeout); resolve(match[0]); }
    });
  });
  const page = await fetch(address);
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.match(html, /DEMO — generated fake records only/);
  assert.match(html, /<h2 id="overview-heading">Saved certificates<\/h2>/);
  assert.doesNotMatch(html, /Export selected records|preview-export-button|download-export-button/);
  assert.match(html, /id="certificate-file" type="file"[^>]*multiple/);
  assert.match(html, /id="inventory-form" data-read-only="true"/);
  assert.match(html, /id="save-button" type="submit" disabled/);
  assert.equal(page.headers.get("cache-control"), "no-store");
  const origin = new URL(address).origin;
  const requestStoreHeaders={Origin:origin,"Content-Type":"application/json","X-Rootwell-Request":"1"};
  const requestStorage=await fetch(origin+"/api/acme/request-storage/status",{method:"POST",headers:requestStoreHeaders,body:"{}"});assert.equal(requestStorage.status,200);const requestCounts=await requestStorage.json();assert.equal(requestCounts.schema_version,"rootwell.request-archive.v1");assert.equal(requestCounts.status.active_requests,32);assert.equal(requestCounts.network_used,false);
  assert.equal((await fetch(origin+"/api/acme/request-storage/archive",{method:"POST",headers:requestStoreHeaders,body:"{}"})).status,405,"demo cannot archive request history");
  const requestArchiveScript=await fetch(origin+"/request-archive.js");assert.equal(requestArchiveScript.status,200);assert.match(await requestArchiveScript.text(),/save.disabled=true/);
  for(const id of ["request-archive-password","request-archive-backup","request-archive-consent"])assert.ok(html.includes('id="'+id+'" disabled'));
  const overviewScript=await fetch(origin+"/automation-status.js");assert.equal(overviewScript.status,200);
  const overview=await fetch(origin+"/api/automation/status",{method:"POST",headers:{Origin:origin,"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify({provider:"letsencrypt-staging"})});assert.equal(overview.status,200);const summary=await overview.json();assert.equal(summary.network_used,false);assert.equal(summary.automatic_renewal,false);assert.equal(summary.dns,"unknown");assert.match(summary.certificates[0].name,/DEMO/);
  assert.equal((await fetch(origin+"/api/automation/status",{method:"POST",body:"{}"})).status,403);
  const timingScript=await fetch(origin+"/renewal-timing.js");assert.equal(timingScript.status,200);assert.match(await timingScript.text(),/submit.disabled=true/);
  const watchScript=await fetch(origin+"/timing-watch.js");assert.equal(watchScript.status,200);const watchSource=await watchScript.text();assert.match(watchSource,/start.disabled=true/);assert.match(watchSource,/stop.disabled=true/);
  const watchHeaders={Origin:origin,"Content-Type":"application/json","X-Rootwell-Request":"1"};
  const jobScript=await fetch(origin+"/renewal-job.js");assert.equal(jobScript.status,200);const jobSource=await jobScript.text();assert.match(jobSource,/start.disabled=true/);assert.match(jobSource,/stop.disabled=true/);
  const jobResult=await fetch(origin+"/api/acme/renewal-job/status",{method:"POST",headers:watchHeaders,body:JSON.stringify({provider:"letsencrypt-staging"})});assert.equal(jobResult.status,200);const jobData=await jobResult.json();assert.equal(jobData.test_only,true);assert.equal(jobData.scope,"session-test-renewal");assert.match(jobData.job.name,/DEMO/);assert.equal(jobData.readiness,null);
  for(const mode of ["start","stop"])assert.equal((await fetch(origin+"/api/acme/renewal-job/"+mode,{method:"POST",headers:watchHeaders,body:"{}"})).status,405,"demo cannot grant or stop a renewal");
  const watchResult=await fetch(origin+"/api/acme/timing-watch/status",{method:"POST",headers:watchHeaders,body:JSON.stringify({provider:"letsencrypt-staging"})});assert.equal(watchResult.status,200);const watchData=await watchResult.json();assert.equal(watchData.automatic_renewal,false);assert.equal(watchData.scope,"session-timing-only");assert.match(watchData.watch.name,/DEMO/);assert.equal(watchData.readiness,null);
  for(const mode of ["start","stop"])assert.equal((await fetch(origin+"/api/acme/timing-watch/"+mode,{method:"POST",headers:watchHeaders,body:"{}"})).status,405,"demo cannot start or stop a background job");
  const timingHeaders={Origin:origin,"Content-Type":"application/json","X-Rootwell-Request":"1"};
  const timingBody=JSON.stringify({provider:"letsencrypt-staging",fingerprint:summary.certificates[0].fingerprint,expected_generation:40});
  const timing=await fetch(origin+"/api/acme/renewal-timing/status",{method:"POST",headers:timingHeaders,body:timingBody});assert.equal(timing.status,200);const time=await timing.json();assert.equal(time.network_attempted,false);assert.equal(time.saved,false);assert.equal(time.automatic_renewal,false);assert.equal(time.status.state,"ari");assert.equal(Object.keys(time.status).length,22);
  assert.equal((await fetch(origin+"/api/acme/renewal-timing/status",{method:"POST",body:timingBody})).status,403);
  assert.equal((await fetch(origin+"/api/acme/renewal-timing/status",{method:"POST",headers:timingHeaders,body:timingBody.replace(':40',':39')})).status,400);
  for(const mode of ["check","interrupt"])assert.equal((await fetch(origin+"/api/acme/renewal-timing/"+mode,{method:"POST",headers:timingHeaders,body:"{}"})).status,405,"demo cannot connect or mutate timing");
  const timingHTML=await (await fetch(origin+"/automation")).text();for(const id of ["renewal-time-password","renewal-time-consent","watch-password","watch-consent"])assert.ok(timingHTML.includes('id="'+id+'" disabled'));
  for(const id of ["renewal-job-password","renewal-job-consent","renewal-job-exclusive"])assert.ok(timingHTML.includes('id="'+id+'" disabled'));
  const dnsScript=await fetch(origin+"/cloudflare-config.js");assert.equal(dnsScript.status,200);assert.match(await dnsScript.text(),/button.disabled=true/);
  const dnsOperationScript=await fetch(origin+"/dns-operation.js");assert.equal(dnsOperationScript.status,200);assert.match(await dnsOperationScript.text(),/button.disabled=true/);
  const dnsOperationStatus=await fetch(origin+"/api/acme/dns/status",{method:"POST",headers:{Origin:origin,"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify({provider:"cloudflare"})});assert.equal(dnsOperationStatus.status,200);const dnsWork=await dnsOperationStatus.json();assert.equal(dnsWork.network_used,false);assert.deepEqual(dnsWork.records.map(row=>row.state),["created","borrowed","creating","deleted"]);
  assert.equal(dnsWork.records[2].attempts,6,"demo includes exhausted recovery case");
  assert.equal(dnsWork.records[2].recovery.attempts,6);
  assert.equal(dnsWork.records[2].maintenance.attempts,0,"demo offers separate operator observation");
  assert.match(timingHTML,/id="dns-operation-reviewed" disabled/);
  for(const mode of ["add","check","cleanup","recover","maintenance"])assert.equal((await fetch(origin+"/api/acme/dns/"+mode,{method:"POST",headers:{Origin:origin,"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify({provider:"cloudflare",password:"fake",expected_generation:40,index:0,confirm:true,exclusive:true})})).status,405,"demo cannot edit DNS or borrow a credential");
  const dnsStatus=await fetch(origin+"/api/dns/cloudflare/status",{method:"POST",headers:{Origin:origin,"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify({provider:"cloudflare"})});assert.equal(dnsStatus.status,200);const dnsConfig=await dnsStatus.json();assert.equal(dnsConfig.state,"not-configured");assert.equal(dnsConfig.network_used,false);assert.equal(dnsConfig.token_verified,false);assert.equal(dnsConfig.dns_changed,false);
  for(const mode of ["save","remove"])assert.equal((await fetch(origin+"/api/dns/cloudflare/"+mode,{method:"POST"})).status,405,"demo cannot store credentials");
  assert.equal((await fetch(origin+"/api/dns/cloudflare/status",{method:"POST",body:"{}"})).status,403);
  const automation=await fetch(origin+"/automation");assert.equal(automation.status,200);assert.match(await automation.text(),/DEMO — fake renewal result, no CA connection or private key/);
  const automationScript=await fetch(origin+"/acme-order.js");assert.equal(automationScript.status,200);assert.match(await automationScript.text(),/consent.disabled=true; password.disabled=true/);
  const demoStatus=await fetch(origin+"/api/acme/order/status",{method:"POST",headers:{Origin:origin,"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify({provider:"letsencrypt-staging"})});assert.equal(demoStatus.status,200);const demoRequest=await demoStatus.json();assert.equal(demoRequest.schema_version,"rootwell.acme.manual-dns.v9");assert.equal(demoRequest.can_issue,false);assert.equal(demoRequest.new_request.available,true);assert.equal(demoRequest.new_request.closed_count,1);assert.equal(demoRequest.state,"domain-verified");assert.equal(demoRequest.network_used,false);assert.equal(demoRequest.issuance.state,"certificate-saved");assert.equal(demoRequest.renewal_result.original_fingerprint,demoRequest.renewal_source);assert.equal(demoRequest.renewal_result.expiry_extended,true);assert.equal(Object.keys(demoRequest.renewal_result).length,5);
  for(const mode of ["issue","certificate-refresh","prepare-key","start","renew","validate","close-request"])assert.equal((await fetch(origin+"/api/acme/order/"+mode,{method:"POST"})).status,405,"demo cannot execute an operation");
  assert.match(html, /href="\/index.html"/);
  assert.match(html, /href="\/certificates" aria-current="page"/);
  assert.match(html, /id="certificate-pair-form" data-read-only="true"/);
  const certificatePage = await fetch(origin + "/certificates");
  assert.equal(certificatePage.status, 200);
  assert.match(certificatePage.headers.get("content-security-policy"), /form-action 'self'/);
  const home = await fetch(origin + "/index.html");
  assert.equal(home.status, 200, "Inventory must link back to the real Workbench in the fixture");
  const homeHTML = await home.text();
  assert.match(homeHTML, /DEMO — local Workbench with synthetic, read-only Inventory/);
  assert.match(homeHTML, /class="rail-item" href="\/certificates"/);
  assert.match(homeHTML, /No certificate uploads/);
  assert.doesNotMatch(homeHTML, /rootwell\.inventory\.workbench\.v1/, "GET must not hand off any saved certificate");
  assert.equal((await fetch(origin + "/")).url, origin + "/index.html");
  for (const asset of ["style.css", "theme.js", "inventory.css", "certificate-library.js", "saved-key-attachment.js"]) {
    const response = await fetch(origin + "/" + asset); assert.equal(response.status, 200);
    assert.equal(response.headers.get("cache-control"), "no-store");
  }
  assert.equal((await fetch(origin + "/index.html", { method: "POST" })).status, 405);
  assert.equal((await fetch(origin + "/index.html?certificate=unexpected")).status, 404);
  const inventory = await fetch(origin + "/api/inventory", { headers: { "X-Rootwell-Request": "1" } });
  assert.equal(inventory.status, 200);
  const result = await inventory.json();
  assert.equal(result.verification, "not-performed");
  assert.equal(result.monitoring.clock_source,"server-clock");
  assert.equal(result.monitoring.refresh_after_seconds,60);
  assert.ok(Number.isFinite(Date.parse(result.monitoring.checked_at)));
  assert.deepEqual(result.records.slice(0,3).map(record => record.expiry.status),["expired","soon","later"]);
  assert.equal(result.records[1].expiry.days_left,12);
  assert.equal(result.records.length, 4);
  assert.ok(result.records.slice(0,3).every(record => record.subject.includes("demo-")));
  assert.ok(result.records.every(record => !Object.hasOwn(record,"der")));
  assert.match(result.records[3].subject,/verify.rootwell.invalid/);
  assert.equal(result.records[3].staging_origin.test_only,true);
  assert.equal(result.records[3].staging_origin.provider,"letsencrypt-staging");
  assert.equal(result.records[3].staging_origin.verified_at,result.records[3].imported_at);
  const activity=await fetch(origin+"/api/inventory/activity",{headers:{"X-Rootwell-Request":"1"}});
  assert.equal(activity.status,200);
  const activityData=await activity.json();assert.equal(activityData.monitoring.status,"not-running","fixture cannot claim a running monitor");
  assert.equal(activityData.events[0].action,"import");assert.deepEqual(activityData.events[0].fingerprints,[result.records[3].fingerprint]);
  assert.equal((await fetch(origin+"/api/inventory/activity")).status,404);
  const compareBody=JSON.stringify({fingerprint:result.records[3].fingerprint,expected_generation:5});
  const compareHeaders={"Content-Type":"application/json",Origin:origin,"X-Rootwell-Request":"1"};
  const comparison=await fetch(origin+"/api/inventory/comparison-source",{method:"POST",headers:compareHeaders,body:compareBody});
  assert.equal(comparison.status,200);assert.equal((await comparison.json()).fingerprint,result.records[3].fingerprint);
  assert.equal((await fetch(origin+"/api/inventory/comparison-source",{method:"POST",body:compareBody})).status,403);
  assert.equal((await fetch(origin+"/api/inventory/comparison-source",{method:"POST",headers:compareHeaders,body:compareBody.replace(':5',':4')})).status,400);
  assert.equal((await fetch(origin+"/api/inventory/comparison-source",{method:"POST",headers:{...compareHeaders,Origin:"http://evil.invalid"},body:compareBody})).status,403);
  assert.equal((await fetch(origin+"/api/inventory/comparison-source")).status,404);
  const selection=new URLSearchParams({fingerprint:result.records[3].fingerprint,expected_generation:"5",tool:"inspect"});
  // fetch correctly forces Sec-Fetch-Mode:cors; model a browser navigation
  // explicitly here. The real form is exercised separately in the browser.
  const navigation=await new Promise((resolve,reject)=>{
    const request=http.request(origin+"/workbench",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded",
      Origin:origin,"Sec-Fetch-Site":"same-origin","Sec-Fetch-Mode":"navigate","Sec-Fetch-Dest":"document"}},response=>{
      let text=""; response.on("data",chunk=>{text+=chunk;}); response.on("end",()=>resolve({status:response.statusCode,text}));
    });
    request.on("error",reject); request.end(selection.toString());
  });
  assert.equal(navigation.status,200);
  assert.match(navigation.text,/rootwell.inventory.workbench.v1/);
  assert.match(navigation.text, /<main><aside class="nonclaim" aria-label="Demo mode"><strong>DEMO — synthetic public certificate only/);
	const renewalFields=new URLSearchParams({fingerprint:result.records[3].fingerprint,expected_generation:"5",tool:"renew"});
	const renewalNavigation=await new Promise((resolve,reject)=>{
	  const request=http.request(origin+"/automation/renew",{method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded",Origin:origin,"Sec-Fetch-Site":"same-origin","Sec-Fetch-Mode":"navigate","Sec-Fetch-Dest":"document"}},response=>{let text="";response.on("data",chunk=>{text+=chunk;});response.on("end",()=>resolve({status:response.statusCode,text}));});request.on("error",reject);request.end(renewalFields.toString());
	});
	assert.equal(renewalNavigation.status,200);assert.match(renewalNavigation.text,/rootwell.acme.renewal-selection.v1/);assert.match(renewalNavigation.text,/DEMO.*fake status only/);assert.doesNotMatch(renewalNavigation.text,/PRIVATE KEY|"private_key"/);
	assert.equal((await fetch(origin+"/automation/renew",{method:"POST",body:renewalFields.toString()})).status,403);
  assert.doesNotMatch(navigation.text, /<div id="inventory-source" hidden>[^<]*<\/div><aside/);
  assert.equal((await fetch(origin+"/workbench")).status,404);
  assert.equal((await fetch(origin+"/workbench",{method:"POST",body:selection.toString()})).status,403);
  assert.equal((await fetch(origin + "/api/inventory")).status, 404);
  assert.equal((await fetch(origin + "/api/inventory", { method: "POST", body: "never save" })).status, 405);
  for (const route of ["check", "save", "download"]) {
    assert.equal((await fetch(origin + "/api/certificates/" + route, {method:"POST",headers:compareHeaders,body:"{}"})).status,405);
  }
  assert.equal((await fetch(origin + "/../docs/ENGINEERING.md")).status, 404);
  const script = await (await fetch(origin + "/inventory.js")).text();
  assert.match(script, /addButton\.disabled = true/);
  assert.match(script, /editOwnerButton\.disabled = true/);
  assert.match(script, /manageLocationButton\.disabled = true/);
  assert.match(script, /deleteRecordButton\.disabled = true/);
  assert.doesNotMatch(script, /createObjectURL|public-inventory-export/);
  console.log("Rootwell read-only fake-data Inventory demo boundary passed.");
} finally {
  child.kill();
}
