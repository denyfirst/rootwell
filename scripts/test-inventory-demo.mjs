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
