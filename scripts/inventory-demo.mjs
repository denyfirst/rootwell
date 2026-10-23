// Read-only loopback fixture for reviewing the real Inventory UI on hosts
// where durable inventory is intentionally unavailable. Never serves user data.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import http from "node:http";
import { X509Certificate } from "node:crypto";

if (process.argv[2] !== "--fixture-only" ||
    (process.argv.length !== 3 && !(process.argv.length === 5 && process.argv[3] === "--port" && /^(0|[1-9]\d{0,4})$/.test(process.argv[4]) && Number(process.argv[4]) <= 65535))) {
  throw new Error("Run only with --fixture-only. This is not the Rootwell daemon.");
}
const port = process.argv.length === 5 ? Number(process.argv[4]) : 4181;

const asset = name => readFileSync(new URL("../cmd/rootwelld/auth/" + name, import.meta.url), "utf8");
function replaceOnce(source, before, after) {
  assert.equal(source.split(before).length, 2, "UI fixture marker changed; update the demo before use");
  return source.replace(before, after);
}
let html = asset("inventory.html");
html = replaceOnce(html, "<main>", `<main><aside class="storage-note" aria-label="Demo mode"><strong>DEMO — generated fake records only</strong><p>This is a read-only visual preview on this computer, not your encrypted inventory. Save, editing, and backup are disabled. Never enter a real certificate or secret here.</p></aside>`);
html = replaceOnce(html, '<form id="inventory-form">', '<form id="inventory-form" data-read-only="true">');
html = replaceOnce(html, '<form id="certificate-pair-form">', '<form id="certificate-pair-form" data-read-only="true">');
let script = asset("inventory.js");
script=replaceOnce(script,'addText(item, "strong", record.subject || "Subject not provided");','addText(item, "strong", record.subject || "Subject not provided"); if (record.staging_origin) addText(item, "small", "DEMO · status example only, not a real CA receipt");');
for (const button of ["addButton", "editOwnerButton", "manageLocationButton", "deleteRecordButton"]) {
  script = replaceOnce(script, `details.appendChild(${button});`, `${button}.disabled = true; details.appendChild(${button});`);
}

const instant = days => new Date(Date.now() + days * 86400000).toISOString().slice(0, 19) + "Z";
const records = [
  { fingerprint: "a".repeat(64), subject: "CN=demo-expired.example", issuer: "CN=Demo CA", dns_names: ["demo-expired.example"],
    not_before: instant(-200), not_after: instant(-2), owner: "Demo platform team", location: "demo/nginx",
    locations: ["demo/nginx"], import_generation: 2, imported_at: instant(-100) },
  { fingerprint: "b".repeat(64), subject: "CN=demo-renew-soon.example", issuer: "CN=Demo CA", dns_names: ["demo-renew-soon.example"],
    not_before: instant(-100), not_after: instant(12), owner: "", location: "",
    locations: [], import_generation: 3, imported_at: instant(-20) },
  { fingerprint: "c".repeat(64), subject: "CN=demo-ok.example", issuer: "CN=Demo CA", dns_names: ["demo-ok.example"],
    not_before: instant(-30), not_after: instant(180), owner: "Demo operations", location: "demo/haproxy",
    locations: ["demo/haproxy", "demo/fortinet"], import_generation: 4, imported_at: instant(-10) }
];
const demoLeaf = new X509Certificate(readFileSync(new URL("../web/workbench/rootwell-verify-demo-leaf.pem", import.meta.url)));
script=replaceOnce(script,"details.appendChild(compareButton);",`compareButton.disabled = record.fingerprint !== ${JSON.stringify(demoLeaf.fingerprint256)}; details.appendChild(compareButton);`);
script=replaceOnce(script,"item.appendChild(downloadButton);","downloadButton.disabled = true; item.appendChild(downloadButton);");
records.push({ fingerprint: demoLeaf.fingerprint256, subject: demoLeaf.subject, issuer: demoLeaf.issuer,
  dns_names: ["verify.rootwell.invalid"], not_before: new Date(demoLeaf.validFrom).toISOString().slice(0,19)+"Z",
  not_after: new Date(demoLeaf.validTo).toISOString().slice(0,19)+"Z", owner: "Synthetic public certificate",
  location: "", locations: [], import_generation: 5, imported_at: instant(-1), has_private_key:true,key_status:"matched",
  staging_origin:{test_only:true,provider:"letsencrypt-staging",verified_at:instant(-1),root_fingerprint:new X509Certificate(readFileSync(new URL("../web/workbench/rootwell-verify-demo-root.pem",import.meta.url))).fingerprint256} });
// All statuses above are fake read-only UI examples, including the key/origin.
// The public demo certificate was NOT issued by Let's Encrypt staging.
records[3].staging_origin.verified_at=records[3].imported_at;
script = replaceOnce(script, "openForm.appendChild(button);",
  `button.disabled = record.fingerprint !== ${JSON.stringify(demoLeaf.fingerprint256)}; openForm.appendChild(button);`);
function fixture() {
  const checkedAt = instant(0);
  const now = Date.parse(checkedAt);
  return JSON.stringify({ generation: 5, verification: "not-performed",
    monitoring: { checked_at: checkedAt, clock_source: "server-clock", refresh_after_seconds: 60 },
    records: records.map(record => {
      const seconds = (Date.parse(record.not_after) - now) / 1000;
      const status = seconds <= 0 ? "expired" : seconds <= 30*86400 ? "soon" : seconds <= 90*86400 ? "medium" : "later";
      return { ...record, expiry: { status, days_left: seconds > 0 ? Math.ceil(seconds/86400) : Math.trunc(seconds/86400) } };
    }) });
}
const assets = new Map([
  ["/inventory", ["text/html; charset=utf-8", html]],
  ["/certificates", ["text/html; charset=utf-8", html]],
  ["/inventory.css", ["text/css; charset=utf-8", asset("inventory.css")]],
  ["/inventory.js", ["text/javascript; charset=utf-8", script]],
  ...["inventory-engine.js", "inventory-import.js", "inventory-lifecycle.js", "certificate-library.js", "saved-key-attachment.js"].map(name => ["/"+name, ["text/javascript; charset=utf-8", asset(name)]])
]);
// Visual QA only: one FAKE completed status, no account/order/key or CA I/O.
// The actual source renders the next step; every mutation still returns 405.
let automationHTML=replaceOnce(asset("acme.html"),"<main>",'<main><aside class="storage-note" aria-label="Demo mode"><strong>DEMO — fake renewal result, no CA connection or private key</strong><p>Read-only visual preview. Use “Check saved DNS request” to see the example result. All dates, saved/key statuses and renewal identities below are simulated, not a CA receipt or actual saved pairs. Password and consent are disabled; never enter real secrets here. Real test issuance requires your Linux or Linux Docker Rootwell.</p></aside>');
for(const id of ["dns-config-zone","dns-config-zone-id","dns-config-token","dns-config-password","dns-config-consent","dns-config-action","dns-operation-password","dns-operation-consent","dns-operation-exclusive"]){
  automationHTML=replaceOnce(automationHTML,`id="${id}"`, `id="${id}" disabled`);
}
let dnsConfigScript=replaceOnce(asset("cloudflare-config.js"),"button.disabled=!!active", "button.disabled=true || !!active");
assets.set("/cloudflare-config.js",["text/javascript; charset=utf-8",dnsConfigScript]);
let dnsOperationScript=replaceOnce(asset("dns-operation.js"),"button.disabled=!!active","button.disabled=true || !!active");
assets.set("/dns-operation.js",["text/javascript; charset=utf-8",dnsOperationScript]);
automationHTML=replaceOnce(automationHTML,'<details id="cloudflare-dns">','<details id="cloudflare-dns"><p class="storage-note">DEMO · four independent fake DNS status examples, not the test request below. No Cloudflare connection, token or DNS change. Password, consent and operations are disabled.</p>');
automationHTML=replaceOnce(automationHTML,'<section class="card" id="certificate-request">','<section class="card" id="certificate-request"><p class="storage-note">DEMO · fake status only, no saved key or CA operation. Actions disabled.</p>');
let automationScript=replaceOnce(asset("acme-order.js"),"refresh.disabled=!!active; names.disabled=!!active; consent.disabled=!!active; password.disabled=!!active; resumeChoice.disabled=!!active;","refresh.disabled=!!active; names.disabled=true; consent.disabled=true; password.disabled=true; resumeChoice.disabled=true;");
automationScript=replaceOnce(automationScript,"submit.disabled=!!active || document.hidden", "submit.disabled=true || !!active || document.hidden");
assets.set("/automation",["text/html; charset=utf-8",automationHTML]);
assets.set("/acme-order.js",["text/javascript; charset=utf-8",automationScript]);
for(const name of ["acme-setup.js","acme-directory.js","acme-account.js","acme-registration.js"])assets.set("/"+name,["text/javascript; charset=utf-8",asset(name)]);
const workbenchTypes = new Map([
  ["worker-browser-smoke.html","text/html; charset=utf-8"], ["worker-browser-smoke.js","text/javascript; charset=utf-8"],
  ["style.css","text/css; charset=utf-8"], ["favicon.svg","image/svg+xml"], ["rootwell.wasm","application/wasm"],
  ...["app.js","wasm-loader.js","wasm_exec.js","theme.js","secret-view.js","private-key.js","private-worker-client.js",
    "private-key-worker.js","pfx.js","pfx-worker-client.js","pfx-worker.js","csr.js","csr-worker-client.js","csr-worker.js","certificate-key-match.js"].map(name=>[name,"text/javascript; charset=utf-8"]),
  ...["rootwell-demo-certificate.pem","rootwell-demo-bundle.pem","rootwell-verify-demo-leaf.pem","rootwell-verify-demo-intermediate.pem",
    "rootwell-verify-demo-root.pem","rootwell-verify-demo-ca-files.pem"].map(name=>[name,"application/x-pem-file"])
]);
const workbenchHTML = () => readFileSync(new URL("../web/workbench/index.html",import.meta.url),"utf8");
const server = http.createServer((request, response) => {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", request.url === "/inventory" ? "same-origin" : "no-referrer");
  response.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self' 'wasm-unsafe-eval'; img-src 'self'; connect-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'none'; form-action " + (["/inventory", "/certificates"].includes(request.url) ? "'self'" : "'none'") + "; frame-ancestors 'none'");
  if (request.headers.host !== "127.0.0.1:"+server.address().port) { response.writeHead(400).end("Fixture host refused"); return; }
  if(request.method==="POST"&&request.url==="/api/dns/cloudflare/status"){
    if(request.headers.origin!=="http://"+request.headers.host||request.headers["x-rootwell-request"]!=="1"||request.headers["content-type"]!=="application/json"){response.writeHead(403).end("Fixture status refused");return;}
    let body="",oversized=false;request.on("data",chunk=>{body+=chunk.toString();if(body.length>1024){oversized=true;body="";}});
    request.on("end",()=>{
      if(oversized||body!==JSON.stringify({provider:"cloudflare"})){response.writeHead(400).end("Fixture status refused");return;}
      response.writeHead(200,{"Content-Type":"application/json; charset=utf-8"}).end(JSON.stringify({schema_version:"rootwell.dns.config.v1",provider:"cloudflare",generation:5,state:"not-configured",zone_name:"",saved_at:"",can_change:true,network_used:false,token_verified:false,dns_changed:false}));
    });return;
  }
  if(request.method==="POST"&&request.url==="/api/acme/dns/status"){
    if(request.headers.origin!=="http://"+request.headers.host || request.headers["x-rootwell-request"]!=="1" || request.headers["content-type"]!=="application/json"){response.writeHead(403).end("Fixture status refused");return;}
    let body="",oversized=false;request.on("data",chunk=>{body+=chunk.toString();if(body.length>1024){oversized=true;body="";}});
    request.on("end",()=>{
      if(oversized || body!==JSON.stringify({provider:"cloudflare"})){response.writeHead(400).end("Fixture status refused");return;}
      const prepared=instant(-1),wait=new Date(Date.now()+120000).toISOString().slice(0,19)+"Z";
      const rows=[["api.example.com","created"],["legacy.example.com","borrowed"],["mail.example.com","creating"],["shop.example.com","deleted"]].map(([domain,state])=>({domain,name:"_acme-challenge."+domain,state,attempts:1,not_before:wait,blocked:false,cleanup_attempts:state==="deleted"?1:0,cleanup_not_before:state==="deleted"?wait:"",cleanup_blocked:false,checked_at:state==="creating"?"":prepared}));
      response.writeHead(200,{"Content-Type":"application/json; charset=utf-8"}).end(JSON.stringify({schema_version:"rootwell.dns.operation.v1",provider:"cloudflare",generation:40,network_used:false,zone_name:"example.com",server_time:instant(0),can_prepare:false,pending_domains:[],prepared:true,prepared_at:prepared,expires:instant(1),records:rows}));
    });return;
  }
  if(request.method==="POST"&&request.url==="/api/acme/order/status"){
    if(request.headers.origin!=="http://"+request.headers.host||request.headers["x-rootwell-request"]!=="1"||request.headers["content-type"]!=="application/json"){response.writeHead(403).end("Fixture status refused");return;}
    let body="",oversized=false;request.on("data",chunk=>{body+=chunk.toString();if(body.length>1024){oversized=true;body="";}});
    request.on("end",()=>{
      if(oversized||body!==JSON.stringify({provider:"letsencrypt-staging"})){response.writeHead(400).end("Fixture status refused");return;}
      const originalExpiry=instant(2),newExpiry=instant(90),preparedAt=instant(-1),requestExpiry=instant(1);
      response.writeHead(200,{"Content-Type":"application/json; charset=utf-8"}).end(JSON.stringify({schema_version:"rootwell.acme.manual-dns.v8",provider:"letsencrypt-staging",generation:5,state:"domain-verified",domains:["verify.rootwell.invalid"],expires:requestExpiry,records:[{domain:"verify.rootwell.invalid",name:"_acme-challenge.verify.rootwell.invalid",value:"",required:false}],renewal_source:demoLeaf.fingerprint256,renewal_result:{original_fingerprint:demoLeaf.fingerprint256,new_fingerprint:Array(32).fill("DD").join(":"),original_expiry:originalExpiry,new_expiry:newExpiry,expiry_extended:true},network_used:false,saved:true,domain_verified:true,can_issue:false,certificate_key:{prepared:true,fingerprint:Array(32).fill("AB").join(":"),prepared_at:preparedAt},issuance:{state:"certificate-saved",started_at:preparedAt,checked_at:preparedAt,observation:"saved",expires:requestExpiry},new_request:{available:true,reason:"complete",closed_count:1}}));
    });return;
  }
  if (request.method === "POST" && request.url === "/workbench") {
    if (request.headers.origin !== "http://"+request.headers.host || request.headers["sec-fetch-site"] !== "same-origin" ||
        request.headers["sec-fetch-mode"] !== "navigate" || request.headers["sec-fetch-dest"] !== "document" ||
        request.headers["content-type"] !== "application/x-www-form-urlencoded") { response.writeHead(403).end("Fixture navigation refused"); return; }
    let body="", refused=false;
    request.on("data", chunk=>{ body+=chunk.toString(); if(body.length>1024) { refused=true; body=""; } });
    request.on("end",()=>{
      const fields=new URLSearchParams(body);
      if (refused || [...fields].length!==3 || fields.get("fingerprint")!==demoLeaf.fingerprint256 || fields.get("expected_generation")!=="5" ||
          !["inspect","verify","convert"].includes(fields.get("tool"))) { response.writeHead(400).end("Fixture selection refused"); return; }
      const payload=JSON.stringify({ schema_version:"rootwell.inventory.workbench.v1", fingerprint:demoLeaf.fingerprint256,
        der:demoLeaf.raw.toString("base64"),tool:fields.get("tool") });
      let page=replaceOnce(workbenchHTML(), '<div id="inventory-source" hidden></div>',
        '<div id="inventory-source" hidden>'+payload+'</div>');
      // Keep the workspace's two body-level grid children unchanged. The
      // demo notice belongs inside main, not beside the navigation rail.
      page=replaceOnce(page, '<main>', '<main><aside class="nonclaim" aria-label="Demo mode"><strong>DEMO — synthetic public certificate only. No authentication or saved user data.</strong></aside>');
      response.writeHead(200,{"Content-Type":"text/html; charset=utf-8"}).end(page);
    });
    return;
  }
	if(request.method==="POST" && request.url==="/automation/renew"){
	  if(request.headers.origin!=="http://"+request.headers.host || request.headers["sec-fetch-site"]!=="same-origin" || request.headers["sec-fetch-mode"]!=="navigate" || request.headers["sec-fetch-dest"]!=="document" || request.headers["content-type"]!=="application/x-www-form-urlencoded"){response.writeHead(403).end("Fixture navigation refused");return;}
	  let body="",refused=false;request.on("data",chunk=>{body+=chunk.toString();if(body.length>1024){refused=true;body="";}});
	  request.on("end",()=>{
		const fields=new URLSearchParams(body);
		if(refused || [...fields].length!==3 || fields.get("fingerprint")!==demoLeaf.fingerprint256 || fields.get("expected_generation")!=="5" || fields.get("tool")!=="renew"){response.writeHead(400).end("Fixture selection refused");return;}
		const selection=JSON.stringify({schema_version:"rootwell.acme.renewal-selection.v1",generation:5,fingerprint:demoLeaf.fingerprint256,domains:records[3].dns_names});
		const page=replaceOnce(automationHTML,'<div id="acme-renewal-source" hidden></div>','<div id="acme-renewal-source" hidden>'+selection+'</div>');
		response.writeHead(200,{"Content-Type":"text/html; charset=utf-8"}).end(page);
	  });return;
	}
  if (request.method === "GET" && request.url === "/") {
    response.writeHead(302, { Location: "/index.html" }).end();
    return;
  }
  if (request.method === "GET" && request.url === "/index.html") {
    const page = replaceOnce(workbenchHTML(), '<main>', '<main><aside class="nonclaim" aria-label="Demo mode"><strong>DEMO — local Workbench with synthetic, read-only Inventory. No authentication or saved user data.</strong></aside>');
    response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }).end(page);
    return;
  }
  if (request.method === "GET" && request.url === "/api/inventory" && request.headers["x-rootwell-request"] === "1") {
    response.writeHead(200, { "Content-Type": "application/json; charset=utf-8" }).end(fixture());
    return;
  }
  if(request.method==="GET"&&request.url==="/api/inventory/activity"&&request.headers["x-rootwell-request"]==="1"){
    response.writeHead(200,{"Content-Type":"application/json; charset=utf-8"}).end(JSON.stringify({schema_version:"rootwell.inventory.activity.v1",generation:5,
      events:[{generation:5,at:records[3].imported_at,action:"import",fingerprints:[demoLeaf.fingerprint256]}],monitoring:{status:"not-running",attention:[]}}));return;
  }
  if(request.method==="POST"&&request.url==="/api/inventory/comparison-source"){
    if(request.headers.origin!=="http://"+request.headers.host||request.headers["sec-fetch-site"]==="cross-site"||request.headers["x-rootwell-request"]!=="1"||request.headers["content-type"]!=="application/json"){response.writeHead(403).end("Fixture source refused");return;}
    let body="",oversized=false;request.on("data",chunk=>{body+=chunk.toString();if(body.length>1024){oversized=true;body="";}});
    request.on("end",()=>{if(oversized||body!==JSON.stringify({fingerprint:demoLeaf.fingerprint256,expected_generation:5})){response.writeHead(400).end("Fixture source refused");return;}
      response.writeHead(200,{"Content-Type":"application/json; charset=utf-8"}).end(JSON.stringify({schema_version:"rootwell.inventory.comparison-source.v1",fingerprint:demoLeaf.fingerprint256,generation:5,der:demoLeaf.raw.toString("base64")}));});return;
  }
  const selected = request.method === "GET" ? assets.get(request.url) : null;
  if (selected) response.writeHead(200, { "Content-Type": selected[0] }).end(selected[1]);
  else if (request.method === "GET" && workbenchTypes.has(request.url.slice(1))) {
    const name=request.url.slice(1);
    try { response.writeHead(200,{"Content-Type":workbenchTypes.get(name)}).end(readFileSync(new URL("../web/workbench/"+name,import.meta.url))); }
    catch { response.writeHead(503).end("Build demo assets first"); }
  }
  else response.writeHead(request.method === "GET" ? 404 : 405).end("Fixture is read-only");
});
server.listen(port, "127.0.0.1", () => {
  process.stdout.write("Read-only fake-data Inventory demo: http://127.0.0.1:" + server.address().port + "/inventory\n");
});
