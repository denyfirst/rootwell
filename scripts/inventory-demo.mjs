// Read-only loopback fixture for reviewing the real Inventory UI on hosts
// where durable inventory is intentionally unavailable. Never serves user data.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import http from "node:http";

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
html = replaceOnce(html, "<main>", `<main><aside class="boundary" aria-label="Demo mode"><strong>DEMO — generated fake records only</strong><p>This is a read-only visual preview on this computer, not your encrypted inventory. Save, editing, and backup are disabled. Never enter a real certificate or secret here.</p></aside>`);
html = replaceOnce(html, 'id="certificate-file" type="file"', 'id="certificate-file" type="file" disabled');
html = replaceOnce(html, '<button id="save-button" type="submit">', '<button id="save-button" type="submit" disabled>');
let script = asset("inventory.js");
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
function fixture() {
  const checkedAt = instant(0);
  const now = Date.parse(checkedAt);
  return JSON.stringify({ generation: 4, verification: "not-performed",
    monitoring: { checked_at: checkedAt, clock_source: "server-clock", refresh_after_seconds: 60 },
    records: records.map(record => {
      const seconds = (Date.parse(record.not_after) - now) / 1000;
      const status = seconds <= 0 ? "expired" : seconds <= 30*86400 ? "soon" : seconds <= 90*86400 ? "medium" : "later";
      return { ...record, expiry: { status, days_left: seconds > 0 ? Math.ceil(seconds/86400) : Math.trunc(seconds/86400) } };
    }) });
}
const assets = new Map([
  ["/inventory", ["text/html; charset=utf-8", html]],
  ["/inventory.css", ["text/css; charset=utf-8", asset("inventory.css")]],
  ["/inventory.js", ["text/javascript; charset=utf-8", script]]
]);
const server = http.createServer((request, response) => {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'");
  if (request.method === "GET" && request.url === "/") {
    response.writeHead(302, { Location: "/inventory" }).end();
    return;
  }
  if (request.method === "GET" && request.url === "/api/inventory" && request.headers["x-rootwell-request"] === "1") {
    response.writeHead(200, { "Content-Type": "application/json; charset=utf-8" }).end(fixture());
    return;
  }
  const selected = request.method === "GET" ? assets.get(request.url) : null;
  if (selected) response.writeHead(200, { "Content-Type": selected[0] }).end(selected[1]);
  else response.writeHead(request.method === "GET" ? 404 : 405).end("Fixture is read-only");
});
server.listen(port, "127.0.0.1", () => {
  process.stdout.write("Read-only fake-data Inventory demo: http://127.0.0.1:" + server.address().port + "/inventory\n");
});
