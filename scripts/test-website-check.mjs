import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

// Website check: a verdict, the chain the server sends and what to fix, built
// from the server's report with textContent only; one request per check.
const source = fs.readFileSync(new URL("../cmd/rootwelld/auth/website-check.js", import.meta.url), "utf8");
const html = fs.readFileSync(new URL("../cmd/rootwelld/auth/website-check.html", import.meta.url), "utf8");
for (const forbidden of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "localStorage", "sessionStorage"]) {
  assert.ok(!source.includes(forbidden), `website-check.js must not use ${forbidden}`);
}
assert.deepEqual([...source.matchAll(/fetch\("([^"]+)"/g)].map((m) => m[1]), ["/api/website-check"]);
// Besides the check, the page asks only for the watched sites, to watch one,
// and to stop watching one.
assert.deepEqual([...new Set([...source.matchAll(/"(\/api\/[^"]+)"/g)].map((m) => m[1]))].sort(), ["/api/watch", "/api/watch/add", "/api/watch/remove", "/api/website-check"]);
assert.match(html, /<link rel="stylesheet" href="\/rootwell\.css">/);
assert.match(html, /<a class="nav-item" href="\/website-check" aria-current="page">/);
assert.doesNotMatch(html, /type="checkbox"|demo|see an example|website-examples|synthetic/i, "no consent box, examples or demos on the page");

class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.textContent = ""; this.className = ""; this.attributes = {}; this.hidden = false; this.disabled = false; this.value = ""; this.listeners = {}; this.type = "";
    this.classList = { add: (c) => { this.className = (this.className + " " + c).trim(); } }; }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  text() { return [this.textContent, ...this.children.map((c) => c.text())].join(" ").replace(/\s+/g, " ").trim(); }
  all(predicate) { return [this, ...this.children.flatMap((c) => c.all(predicate))].filter(predicate); }
}

// watch is the stand-in for /api/watch: the sites, and whether a phone code
// was entered lately.
function fixture({ reply, hash = "", watch = { sites: [], fresh: true, freshAsked: 0, calls: [] } } = {}) {
  const ids = {}; const byId = (id) => ids[id] ??= new Node("div");
  const requests = []; const docListeners = {};
  const watchReply = (url, options) => {
    const body = options.body ? JSON.parse(options.body) : null;
    watch.calls.push({ url, method: options.method, body });
    if (url === "/api/watch") return answer(200, { sites: watch.sites });
    if (url === "/api/watch/add") { watch.sites.push({ target: body.target, added_at: "2026-11-27T10:00:00Z" }); return answer(201, watch.sites.at(-1)); }
    if (!watch.fresh) return answer(428, "Enter a code from your phone first.");
    watch.sites = watch.sites.filter((site) => site.target !== body.target);
    return answer(204, "");
  };
  const document = { getElementById: byId, createElement: (t) => new Node(t), createElementNS: (_, t) => new Node(t), hidden: false,
    addEventListener: (name, fn) => { docListeners[name] = fn; } };
  vm.runInNewContext(source, {
    document, location: { hash }, setTimeout: () => 1, clearTimeout() {}, AbortController, Date, JSON, Number, URL, decodeURIComponent,
    fetch: async (url, options) => { if (url.startsWith("/api/watch")) return watchReply(url, options); requests.push({ url, options }); return reply(); },
    rootwellFresh: async () => { watch.freshAsked++; watch.fresh = true; return true; },
  });
  return { ids, requests, watch, submit: async (site) => { ids.site.value = site; await ids["site-form"].listeners.submit({ preventDefault() {} }); } };
}
const answer = (status, body) => ({ ok: status >= 200 && status < 300, status, text: async () => (typeof body === "string" ? body : JSON.stringify(body)) });
const days = (n) => new Date(Date.now() + n * 86400000).toISOString();
const leaf = { fingerprint: "AA", subject: "shop.example.com", issuer: "R11", role: "leaf", sent: true, in_date: true, use: "path", not_after: days(74) };
const inter = { fingerprint: "BB", subject: "R11", issuer: "ISRG Root X1", role: "intermediate", sent: true, in_date: true, use: "path", not_after: days(500) };
const root = { fingerprint: "CC", subject: "ISRG Root X1", role: "trust-anchor", sent: false, in_date: true, use: "path", not_after: days(3000) };
const healthy = { hostname: "shop.example.com", port: 443, state: "verified", trusted: true, trust_source: "public", path: [leaf, inter, root], presented: [leaf, inter], findings: [], observed_at: new Date().toISOString(), tls_version: "TLS 1.3", address: "203.0.113.5" };
const note = (code, title, certificates = []) => ({ code, level: "note", title, detail: title + " detail.", action: "", certificates });

// A healthy site: a good verdict, the whole chain with the root, nothing to fix.
{
  const f = fixture({ reply: () => answer(200, healthy) });
  await f.submit("  shop.example.com ");
  assert.equal(f.requests.length, 1);
  assert.equal(f.requests[0].options.method, "POST");
  assert.equal(f.requests[0].options.headers["X-Rootwell-Request"], "1");
  assert.deepEqual(JSON.parse(f.requests[0].options.body), { target: "shop.example.com", confirm: true });
  const page = f.ids["site-result"];
  assert.equal(page.hidden, false);
  assert.match(page.text(), /Everything is in order/);
  assert.equal(page.all((n) => /^link (ok|broken)$/.test(n.className)).length, 3);
  assert.match(page.text(), /74 days left/);
  // Long lives read as months and years, as on every other page.
  assert.match(page.text(), /16 months left/);
  assert.match(page.text(), /8 years left/);
  assert.doesNotMatch(page.text(), /500 days|3000 days/);
  assert.match(page.text(), /Built into devices/);
  assert.match(page.text(), /Nothing to fix/);
  assert.match(page.text(), /203\.0\.113\.5:443/);
  assert.match(page.text(), /does not check whether the certificate authority has revoked/);
  assert.doesNotMatch(page.text(), /Also sent by the server|Needs a fix|Good to know/);
}

// What emanat.az sends: the chain, an older chain for old devices and a root.
// All green, both explained once, nothing to fix.
{
  const cross = { fingerprint: "DD", subject: "Root R46", role: "intermediate", sent: true, in_date: true, use: "older-path", not_after: days(4000) };
  const oldest = { fingerprint: "EE", subject: "AAA Certificate Services", role: "intermediate", sent: true, in_date: true, use: "root", not_after: days(760) };
  const report = { ...healthy, presented: [leaf, inter, cross, oldest], findings: [note("older-chain", "The server also sends a chain for older devices", ["DD"]), note("sent-root", "The server sends a root certificate", ["EE"])] };
  const f = fixture({ reply: () => answer(200, report) });
  await f.submit("emanat.az");
  const page = f.ids["site-result"];
  assert.match(page.text(), /Everything is in order/);
  assert.match(page.text(), /Nothing to fix/);
  assert.match(page.text(), /Also sent by the server/);
  assert.match(page.text(), /For older devices/);
  assert.match(page.text(), /Devices already have it/);
  assert.match(page.text(), /Good to know .*older devices/);
  assert.doesNotMatch(page.text(), /Needs a fix/);
  assert.equal(page.all((n) => /^link extra$/.test(n.className)).length, 2);
}

// A certificate that belongs to no chain is amber, named and listed to fix.
{
  const stray = { fingerprint: "FF", subject: "Old Issuer", role: "intermediate", sent: true, in_date: true, use: "unrelated", not_after: days(300) };
  const report = { ...healthy, state: "attention", presented: [leaf, inter, stray],
    findings: [{ code: "unrelated", level: "attention", title: "The server sends a certificate that does not belong here", detail: "\u201cOld Issuer\u201d is not part of any chain.", action: "Remove \u201cOld Issuer\u201d.", certificates: ["FF"] }] };
  const f = fixture({ reply: () => answer(200, report) });
  await f.submit("shop.example.com");
  const page = f.ids["site-result"];
  assert.match(page.children[0].className, /verdict soon/);
  assert.equal(page.all((n) => /^link warn$/.test(n.className)).length, 1);
  assert.match(page.text(), /Old Issuer Not part of this chain · Needs a fix/);
  assert.match(page.text(), /How to fix it .*Remove/);
}

// A missing intermediate is drawn where it should be, dashed.
{
  const report = { ...healthy, state: "failed", trusted: false, trust_source: "", path: [leaf], presented: [leaf],
    findings: [{ code: "missing-issuer", level: "failed", title: "\u201cR11\u201d is missing from the chain", detail: "The server does not send \u201cR11\u201d.", action: "Add \u201cR11\u201d after the website certificate.", certificates: [] }] };
  const f = fixture({ reply: () => answer(200, report) });
  await f.submit("shop.example.com");
  const page = f.ids["site-result"];
  const missing = page.all((n) => n.className === "link missing");
  assert.equal(missing.length, 1);
  assert.match(missing[0].text(), /R11 Missing · The server does not send it/);
  assert.equal(page.all((n) => n.className === "link broken").length, 0, "the website certificate itself is fine");
  assert.equal(page.text().split("The server does not send \u201cR11\u201d.").length - 1, 1, "the verdict's words are not repeated in the fix");
  assert.match(page.text(), /How to fix it .*Add \u201cR11\u201d after the website certificate\./);
}

// An internal server trusted through the person's own saved root.
{
  const saved = { ...root, subject: "Company Root" };
  const report = { ...healthy, hostname: "10.0.0.5", port: 8443, address: "10.0.0.5", trust_source: "saved", saved_root: "Company Root", path: [leaf, inter, saved],
    findings: [note("saved-root", "Trusted through your own root \u201cCompany Root\u201d", ["CC"])] };
  const f = fixture({ reply: () => answer(200, report) });
  await f.submit("10.0.0.5:8443");
  assert.deepEqual(JSON.parse(f.requests[0].options.body), { target: "10.0.0.5:8443", confirm: true });
  const text = f.ids["site-result"].text();
  assert.match(text, /10\.0\.0\.5:8443 sends a complete, valid certificate, trusted through your root \u201cCompany Root\u201d\./);
  assert.match(text, /Company Root Your saved root/);
  assert.match(text, /10\.0\.0\.5:8443/);
}

// A name in another script goes as its xn-- form, with its port.
{
  const f = fixture({ reply: () => answer(200, healthy) });
  await f.submit("bak\u0131.lab.az:8443");
  assert.deepEqual(JSON.parse(f.requests[0].options.body), { target: "xn--bak-lua.lab.az:8443", confirm: true });
  const g = fixture({ reply: () => answer(200, healthy) });
  await g.submit("bak\u0131.lab.az/path");
  assert.equal(g.requests.length, 0);
}

// A broken site: the failed finding leads, its fix is listed.
{
  const broken = { ...healthy, state: "failed", trusted: false, path: [], presented: [leaf],
    findings: [{ code: "missing", level: "failed", title: "A certificate is missing", detail: "The server does not send the intermediate.", action: "Serve the full chain.", certificates: [] }] };
  const f = fixture({ reply: () => answer(200, broken) });
  await f.submit("shop.example.com");
  const text = f.ids["site-result"].text();
  assert.match(text, /A certificate is missing/);
  assert.match(text, /How to fix it/);
  assert.match(text, /Serve the full chain\./);
  assert.match(f.ids["site-result"].children[0].className, /verdict bad/);
}

// Refusals and failures say so, in words, and keep the button usable.
for (const [reply, expected] of [
  [() => answer(400, "Enter a website name or address, with its port if it is not 443."), /name or address/],
  [() => answer(502, "Nothing answers on port 8443 at 10.0.0.5."), /Nothing answers on port 8443/],
  [() => answer(401, "sign in first"), /Sign in again/],
  [() => answer(200, "{not json"), /did not finish/],
  [() => answer(200, { hostname: "x" }), /did not finish/],
  [() => { throw new Error("offline"); }, /did not finish/],
]) {
  const f = fixture({ reply });
  await f.submit("shop.example.com");
  assert.match(f.ids["site-status"].textContent, expected);
  assert.equal(f.ids["site-check"].disabled, false);
  assert.equal(f.ids["site-result"].children.length, 0, "a failed check draws no result");
}

// A new check clears the last result first: a failure never stands above an
// older site's verdict.
{
  let n = 0;
  const f = fixture({ reply: () => (n++ === 0 ? answer(200, healthy) : answer(502, "10.0.0.5 did not answer on port 443 in time.")) });
  await f.submit("shop.example.com");
  assert.equal(f.ids["site-result"].hidden, false);
  await f.submit("10.0.0.5");
  assert.equal(f.ids["site-result"].children.length, 0);
  assert.equal(f.ids["site-result"].hidden, true);
  assert.match(f.ids["site-status"].textContent, /did not answer/);
}

// An empty or spaced entry sends nothing.
for (const bad of ["", "   ", "shop example.com"]) {
  const f = fixture({ reply: () => answer(200, healthy) });
  await f.submit(bad);
  assert.equal(f.requests.length, 0);
  assert.match(f.ids["site-status"].textContent, /Enter a website/);
}

// Certificates links here with the name after #.
{
  const f = fixture({ reply: () => answer(200, healthy), hash: "#mail.example.com" });
  assert.equal(f.ids.site.value, "mail.example.com");
}

// Watching: the list shows each site's state; a checked site can be watched,
// is then named Watched, and stopping asks for a phone code first.
{
  const settle = async () => { for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r)); };
  const watch = { sites: [{ target: "intranet.lab:8443", added_at: "2026-11-26T10:00:00Z", checked_at: "2026-11-27T08:00:00Z", state: "failed",
    problem: "The chain is incomplete", not_after: days(40) }], fresh: false, freshAsked: 0, calls: [] };
  const f = fixture({ reply: () => answer(200, healthy), watch });
  await settle();
  assert.equal(f.ids.watched.hidden, false);
  assert.equal(f.ids["watched-count"].textContent, "1 website");
  assert.match(f.ids["watched-list"].text(), /^intranet\.lab:8443 Checked .+ · its certificate lasts until .+ The chain is incomplete Problem Stop watching$/);
  await f.submit("shop.example.com");
  await settle();
  const row = f.ids["site-result"].children[1];
  assert.match(row.text(), /^Watch this site Rootwell checks it once a day/);
  await row.children[0].listeners.click();
  await settle();
  assert.deepEqual(watch.calls.filter((c) => c.url === "/api/watch/add").map((c) => c.body), [{ target: "shop.example.com" }]);
  assert.match(row.text(), /^Watched Rootwell checks it once a day\.$/);
  assert.equal(f.ids["watched-count"].textContent, "2 websites");
  assert.equal(f.requests.length, 1, "watching sends no second check");
  // Stopping: Rootwell asks for a phone code, then the site leaves the list.
  const stop = f.ids["watched-list"].children[0].children.at(-1);
  await stop.listeners.click();
  await settle();
  assert.equal(watch.freshAsked, 1);
  assert.deepEqual(watch.calls.filter((c) => c.url === "/api/watch/remove").map((c) => c.body), [{ target: "intranet.lab:8443" }, { target: "intranet.lab:8443" }]);
  assert.equal(f.ids["watched-count"].textContent, "1 website");
  // Clicking a watched site checks it again.
  f.ids["watched-list"].children[0].children[0].children[0].listeners.click();
  await settle();
  assert.equal(f.requests.length, 2);
  assert.deepEqual(JSON.parse(f.requests[1].options.body), { target: "shop.example.com", confirm: true });
}

console.log("Website check draws the verdict, chain and fix, refuses empty or failed checks plainly, and watches sites.");
