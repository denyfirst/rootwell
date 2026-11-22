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
assert.match(html, /<link rel="stylesheet" href="\/rootwell\.css">/);
assert.match(html, /<a class="nav-item" href="\/website-check" aria-current="page">/);
assert.doesNotMatch(html, /type="checkbox"|demo|see an example|website-examples|synthetic/i, "no consent box, examples or demos on the page");

class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.textContent = ""; this.className = ""; this.attributes = {}; this.hidden = false; this.disabled = false; this.value = ""; this.listeners = {};
    this.classList = { add: (c) => { this.className = (this.className + " " + c).trim(); } }; }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  text() { return [this.textContent, ...this.children.map((c) => c.text())].join(" ").replace(/\s+/g, " ").trim(); }
  all(predicate) { return [this, ...this.children.flatMap((c) => c.all(predicate))].filter(predicate); }
}

function fixture({ reply, hash = "" } = {}) {
  const ids = {}; const byId = (id) => ids[id] ??= new Node("div");
  const requests = []; const docListeners = {};
  const document = { getElementById: byId, createElement: (t) => new Node(t), createElementNS: (_, t) => new Node(t), hidden: false,
    addEventListener: (name, fn) => { docListeners[name] = fn; } };
  vm.runInNewContext(source, {
    document, location: { hash }, setTimeout: () => 1, clearTimeout() {}, AbortController, Date, JSON, Number, decodeURIComponent,
    fetch: async (url, options) => { requests.push({ url, options }); return reply(); },
  });
  return { ids, requests, submit: async (site) => { ids.site.value = site; await ids["site-form"].listeners.submit({ preventDefault() {} }); } };
}
const answer = (status, body) => ({ ok: status === 200, status, text: async () => (typeof body === "string" ? body : JSON.stringify(body)) });
const leaf = { fingerprint: "AA", subject: "CN=shop.example.com", role: "leaf", sent: true, in_date: true, not_after: new Date(Date.now() + 74 * 86400000).toISOString() };
const inter = { fingerprint: "BB", subject: "CN=R11", role: "intermediate", sent: true, in_date: true, not_after: new Date(Date.now() + 500 * 86400000).toISOString() };
const root = { fingerprint: "CC", subject: "CN=ISRG Root X1", role: "root", sent: false, in_date: true, not_after: new Date(Date.now() + 3000 * 86400000).toISOString() };
const healthy = { hostname: "shop.example.com", state: "verified", trusted: true, path: [leaf, inter, root], presented: [leaf, inter], findings: [], observed_at: new Date().toISOString(), tls_version: "TLS 1.3", address: "203.0.113.5" };

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
  assert.match(page.text(), /Trusted root/);
  assert.match(page.text(), /Nothing to fix/);
}

// A broken site: the failed finding leads, its fix is listed.
{
  const broken = { ...healthy, state: "failed", trusted: false, path: [], presented: [leaf],
    findings: [{ code: "missing", level: "failed", title: "A certificate is missing", detail: "The server does not send the intermediate.", action: "Serve the full chain." }] };
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
  [() => answer(400, "Enter a public DNS name or HTTPS origin."), /public DNS name/],
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

console.log("Website check draws the verdict, chain and fix, and refuses empty or failed checks plainly.");
