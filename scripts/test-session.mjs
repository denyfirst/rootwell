import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

// Sign out from the rail: the server must confirm before the page leaves, and
// the script stays a network-only helper that never touches files or storage.
const source = fs.readFileSync(new URL("../web/workbench/session.js", import.meta.url), "utf8");
for (const forbidden of ["FileReader", "arrayBuffer", ".files", "localStorage", "sessionStorage", "indexedDB",
  "innerHTML", "Worker(", "import(", "eval(", "XMLHttpRequest", "sendBeacon", "WebSocket"]) {
  assert.ok(!source.includes(forbidden), `session.js must not use ${forbidden}`);
}
assert.deepEqual([...source.matchAll(/fetch\("([^"]+)"/g)].map((m) => m[1]), ["/api/session"],
  "session.js talks only to the session endpoint");

// The six pages in the menu.
for (const page of ["../web/workbench/certificates.html", "../cmd/rootwelld/auth/website-check.html", "../web/workbench/inspect.html",
  "../web/workbench/convert.html", "../web/workbench/request.html", "../cmd/rootwelld/auth/account.html"]) {
  const html = fs.readFileSync(new URL(page, import.meta.url), "utf8");
  assert.match(html, /<script src="\/?session\.js" defer><\/script>/, `${page} loads session.js`);
  assert.match(html, /<button class="(?:nav-item|shell-button)" id="rail-sign-out" type="button" hidden>/, `${page} has Sign out in its rail`);
  assert.equal((html.match(/aria-current="page"/g) || []).length, 1, `${page} marks exactly one current place`);
}

function fixture(reply) {
  const listeners = {};
  const label = { textContent: "Sign out" };
  const button = { hidden: true, disabled: false, querySelector: (selector) => (assert.equal(selector, "span"), label),
    addEventListener: (name, fn) => { listeners[name] = fn; } };
  const requests = [], visits = [];
  vm.runInNewContext(source, {
    document: { getElementById: (id) => (assert.equal(id, "rail-sign-out"), button),
      addEventListener: (name, fn) => { assert.equal(name, "DOMContentLoaded"); fn(); } },
    window: {
      fetch: async (url, options) => { requests.push({ url, options }); return reply(); },
      location: { assign: (url) => visits.push(url) },
    },
  });
  return { button, label, requests, visits, click: () => listeners.click() };
}

// Confirmed by the server: leave for the sign-in page.
const ok = fixture(() => ({ status: 204 }));
assert.equal(ok.button.hidden, false);
await ok.click();
assert.equal(ok.requests.length, 1);
assert.equal(ok.requests[0].url, "/api/session");
assert.equal(ok.requests[0].options.method, "DELETE");
assert.equal(ok.requests[0].options.headers["X-Rootwell-Request"], "1");
assert.equal(ok.requests[0].options.credentials, "same-origin");
assert.equal(ok.requests[0].options.redirect, "error");
assert.deepEqual(ok.visits, ["/login"]);

// Refused or lost: stay, say so, and allow another try.
for (const reply of [() => ({ status: 403 }), () => ({ status: 200 }), () => { throw new Error("offline"); }]) {
  const failed = fixture(reply);
  await failed.click();
  assert.deepEqual(failed.visits, []);
  assert.equal(failed.label.textContent, "Sign out failed; try again");
  assert.equal(failed.button.disabled, false);
}

// A second click while the first is pending sends nothing more.
let release;
const pending = fixture(() => new Promise((resolve) => { release = () => resolve({ status: 204 }); }));
const first = pending.click();
const second = pending.click();
assert.equal(pending.requests.length, 1, "a second click while pending must send nothing");
release();
await first;
await second;
assert.deepEqual(pending.visits, ["/login"]);

console.log("Sign out confirms with the server before leaving and reads no files.");
