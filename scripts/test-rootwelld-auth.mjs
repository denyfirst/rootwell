import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = fs.readFileSync(new URL("../cmd/rootwelld/auth/auth.js", import.meta.url), "utf8");
assert.doesNotMatch(source, /innerHTML|localStorage|sessionStorage|console\.|sendBeacon/);
const loginResponse = (mode) => new Response(JSON.stringify({mode}), {headers:{"content-type":"application/json"}});
const changedResponse = () => new Response(null, {status:204});

function page(mode, fetchImpl) {
  const handlers = {}, redirects = [], timers = new Map(), requests = [];
  let timerId = 0;
  const elements = {
    "auth-form": {
      addEventListener(name, callback) { handlers[`form:${name}`] = callback; },
      querySelector() { return elements.submit; },
    },
    status: {textContent:""},
    password: {value:"initial test password", disabled:false},
    next: {value:"a long replacement password", disabled:false},
    confirm: {value:"a long replacement password", disabled:false},
    "sign-out": {
      disabled:false,
      addEventListener(name, callback) { handlers[`sign-out:${name}`] = callback; },
    },
    submit: {disabled:false},
  };
  const document = {
    hidden:false, body:{dataset:{mode}},
    getElementById(id) { return mode === "login" && ["next", "confirm", "sign-out"].includes(id) ? null : elements[id]; },
    addEventListener(name, callback) { handlers[name] = callback; },
  };
  vm.runInNewContext(source, {
    document,
    window: {
      location: {assign(url) { redirects.push(url); }},
      addEventListener(name, callback) { handlers[name] = callback; },
    },
    AbortController, TextDecoder, Uint8Array,
    setTimeout(fn, delay) { assert.equal(delay, 15000); const id = ++timerId; timers.set(id, fn); return id; },
    clearTimeout(id) { timers.delete(id); },
    fetch(url, options) { requests.push({url, options}); return fetchImpl(url, options); },
  }, {filename:"auth.js"});
  return {handlers, redirects, elements, requests, timers, document,
    submit() { return handlers["form:submit"]({preventDefault(){}}); },
    expire() { assert.equal(timers.size, 1); [...timers.values()][0](); },
  };
}
function finished(f) {
  assert.equal(f.elements.submit.disabled, false);
  assert.equal(f.elements.password.disabled, false);
  assert.equal(f.elements.password.value, "");
  if (f.document.body.dataset.mode !== "login") {
    for (const id of ["next", "confirm"]) { assert.equal(f.elements[id].value, ""); assert.equal(f.elements[id].disabled, false); }
    assert.equal(f.elements["sign-out"].disabled, false);
  }
  assert.equal(f.timers.size, 0);
  assert.doesNotMatch(f.elements.status.textContent, /secret-sentinel|initial test password|replacement password/);
}

for (const mode of ["setup", "ready"]) {
  const f = page("login", async () => loginResponse(mode));
  assert.equal(f.requests.length, 0, "login must not request on page load");
  await f.submit();
  const {url, options} = f.requests[0];
  assert.equal(url, "/api/session"); assert.equal(options.method, "POST");
  assert.equal(options.credentials, "same-origin"); assert.equal(options.cache, "no-store");
  assert.equal(options.headers["X-Rootwell-Request"], "1");
  assert.equal(JSON.parse(options.body).password, "initial test password");
  assert.deepEqual(f.redirects, [mode === "setup" ? "/setup" : "/"]);
  finished(f);
}
{
  const f = page("setup", async () => { throw new Error("fetch must not run"); });
  f.elements.confirm.value = "different";
  await f.submit();
  assert.match(f.elements.status.textContent, /do not match/i);
  assert.equal(f.requests.length, 0); assert.deepEqual(f.redirects, []);
}
for (const mode of ["setup", "account"]) {
  const f = page(mode, async () => changedResponse());
  await f.submit();
  assert.equal(f.requests[0].url, "/api/password");
  assert.equal(JSON.parse(f.requests[0].options.body).next, "a long replacement password");
  assert.deepEqual(f.redirects, ["/login"]); finished(f);
}
{
  const f = page("account", async () => changedResponse());
  await f.handlers["sign-out:click"]();
  assert.equal(f.requests[0].url, "/api/session"); assert.equal(f.requests[0].options.method, "DELETE");
  assert.equal(f.requests[0].options.body, undefined);
  assert.deepEqual(f.redirects, ["/login"]); finished(f);
}

// Refusals never reflect server text or retain entered credentials.
for (const status of [400, 401, 429, 500]) {
  const f = page("login", async () => new Response("secret-sentinel", {status}));
  await f.submit(); assert.deepEqual(f.redirects, []); finished(f);
}
for (const action of ["password", "logout"]) {
  for (const status of [400, 401, 429, 500]) {
    const f = page("account", async () => new Response("secret-sentinel", {status}));
    await (action === "password" ? f.submit() : f.handlers["sign-out:click"]());
    assert.deepEqual(f.redirects, []); finished(f);
  }
}
for (const text of ['null', '{"mode":"remote"}', '{"Mode":"ready"}', '{"mode":"ready","x":1}',
  '{"mode":"setup","mode":"ready"}', '<html>secret-sentinel</html>', 'x'.repeat(8193)]) {
  const f = page("login", async () => new Response(text, {headers:{"content-type":"application/json"}}));
  await f.submit(); assert.deepEqual(f.redirects, []); finished(f);
}
for (const response of [
  () => new Response('{"mode":"ready"}', {headers:{"content-type":"text/html"}}),
  () => new Response(new Uint8Array([0xff]), {headers:{"content-type":"application/json"}}),
  () => new Response(null, {headers:{"content-type":"application/json"}}),
  () => new Response('{"mode":"ready"}', {status:201, headers:{"content-type":"application/json"}}),
  () => { throw new Error("secret-sentinel"); },
]) {
  const f = page("login", async () => response()); await f.submit();
  assert.deepEqual(f.redirects, []); finished(f);
}
for (const action of ["password", "logout"]) {
  const f = page("account", async () => new Response("secret-sentinel"));
  await (action === "password" ? f.submit() : f.handlers["sign-out:click"]());
  assert.deepEqual(f.redirects, []); assert.match(f.elements.status.textContent, /could not be confirmed/); finished(f);
}

// Cancellation settles the UI even if synthetic fetch ignores AbortSignal.
for (const action of ["login", "password", "logout"]) {
  for (const boundary of ["deadline", "hidden", "pagehide"]) {
    let release;
    const f = page(action === "login" ? "login" : "account", () => new Promise(resolve => { release = resolve; }));
    const work = action === "logout" ? f.handlers["sign-out:click"]() : f.submit();
    assert.equal(f.elements.submit.disabled, true); assert.equal(f.elements.password.value, "");
    if (boundary === "deadline") f.expire();
    else if (boundary === "hidden") { f.document.hidden = true; f.handlers.visibilitychange(); }
    else f.handlers.pagehide();
    await work;
    assert.equal(f.requests[0].options.signal.aborted, true);
    assert.deepEqual(f.redirects, []); assert.match(f.elements.status.textContent, /could not be confirmed/); finished(f);
    release(action === "login" ? loginResponse("ready") : changedResponse());
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(f.redirects, [], "late success must not restore authority");
  }
}

for (const kind of ["stall", "broken", "too-big", "empty", "chunks"]) {
  let cancelled = false;
  const body = new ReadableStream({
    start(controller) {
      if (kind === "broken") controller.error(new Error("secret-sentinel"));
      if (kind === "too-big") controller.enqueue(new Uint8Array(8193));
      if (kind === "empty") controller.enqueue(new Uint8Array(0));
      if (kind === "chunks") {
        controller.enqueue(new TextEncoder().encode('{"mode":'));
        controller.enqueue(new TextEncoder().encode('"ready"}')); controller.close();
      }
    },
    cancel() { cancelled = true; },
  });
  const f = page("login", async () => new Response(body, {headers:{"content-type":"application/json"}}));
  const work = f.submit();
  if (kind === "stall") { await new Promise(resolve => setImmediate(resolve)); f.expire(); }
  await work;
  assert.deepEqual(f.redirects, kind === "chunks" ? ["/"] : []); finished(f);
  if (kind === "stall" || kind === "too-big") assert.equal(cancelled, true);
}
{
  let release;
  const f = page("account", () => new Promise(resolve => { release = resolve; }));
  const work = f.submit();
  await f.submit(); await f.handlers["sign-out:click"]();
  assert.equal(f.requests.length, 1, "overlapping actions are refused");
  f.expire(); await work;
  release(changedResponse()); await new Promise(resolve => setImmediate(resolve));
  f.elements.password.value = "fresh password";
  f.elements.next.value = f.elements.confirm.value = "fresh replacement password";
  const retry = f.submit(); assert.equal(f.requests.length, 2, "timeout must not permanently lock controls");
  release(changedResponse()); await retry; assert.deepEqual(f.redirects, ["/login"]); finished(f);
}
{
  const f = page("setup", async () => { throw new Error("hidden page must not request"); });
  f.document.hidden = true; f.handlers.visibilitychange();
  await f.submit(); await f.handlers["sign-out:click"]();
  assert.equal(f.requests.length, 0); assert.equal(f.elements.password.value, "");
}
console.log("Rootwell auth UI: success/refusal, strict bounded body, whole-request deadline, uncertain writes, hidden/late cancellation and credential clearing passed.");
