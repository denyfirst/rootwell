import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = fs.readFileSync(new URL("../cmd/rootwelld/auth/auth.js", import.meta.url), "utf8");

function page(mode, fetchImpl) {
  const handlers = {};
  const redirects = [];
  const elements = {
    "auth-form": {
      addEventListener(name, callback) { handlers[`form:${name}`] = callback; },
      querySelector() { return elements.submit; },
    },
    status: { textContent: "" },
    password: { value: "initial test password" },
    next: { value: "a long replacement password" },
    confirm: { value: "a long replacement password" },
    "sign-out": {
      disabled: false,
      addEventListener(name, callback) { handlers[`sign-out:${name}`] = callback; },
    },
    submit: { disabled: false },
  };
  vm.runInNewContext(source, {
    document: {
      body: { dataset: { mode } },
      getElementById(id) { return mode === "login" && (id === "next" || id === "confirm" || id === "sign-out") ? null : elements[id]; },
    },
    window: { location: { assign(url) { redirects.push(url); } } },
    fetch: fetchImpl,
  }, { filename: "auth.js" });
  return { handlers, redirects, elements };
}

let request;
const login = page("login", async (url, options) => {
  request = { url, options };
  return { ok: true, async json() { return { mode: "setup" }; } };
});
await login.handlers["form:submit"]({ preventDefault() {} });
assert.equal(request.url, "/api/session");
assert.equal(request.options.method, "POST");
assert.equal(request.options.credentials, "same-origin");
assert.equal(request.options.headers["X-Rootwell-Request"], "1");
assert.equal(JSON.parse(request.options.body).password, "initial test password");
assert.deepEqual(login.redirects, ["/setup"]);
assert.equal(login.elements.password.value, "");

const mismatch = page("setup", async () => { throw new Error("fetch must not run"); });
mismatch.elements.confirm.value = "different";
await mismatch.handlers["form:submit"]({ preventDefault() {} });
assert.match(mismatch.elements.status.textContent, /do not match/i);
assert.deepEqual(mismatch.redirects, []);

const setup = page("setup", async (url, options) => {
  request = { url, options };
  return { ok: true };
});
await setup.handlers["form:submit"]({ preventDefault() {} });
assert.equal(request.url, "/api/password");
assert.equal(JSON.parse(request.options.body).next, "a long replacement password");
assert.deepEqual(setup.redirects, ["/login"]);

const failedSignOut = page("account", async () => { throw new Error("network unavailable"); });
await failedSignOut.handlers["sign-out:click"]();
assert.deepEqual(failedSignOut.redirects, []);
assert.match(failedSignOut.elements.status.textContent, /could not be confirmed/i);
assert.equal(failedSignOut.elements["sign-out"].disabled, false);

const signedOut = page("account", async () => ({ ok: true }));
await signedOut.handlers["sign-out:click"]();
assert.deepEqual(signedOut.redirects, ["/login"]);

console.log("Rootwell login, rotation, and sign-out browser behavior passed.");
