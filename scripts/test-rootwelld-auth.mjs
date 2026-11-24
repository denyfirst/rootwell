// Drives the sign-in, setup and Account pages' real scripts (auth.js, qr.js,
// fresh.js) against a stand-in DOM and server, and checks what they send and
// show.
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const read = (path) => fs.readFileSync(new URL(path, import.meta.url), "utf8");
const scripts = {
  auth: read("../cmd/rootwelld/auth/auth.js"),
  qr: read("../cmd/rootwelld/auth/qr.js"),
  fresh: read("../web/workbench/fresh.js"),
  passkey: read("../cmd/rootwelld/auth/passkey.js"),
};
for (const [name, source] of Object.entries(scripts)) {
  assert.doesNotMatch(source, /innerHTML|outerHTML|insertAdjacentHTML|localStorage|sessionStorage|console\.|sendBeacon|eval\(|new Function/, name);
}

const secrets = /an account password for testing|aaaaaa-bbbbbb|123456|abcd-efgh/;
const json = (status, value) => new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
const empty = (status) => new Response(null, { status });
const text = (status, body) => new Response(body, { status, headers: { "content-type": "text/plain; charset=utf-8" } });
const rows = Array.from({ length: 21 }, (_, y) => Array.from({ length: 21 }, (_, x) => ((x * y + x) % 3 === 0 ? "1" : "0")).join(""));
const key = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
const codes = Array.from({ length: 10 }, (_, i) => "abcd-efgh-ijkl-mn" + "234567ab".slice(i % 8, i % 8 + 1) + "q");

class Node {
  constructor(tag, id) {
    Object.assign(this, { tag, id, value: "", hidden: false, disabled: false, textContent: "", children: [], attributes: {}, dataset: {}, listeners: {}, className: "" });
  }
  addEventListener(name, fn) { (this.listeners[name] ??= []).push(fn); }
  async fire(name, event = {}) {
    for (const fn of this.listeners[name] || []) await fn({ preventDefault() {}, key: event.key, ...event });
  }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  replaceChildren(...nodes) { this.children = nodes; }
  append(...nodes) { this.children.push(...nodes); }
  appendChild(node) { this.children.push(node); return node; }
  remove() {}
  focus() { this.focused = true; }
  click() { this.clicked = true; }
  querySelectorAll() { return this.buttons || []; }
}

function load(mode, server, { fresh = async () => true, credentials = null } = {}) {
  const nodes = {};
  const $ = (id) => (nodes[id] ??= new Node("div", id));
  const requests = [];
  const redirects = [];
  const pageHandlers = {};
  const forms = ["password-form", "code-form", "setup-form", "phone-form"];
  for (const id of forms) $(id).buttons = [new Node("button")];
  $("code-form").hidden = true;
  for (const id of ["phone-step", "codes-step"]) $(id).hidden = true;
  const body = new Node("body");
  body.dataset.mode = mode;
  const document = {
    body,
    getElementById: $,
    createElement: (tag) => new Node(tag),
    createElementNS: (_, tag) => new Node(tag),
    addEventListener() {},
  };
  const context = {
    document, URL: { createObjectURL: () => "blob:x", revokeObjectURL() {} }, Blob,
    navigator: { clipboard: { writeText: async (value) => { context.copied = value; } }, ...(credentials ? { credentials } : {}) },
    ...(credentials ? { PublicKeyCredential: function PublicKeyCredential() {} } : {}),
    atob, btoa, Uint8Array,
    window: { location: { assign: (url) => redirects.push(url) }, addEventListener: (name, fn) => { pageHandlers[name] = fn; } },
    AbortController, setTimeout: (fn, delay) => { assert.ok(delay <= 30000); return 0; }, clearTimeout() {},
    fetch: async (url, options) => {
      const sent = options.body ? JSON.parse(options.body) : undefined;
      requests.push({ url, method: options.method, body: sent, headers: { ...options.headers } });
      assert.equal(options.credentials, "same-origin");
      assert.equal(options.redirect, "error");
      assert.equal(options.headers["X-Rootwell-Request"], "1");
      return server(url, options.method, sent);
    },
  };
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(scripts.qr, context, { filename: "qr.js" });
  vm.runInContext(scripts.passkey, context, { filename: "passkey.js" });
  context.rootwellFresh = fresh;
  vm.runInContext(scripts.auth, context, { filename: "auth.js" });
  return { $, requests, redirects, context, pageHandlers, submit: (id) => $(id).fire("submit"), settle: () => new Promise((r) => setTimeout(r, 0)) };
}

function noSecrets(page) {
  assert.doesNotMatch(page.$("status").textContent, secrets);
}

// ── Sign in: the password, then the phone code ─────────────────────────────
{
  let codeAnswer = empty(401);
  const page = load("login", (url, method) => {
    if (url === "/api/session" && method === "GET") return json(200, { stage: "none" });
    if (url === "/api/session" && method === "POST") return empty(204);
    if (url === "/api/session/code") return codeAnswer;
    if (url === "/api/session" && method === "DELETE") return empty(204);
    throw new Error("unexpected " + url);
  });
  await page.settle();
  page.$("name").value = "not a name";
  page.$("password").value = "an account password for testing";
  await page.submit("password-form");
  assert.equal(page.requests.length, 1, "a malformed name is refused before anything is sent");
  assert.equal(page.$("password").value, "", "the password field is emptied");
  page.$("name").value = " ada ";
  page.$("password").value = "an account password for testing";
  await page.submit("password-form");
  assert.deepEqual(page.requests.at(-1), { url: "/api/session", method: "POST", body: { name: "ada", password: "an account password for testing" },
    headers: { "Content-Type": "application/json", "X-Rootwell-Request": "1" } });
  assert.equal(page.$("password-form").hidden, true);
  assert.equal(page.$("code-form").hidden, false);
  assert.equal(page.$("code").focused, true);
  page.$("code").value = "123456";
  await page.submit("code-form");
  assert.deepEqual(page.requests.at(-1).body, { code: "123456" });
  assert.equal(page.$("status").textContent, "That code does not match.");
  assert.equal(page.$("code").value, "");
  noSecrets(page);
  codeAnswer = text(429, "Too many wrong tries.");
  page.$("code").value = "123456";
  await page.submit("code-form");
  assert.match(page.$("status").textContent, /Too many wrong tries/);
  codeAnswer = text(401, "Too many wrong codes. Sign in again.");
  page.$("code").value = "123456";
  await page.submit("code-form");
  assert.equal(page.$("code-form").hidden, true, "five wrong codes go back to the password");
  assert.equal(page.$("password-form").hidden, false);
  assert.match(page.$("status").textContent, /Sign in again/);
  await page.submit("password-form");
  codeAnswer = empty(204);
  page.$("code").value = "abcd-efgh-ijkl-mnop";
  await page.submit("code-form");
  assert.deepEqual(page.redirects, ["/certificates"]);
}
{
  // Reloading after the password goes straight to the code.
  const page = load("login", () => json(200, { stage: "code" }));
  await page.settle();
  await page.settle();
  assert.equal(page.$("code-form").hidden, false);
}

// ── Setup: the code, then the phone, then the recovery codes ───────────────
{
  let setupAnswer = text(401, "no");
  let confirmAnswer = text(401, "That code does not match.");
  const page = load("setup", (url) => {
    if (url === "/api/setup") return setupAnswer;
    if (url === "/api/setup/confirm") return confirmAnswer;
    throw new Error("unexpected " + url);
  });
  const fill = () => {
    page.$("setup-code").value = "aaaaaa-bbbbbb-cccccc-dddddd";
    page.$("name").value = "ada";
    page.$("password").value = "an account password for testing";
    page.$("confirm").value = "an account password for testing";
  };
  fill();
  page.$("confirm").value = "something else entirely here";
  await page.submit("setup-form");
  assert.equal(page.requests.length, 0, "differing passwords are caught on the page");
  assert.match(page.$("status").textContent, /differ/);
  fill();
  await page.submit("setup-form");
  assert.deepEqual(page.requests.at(-1).body, { code: "aaaaaa-bbbbbb-cccccc-dddddd", name: "ada", password: "an account password for testing" });
  assert.match(page.$("status").textContent, /setup code does not work/);
  assert.equal(page.$("phone-step").hidden, true);
  noSecrets(page);
  setupAnswer = json(200, { name: "ada", key, qr: rows });
  fill();
  await page.submit("setup-form");
  assert.equal(page.$("setup-step").hidden, true);
  assert.equal(page.$("phone-step").hidden, false);
  for (const id of ["password", "confirm", "setup-code"]) assert.equal(page.$(id).value, "", id + " is emptied");
  assert.equal(page.$("phone-key").textContent, "JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP");
  const qr = page.$("phone-qr");
  assert.equal(qr.attributes.viewBox, "-4 -4 29 29");
  assert.match(qr.children[0].attributes.d, /^(M\d+ \d+h\d+v1h-\d+z)+$/);
  page.$("phone-code").value = "12345";
  await page.submit("phone-form");
  assert.equal(page.requests.length, 2, "a code that is not six digits is not sent");
  page.$("phone-code").value = "123456";
  await page.submit("phone-form");
  assert.match(page.$("status").textContent, /does not match/);
  confirmAnswer = json(200, { recovery_codes: codes });
  page.$("phone-code").value = "123456";
  await page.submit("phone-form");
  assert.equal(page.$("phone-step").hidden, true);
  assert.equal(page.$("codes-step").hidden, false);
  assert.deepEqual(page.$("codes").children.map((li) => li.textContent), codes);
  await page.$("codes-copy").onclick();
  assert.match(page.context.copied, /^Rootwell recovery codes for ada\n/);
}
{
  // A QR that is not modules is refused, and nothing is drawn.
  const page = load("setup", () => json(200, { name: "ada", key, qr: ["0101", "x"] }));
  page.$("setup-code").value = "aaaaaa-bbbbbb-cccccc-dddddd";
  page.$("name").value = "ada";
  page.$("password").value = page.$("confirm").value = "an account password for testing";
  await page.submit("setup-form");
  assert.equal(page.$("phone-step").hidden, true);
  assert.match(page.$("status").textContent, /did not go through/);
}

// ── Account: a change that needs a fresh code asks once, then repeats ──────
{
  let asked = 0;
  const sent = [];
  const page = load("account", (url, method, body) => {
    if (url === "/api/session") return json(200, { stage: "ready", name: "ada", recovery_left: 4, fresh: false });
    sent.push(url);
    if (sent.filter((u) => u === url).length === 1) return text(428, "Enter a code from your phone first.");
    if (url === "/api/password") return empty(204);
    if (url === "/api/recovery-codes") return json(200, { recovery_codes: codes });
    if (url === "/api/phone") return json(200, { name: "ada", key, qr: rows });
    if (url === "/api/phone/confirm") return empty(204);
    throw new Error("unexpected " + url);
  }, { fresh: async () => { asked++; return true; } });
  await page.settle();
  await page.settle();
  assert.equal(page.$("account-name").textContent, "ada");
  assert.equal(page.$("codes-left").textContent, "4 are left.");
  await page.$("codes-new").fire("click");
  assert.equal(asked, 1);
  assert.deepEqual(page.$("codes").children.map((li) => li.textContent), codes);
  assert.equal(page.$("codes-left").textContent, "10 are left.");
  await page.$("phone-start").fire("click");
  assert.equal(page.$("phone-step").hidden, false);
  page.$("phone-code").value = "123456";
  await page.submit("phone-form");
  assert.match(page.$("status").textContent, /new phone/);
  page.$("password").value = "an account password for testing";
  page.$("next").value = page.$("confirm").value = "a different long test password";
  await page.submit("password-form");
  assert.deepEqual(page.redirects, ["/login"]);
  assert.equal(asked, 4);
  page.pageHandlers.pagehide();
  for (const id of ["password", "next", "confirm", "phone-code"]) assert.equal(page.$(id).value, "", id + " is emptied on leaving");
}
{
  // A cancelled code changes nothing and says so.
  const page = load("account", (url) => url === "/api/session" ? json(200, { stage: "ready", name: "ada", recovery_left: 10 }) : text(428, "code"),
    { fresh: async () => false });
  await page.settle();
  await page.$("codes-new").fire("click");
  assert.match(page.$("status").textContent, /Nothing changed/);
  assert.equal(page.$("codes-step").hidden, true);
}

// ── The fresh-code dialog itself ───────────────────────────────────────────
{
  const created = [];
  let answer = text(401, "That code does not match.");
  const document = {
    body: { append: (...nodes) => created.push(...nodes) },
    createElement: (tag) => new Node(tag),
  };
  const context = {
    document, window: { location: { assign() {} }, addEventListener() {} },
    fetch: async (url, options) => {
      assert.equal(url, "/api/fresh");
      assert.equal(options.headers["X-Rootwell-Request"], "1");
      context.last = JSON.parse(options.body);
      return answer;
    },
  };
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(scripts.fresh, context, { filename: "fresh.js" });
  const waiting = context.rootwellFresh();
  const [scrim, dialog] = created;
  assert.equal(dialog.hidden, false);
  assert.equal(scrim.hidden, false);
  const form = dialog.children[0];
  const input = form.children[1].children[1].children[1];
  input.value = " 123456 ";
  await form.fire("submit");
  assert.deepEqual(context.last, { code: "123456" });
  assert.equal(input.value, "", "a wrong code is emptied");
  assert.equal(dialog.hidden, false);
  answer = empty(204);
  input.value = "654321";
  await form.fire("submit");
  assert.equal(await waiting, true);
  assert.equal(dialog.hidden, true);
  const cancelled = context.rootwellFresh();
  await dialog.fire("keydown", { key: "Escape" });
  assert.equal(await cancelled, false);
}

// ── Passkeys: in place of the code at sign-in, and added on Account ────────
const buffer = (...b) => new Uint8Array(b).buffer;
{
  const asked = [];
  const credentials = {
    get: async ({ publicKey }) => {
      asked.push(publicKey);
      return { rawId: buffer(1, 2, 3), response: { clientDataJSON: buffer(4), authenticatorData: buffer(5, 6), signature: buffer(255, 254) } };
    },
  };
  let passkeyAnswer = text(401, "That passkey was not accepted.");
  const page = load("login", (url, method) => {
    if (url === "/api/session" && method === "GET") return json(200, { stage: "code", passkeys: true });
    if (url === "/api/passkey/options") return json(200, { challenge: "AQID", rp_id: "localhost", allow: ["AQID"], timeout: 120000 });
    if (url === "/api/passkey") return passkeyAnswer;
    throw new Error("unexpected " + url);
  }, { credentials });
  for (let i = 0; i < 4; i++) await page.settle();
  assert.equal(page.$("passkey-sign-in").hidden, false, "the passkey is offered at the code step");
  await page.$("passkey-sign-in").fire("click");
  assert.deepEqual(page.requests.find((r) => r.url === "/api/passkey").body,
    { id: "AQID", client_data: "BA", authenticator_data: "BQY", signature: "__4" });
  const request = asked[0];
  assert.equal(request.rpId, "localhost");
  assert.equal(request.userVerification, "required");
  assert.deepEqual([...new Uint8Array(request.challenge)], [1, 2, 3]);
  assert.deepEqual([...new Uint8Array(request.allowCredentials[0].id)], [1, 2, 3]);
  assert.equal(page.$("status").textContent, "That passkey was not accepted.");
  passkeyAnswer = empty(204);
  await page.$("passkey-sign-in").fire("click");
  assert.deepEqual(page.redirects, ["/certificates"]);
}
{
  // An account without a passkey is offered none.
  const page = load("login", (url) => url === "/api/session" ? json(200, { stage: "code", passkeys: false }) : empty(500),
    { credentials: { get: async () => null } });
  for (let i = 0; i < 4; i++) await page.settle();
  assert.equal(page.$("passkey-sign-in").hidden, true);
}
{
  const made = [];
  const credentials = {
    create: async ({ publicKey }) => {
      made.push(publicKey);
      return { response: { clientDataJSON: buffer(7), attestationObject: buffer(8, 9) } };
    },
  };
  let asked = 0;
  const page = load("account", (url, method, body) => {
    if (url === "/api/session") return json(200, { stage: "ready", name: "ada", recovery_left: 10 });
    if (url === "/api/passkeys" && method === "GET") return json(200, { passkeys: [] });
    if (url === "/api/passkeys/options") {
      return asked++ === 0 ? text(428, "Enter a code from your phone first.") :
        json(200, { challenge: "AQID", rp_id: "localhost", user_id: "BAU", user_name: "ada", exclude: ["Bgc"], timeout: 120000 });
    }
    if (url === "/api/passkeys" && method === "POST") return json(201, { passkeys: [{ id: "AQID", name: body.name, added: "2026-11-24T12:00:00Z", last_used: "" }] });
    if (url === "/api/passkeys/remove") return json(200, { passkeys: [] });
    throw new Error("unexpected " + url);
  }, { credentials });
  for (let i = 0; i < 3; i++) await page.settle();
  assert.equal(page.$("passkeys").children[0].textContent, "No passkey yet.");
  assert.equal(page.$("passkey-add").hidden, false);
  page.$("passkey-name").value = " Work laptop ";
  await page.$("passkey-add").fire("click");
  assert.equal(asked, 2, "the page asked for a fresh code, then asked again");
  const options = made[0];
  assert.equal(options.rp.id, "localhost");
  assert.equal(options.attestation, "none");
  assert.equal(options.authenticatorSelection.userVerification, "required");
  assert.deepEqual([...options.pubKeyCredParams].map((p) => p.alg), [-7, -8, -257]);
  assert.deepEqual([...new Uint8Array(options.user.id)], [4, 5]);
  assert.deepEqual([...new Uint8Array(options.excludeCredentials[0].id)], [6, 7]);
  assert.deepEqual(page.requests.find((r) => r.url === "/api/passkeys" && r.method === "POST").body,
    { client_data: "Bw", attestation: "CAk", name: "Work laptop" });
  assert.match(page.$("passkeys").children[0].children[0].textContent, /^Work laptop · added 2026-11-24/);
  await page.$("passkeys").children[0].children[1].fire("click");
  assert.deepEqual(page.requests.at(-1).body, { id: "AQID" });
  assert.equal(page.$("passkeys").children[0].textContent, "No passkey yet.");
}

{
  // The fresh-code dialog: a passkey in place of the typed code, offered only
  // when the account has one.
  for (const has of [false, true]) {
    const created = [];
    const sent = [];
    const context = {
      document: { body: { append: (...nodes) => created.push(...nodes) }, createElement: (tag) => new Node(tag) },
      window: { location: { assign() {} }, addEventListener() {} },
      rootwellPasskey: { supported: () => true, sign: async (options) => ({ id: "AQID", client_data: "BA", authenticator_data: "BQY", signature: options.challenge }) },
      fetch: async (url, options) => {
        sent.push({ url, body: options.body ? JSON.parse(options.body) : undefined });
        if (url === "/api/session") return json(200, { stage: "ready", passkeys: has });
        if (url === "/api/passkey/options") return json(200, { challenge: "Cg", rp_id: "localhost", allow: ["AQID"], timeout: 1 });
        if (url === "/api/passkey") return empty(204);
        throw new Error("unexpected " + url);
      },
    };
    context.globalThis = context;
    vm.createContext(context);
    vm.runInContext(scripts.fresh, context, { filename: "fresh.js" });
    const waiting = context.rootwellFresh();
    for (let i = 0; i < 4; i++) await new Promise((r) => setTimeout(r, 0));
    const dialog = created[1];
    const passkeyButton = dialog.children[0].children[2].children[1];
    assert.equal(passkeyButton.hidden, !has, has ? "offered with a passkey" : "hidden without one");
    if (!has) continue;
    await passkeyButton.fire("click");
    assert.equal(await waiting, true);
    assert.deepEqual(sent.at(-1), { url: "/api/passkey", body: { id: "AQID", client_data: "BA", authenticator_data: "BQY", signature: "Cg" } });
  }
}

{
  // Installation: the facts, and a backup after a fresh code, as a download.
  let backups = 0;
  let asked = 0;
  const page = load("installation", (url) => {
    if (url === "/api/installation") return json(200, { names: ["localhost", "127.0.0.1", "::1"], fingerprint: "AB:CD", serving_until: "2027-02-22T11:36:48Z", certificates: 4 });
    if (url === "/api/backup") {
      return backups++ === 0 ? text(428, "Enter a code from your phone first.") :
        new Response(new Uint8Array([1, 2, 3]), { status: 200, headers: { "content-type": "application/octet-stream", "content-disposition": 'attachment; filename="rootwell-backup-20261124T120000Z.db"' } });
    }
    throw new Error("unexpected " + url);
  }, { fresh: async () => { asked++; return true; } });
  for (let i = 0; i < 3; i++) await page.settle();
  assert.equal(page.$("names").textContent, "localhost, 127.0.0.1, ::1");
  assert.equal(page.$("fingerprint").textContent, "AB:CD");
  assert.match(page.$("serving").textContent, /until 2027-02-22\./);
  assert.equal(page.$("contents").textContent, "4 certificates are saved.");
  await page.$("backup-download").fire("click");
  assert.equal(asked, 1, "the backup asked for a fresh code once");
  assert.equal(backups, 2);
  assert.match(page.$("status").textContent, /^Downloaded rootwell-backup-20261124T120000Z\.db\./);
  const link = page.context.document.body.children.at(-1);
  assert.equal(link.download, "rootwell-backup-20261124T120000Z.db");
  assert.equal(link.clicked, true);
}

console.log("sign-in, setup, account and fresh-code pages behave as expected");
