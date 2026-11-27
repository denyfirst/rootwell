import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

// Alerts, driven against a stand-in for /api/alerts: Telegram and e-mail are
// saved, a saved token or password is never shown and stays when its field is
// left empty, saving and turning off ask for a phone code when Rootwell says
// so, tests say how they went, and the log shows what was sent.
const read = (name) => fs.readFileSync(new URL("../web/workbench/" + name, import.meta.url), "utf8");
const uiSource = read("ui.js");
const source = read("alerts.js");
const html = read("alerts.html");
for (const forbidden of ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "localStorage", "sessionStorage",
  "indexedDB", ".files", "arrayBuffer", "FileReader", "Worker(", "https://", "http://"]) {
  assert.ok(!source.includes(forbidden), `alerts.js must not use ${forbidden}`);
}
assert.deepEqual([...new Set([...source.matchAll(/call\("([^"]+)"/g)].map((m) => m[1]))].sort(),
  ["/api/alerts", "/api/alerts/email", "/api/alerts/remove", "/api/alerts/telegram", "/api/alerts/test"]);
assert.match(html, /<a class="nav-item" href="\/alerts" aria-current="page">/);
for (const script of ["/session.js", "/fresh.js", "/ui.js", "/alerts.js"]) assert.ok(html.includes(`<script src="${script}" defer></script>`), `alerts.html loads ${script}`);
assert.doesNotMatch(html, /style="|demo|<input class="input[^>]*value=/i, "no inline style, no demo material, no field filled in");

// ── A stand-in for /api/alerts ───────────────────────────────────────────
const token = "123456789:AAH-synthetic_token_for_tests_only_000";
const api = { email: null, telegram: null, log: [], fresh: true, freshAnswer: true, freshAsked: 0, calls: [], token: "", password: "", testFails: "" };
const reply = (status, body) => new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "Content-Type": typeof body === "string" ? "text/plain" : "application/json" } });
async function fetch(url, options) {
  const body = options.body ? JSON.parse(options.body) : null;
  api.calls.push({ url, body });
  assert.equal(options.headers["X-Rootwell-Request"], "1");
  assert.equal(options.credentials, "same-origin");
  if (url === "/api/alerts") return reply(200, { email: api.email, telegram: api.telegram, log: api.log });
  if (url === "/api/alerts/test") {
    if (api.testFails) return reply(502, { error: api.testFails });
    api.log.unshift({ at: "2026-11-27T10:00:00Z", subject: "Rootwell: a test alert", test: true, results: { [body.channel]: "" } });
    return reply(200, { sent: true });
  }
  if (!api.fresh) return reply(428, "Enter a code from your phone first.");
  switch (url) {
    case "/api/alerts/telegram":
      if (body.keep_token ? !api.token || body.token : !body.token) return reply(400, { error: "Telegram does not accept this bot token. Copy it again from @BotFather." });
      if (!body.keep_token) api.token = body.token;
      api.telegram = { chat_id: body.chat_id };
      return new Response(null, { status: 204 });
    case "/api/alerts/email":
      if (!body.keep_password) api.password = body.password;
      api.email = { host: body.host, port: body.port, security: body.security, username: body.username, from: body.from, to: body.to, has_password: !!api.password };
      return new Response(null, { status: 204 });
    case "/api/alerts/remove":
      if (body.channel === "telegram") { api.telegram = null; api.token = ""; } else { api.email = null; api.password = ""; }
      return new Response(null, { status: 204 });
  }
  throw new Error("unexpected " + url);
}

// ── A small DOM ──────────────────────────────────────────────────────────
class Node {
  constructor(tag) {
    Object.assign(this, { tag, children: [], textContent: "", className: "", attributes: {}, hidden: false, disabled: false, value: "",
      type: "", checked: false, placeholder: "", listeners: {} });
  }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  all() { return [this, ...this.children.flatMap((c) => c.all())]; }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  querySelectorAll(selector) {
    const inputs = this.all().filter((n) => n !== this && n.tag === "input");
    return selector === "input:checked" ? inputs.filter((n) => n.checked) : inputs;
  }
  text() { return [this.textContent, ...this.children.map((c) => c.text())].join(" ").replace(/\s+/g, " ").trim(); }
}
const ids = {};
const $ = (id) => (ids[id] ??= new Node(/token|chat|host|port|user|password|from|to$/.test(id) && !/-(state|status|save|test|off)$/.test(id) ? "input" : "div"));
for (const value of ["starttls", "tls"]) {
  const radio = new Node("input");
  Object.assign(radio, { type: "radio", value, checked: value === "starttls" });
  $("email-security").appendChild(new Node("label")).appendChild(radio);
}
const document = { getElementById: $, createElement: (tag) => new Node(tag), createElementNS: (_, tag) => new Node(tag), body: new Node("body") };
const win = {
  rootwellFresh: async () => { api.freshAsked++; api.fresh = api.freshAnswer; return api.freshAnswer; },
  listeners: {}, addEventListener(name, fn) { this.listeners[name] = fn; },
};
const load = (src, filename) => vm.runInThisContext("(function (globalThis, document, fetch, setTimeout) {" + src + "\n})", { filename })(win, document, fetch, () => 0);
const settle = async () => { for (let i = 0; i < 40; i++) await new Promise((r) => setImmediate(r)); };
const submit = async (form) => { await $(form).listeners.submit({ preventDefault() {} }); await settle(); };
const last = (url) => api.calls.filter((c) => c.url === url).at(-1);
load(uiSource, "ui.js");
load(source, "alerts.js");
await settle();

// Nothing set up yet.
assert.equal($("telegram-state").text(), "Off");
assert.equal($("email-state").text(), "Off");
assert.equal($("telegram-test").hidden, true);
assert.equal($("email-port").value, "587", "STARTTLS's usual port is filled in");
assert.equal($("log").text(), "Nothing sent yet.");

// Telegram: a token and a chat; saving asks for a phone code first.
await submit("telegram-form");
assert.match($("telegram-status").text(), /Enter the bot token and the chat ID/);
$("telegram-token").value = token;
$("telegram-chat").value = " -1001234567890 ";
api.fresh = false;
await submit("telegram-form");
assert.equal(api.freshAsked, 1, "the page asks for a phone code");
assert.deepEqual(last("/api/alerts/telegram").body, { token, keep_token: false, chat_id: "-1001234567890" });
assert.match($("telegram-status").text(), /Saved\. Send a test/);
assert.equal($("telegram-state").text(), "On");
assert.equal($("telegram-token").value, "", "the token leaves the field once saved");
assert.equal($("telegram-token").placeholder, "Saved. Leave empty to keep it.");
assert.equal($("telegram-test").hidden, false);
// A new chat keeps the saved token: the page never has it to send back.
$("telegram-chat").value = "42";
await submit("telegram-form");
assert.deepEqual(last("/api/alerts/telegram").body, { token: "", keep_token: true, chat_id: "42" });
assert.equal(api.token, token);
// A test says it arrived, or why not, in Rootwell's words.
await $("telegram-test").listeners.click();
await settle();
assert.match($("telegram-status").text(), /Sent\. It should be in the chat now\./);
assert.match($("log").text(), /^Rootwell: a test alert .+ Telegram$/);
api.testFails = "The bot cannot write to this chat. Send the bot a message first, or add it to the group, then check the chat ID.";
await $("telegram-test").listeners.click();
await settle();
assert.equal($("telegram-status").text(), api.testFails);
api.testFails = "";

// E-mail: TLS picks its port; the password is never shown, and stays when
// the field is left empty.
for (const radio of $("email-security").querySelectorAll("input")) radio.checked = radio.value === "tls";
$("email-security").querySelectorAll("input")[1].listeners.change();
assert.equal($("email-port").value, "465");
$("email-host").value = "Mail.Example.Test";
$("email-user").value = "alerts";
$("email-password").value = "a mail password";
$("email-from").value = "rootwell@example.test";
$("email-to").value = "ops@example.test, web@example.test";
await submit("email-form");
assert.deepEqual(last("/api/alerts/email").body, { host: "mail.example.test", port: 465, security: "tls", username: "alerts", password: "a mail password",
  keep_password: false, from: "rootwell@example.test", to: ["ops@example.test", "web@example.test"] });
assert.equal($("email-state").text(), "On");
assert.equal($("email-password").value, "");
assert.equal($("email-password").placeholder, "Saved. Leave empty to keep it.");
assert.equal($("email-to").value, "ops@example.test, web@example.test");
$("email-to").value = "night@example.test";
await submit("email-form");
assert.equal(last("/api/alerts/email").body.keep_password, true);
assert.equal(last("/api/alerts/email").body.password, "");
assert.equal(api.password, "a mail password");
$("email-to").value = Array.from({ length: 11 }, (_, i) => "a" + i + "@example.test").join(",");
const saves = api.calls.filter((c) => c.url === "/api/alerts/email").length;
await submit("email-form");
assert.match($("email-status").text(), /up to 10 recipients/);
assert.equal(api.calls.filter((c) => c.url === "/api/alerts/email").length, saves);

// Turning off forgets the secret, and needs the phone code too.
api.fresh = false;
api.freshAnswer = false;
await $("telegram-off").listeners.click();
await settle();
assert.match($("telegram-status").text(), /Nothing changed\. That needs a code from your phone\./);
assert.equal($("telegram-state").text(), "On");
api.freshAnswer = true;
await $("telegram-off").listeners.click();
await settle();
assert.match($("telegram-status").text(), /Telegram alerts are off, and the token is forgotten\./);
assert.equal($("telegram-state").text(), "Off");
assert.equal(api.token, "");

// The log: what failed says why.
api.log.unshift({ at: "2026-11-27T11:00:00Z", subject: "Rootwell: shop.test ends in 14 days", results: { email: "The mail server did not accept the user name and password.", telegram: "" } });
await $("email-test").listeners.click();
await settle();
assert.match($("log").text(), /Rootwell: shop\.test ends in 14 days .+ E-mail: The mail server did not accept the user name and password\. E-mail Telegram/);

// Leaving the page forgets what was typed into the secret fields.
$("email-password").value = "typed";
$("telegram-token").value = "typed";
win.listeners.pagehide();
assert.equal($("email-password").value, "");
assert.equal($("telegram-token").value, "");

console.log("Alerts saves Telegram and e-mail, keeps secrets unseen, asks for a phone code to change them, and shows what was sent.");
