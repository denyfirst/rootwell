"use strict";

// Alerts: where Rootwell writes when a certificate comes close to its end.
// Telegram and e-mail, each saved on its own; a saved token or password is
// never shown again, and stays when its field is left empty. Saving and
// turning off need a code from the phone; the page asks once when Rootwell
// says so. Requests go only to this Rootwell's /api/alerts endpoints, and all
// text is written with textContent.
(function () {
  const ui = globalThis.rootwellUI;
  const $ = (id) => document.getElementById(id);
  const pageStatus = $("page-status");
  let current = { email: null, telegram: null, log: [] };

  class Plain extends Error {}
  const messages = {
    401: "Your session has ended. Sign in again.",
    429: "A test was just sent. Try again in a few seconds.",
    503: "Rootwell is busy. Try again in a moment.",
  };

  async function call(path, body, asked) {
    const response = await fetch(path, {
      method: body ? "POST" : "GET", credentials: "same-origin", cache: "no-store", redirect: "error",
      headers: body ? { "Content-Type": "application/json", "X-Rootwell-Request": "1" } : { "X-Rootwell-Request": "1" },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (response.status === 428 && !asked) {
      if (await globalThis.rootwellFresh()) return call(path, body, true);
      throw new Plain("Nothing changed. That needs a code from your phone.");
    }
    if (!response.ok) {
      let said = "";
      if ((response.headers.get("Content-Type") || "").startsWith("application/json")) {
        try { said = JSON.parse(await response.text()).error || ""; } catch { said = ""; }
      }
      throw new Plain(typeof said === "string" && said && said.length < 400 ? said : messages[response.status] || "Rootwell could not do that. Try again.");
    }
    return response;
  }

  function say(target, kind, text) {
    if (!text) return target.replaceChildren();
    if (kind === "good") {
      const box = ui.el("div", "notice good");
      box.appendChild(ui.icon("ok"));
      box.appendChild(ui.el("span", "", text));
      return target.replaceChildren(box);
    }
    target.replaceChildren(ui.el("span", kind === "bad" ? "error-text" : "meta", text));
  }

  const state = (on) => ui.el("span", on ? "pill pill-good" : "pill pill-plain", on ? "On" : "Off");

  // ── Telegram ───────────────────────────────────────────────────────────

  const tg = { form: $("telegram-form"), token: $("telegram-token"), chat: $("telegram-chat"), save: $("telegram-save"),
    test: $("telegram-test"), off: $("telegram-off"), status: $("telegram-status"), state: $("telegram-state") };

  function drawTelegram() {
    const on = !!current.telegram;
    tg.state.replaceChildren(state(on));
    tg.chat.value = on ? current.telegram.chat_id : tg.chat.value;
    tg.token.value = "";
    tg.token.placeholder = on ? "Saved. Leave empty to keep it." : "";
    tg.test.hidden = !on;
    tg.off.hidden = !on;
  }

  async function saveTelegram(event) {
    event.preventDefault();
    const token = tg.token.value.trim();
    const chat = tg.chat.value.trim();
    if (!chat || (!token && !current.telegram)) return say(tg.status, "bad", "Enter the bot token and the chat ID.");
    tg.save.disabled = true;
    say(tg.status, "plain", "Saving…");
    try {
      await call("/api/alerts/telegram", { token, keep_token: !token, chat_id: chat });
      tg.token.value = "";
      await load();
      say(tg.status, "good", "Saved. Send a test to see it arrive.");
    } catch (failure) {
      say(tg.status, "bad", failure instanceof Plain ? failure.message : "Nothing was saved. Try again.");
    } finally {
      tg.save.disabled = false;
    }
  }

  // ── E-mail ─────────────────────────────────────────────────────────────

  const em = { form: $("email-form"), host: $("email-host"), port: $("email-port"), security: $("email-security"), user: $("email-user"),
    password: $("email-password"), from: $("email-from"), to: $("email-to"), save: $("email-save"), test: $("email-test"),
    off: $("email-off"), status: $("email-status"), state: $("email-state") };

  function security() {
    const radio = em.security.querySelector("input:checked");
    return radio ? radio.value : "starttls";
  }

  function drawEmail() {
    const e = current.email;
    em.state.replaceChildren(state(!!e));
    if (e) {
      em.host.value = e.host;
      em.port.value = String(e.port);
      for (const radio of em.security.querySelectorAll("input")) radio.checked = radio.value === e.security;
      em.user.value = e.username || "";
      em.from.value = e.from;
      em.to.value = e.to.join(", ");
    } else if (!em.port.value) {
      em.port.value = "587";
    }
    em.password.value = "";
    em.password.placeholder = e && e.has_password ? "Saved. Leave empty to keep it." : "";
    em.test.hidden = !e;
    em.off.hidden = !e;
  }

  async function saveEmail(event) {
    event.preventDefault();
    const to = em.to.value.split(/[\s,;]+/).filter(Boolean);
    const port = Number(em.port.value);
    const password = em.password.value;
    const keep = !password && !!(current.email && current.email.has_password) && !!em.user.value.trim();
    if (!em.host.value.trim() || !Number.isInteger(port) || port < 1 || port > 65535 || !em.from.value.trim() || !to.length) {
      return say(em.status, "bad", "Enter the mail server, its port, the sender and at least one recipient.");
    }
    if (to.length > 10) return say(em.status, "bad", "Use up to 10 recipients.");
    em.save.disabled = true;
    say(em.status, "plain", "Saving…");
    try {
      await call("/api/alerts/email", { host: em.host.value.trim().toLowerCase(), port, security: security(), username: em.user.value.trim(),
        password, keep_password: keep, from: em.from.value.trim(), to });
      em.password.value = "";
      await load();
      say(em.status, "good", "Saved. Send a test to see it arrive.");
    } catch (failure) {
      say(em.status, "bad", failure instanceof Plain ? failure.message : "Nothing was saved. Try again.");
    } finally {
      em.save.disabled = false;
    }
  }

  // Picking an encryption fills in its usual port, unless one was typed.
  for (const radio of em.security.querySelectorAll("input")) {
    radio.addEventListener("change", () => {
      if (em.port.value === "587" || em.port.value === "465" || !em.port.value) em.port.value = security() === "tls" ? "465" : "587";
    });
  }

  // ── Both ───────────────────────────────────────────────────────────────

  async function test(channel, parts) {
    parts.test.disabled = true;
    say(parts.status, "plain", "Sending a test…");
    try {
      await call("/api/alerts/test", { channel });
      say(parts.status, "good", channel === "telegram" ? "Sent. It should be in the chat now." : "Sent. It should arrive in a minute.");
    } catch (failure) {
      say(parts.status, "bad", failure instanceof Plain ? failure.message : "The test was not sent.");
    } finally {
      parts.test.disabled = false;
      void load();
    }
  }

  async function turnOff(channel, parts) {
    parts.off.disabled = true;
    try {
      await call("/api/alerts/remove", { channel });
      await load();
      say(parts.status, "good", channel === "telegram" ? "Telegram alerts are off, and the token is forgotten." : "E-mail alerts are off, and the password is forgotten.");
    } catch (failure) {
      say(parts.status, "bad", failure instanceof Plain ? failure.message : "Nothing changed.");
    } finally {
      parts.off.disabled = false;
    }
  }

  function drawLog() {
    const log = $("log");
    if (!current.log.length) return log.replaceChildren(ui.el("p", "meta", "Nothing sent yet."));
    log.replaceChildren(...current.log.map((entry) => {
      const row = ui.el("div", "file-chip");
      const words = ui.el("div");
      words.appendChild(ui.el("strong", "", entry.subject));
      words.appendChild(ui.el("small", "", ui.formatDate(entry.at) + " " + new Date(entry.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })));
      for (const [channel, result] of Object.entries(entry.results || {})) {
        if (result) words.appendChild(ui.el("small", "error-text", (channel === "email" ? "E-mail: " : "Telegram: ") + result));
      }
      row.appendChild(words);
      for (const [channel, result] of Object.entries(entry.results || {})) {
        row.appendChild(ui.el("span", result ? "pill pill-bad" : "pill pill-good", channel === "email" ? "E-mail" : "Telegram"));
      }
      return row;
    }));
  }

  async function load() {
    try {
      const response = await call("/api/alerts");
      const text = await response.text();
      if (text.length > 1024 * 1024) throw new Error("large");
      const answer = JSON.parse(text);
      current = { email: answer.email || null, telegram: answer.telegram || null, log: Array.isArray(answer.log) ? answer.log : [] };
      drawTelegram();
      drawEmail();
      drawLog();
      say(pageStatus);
    } catch (failure) {
      say(pageStatus, "bad", failure instanceof Plain ? failure.message : "The alert settings could not be read. Reload the page.");
    }
  }

  tg.form.addEventListener("submit", saveTelegram);
  em.form.addEventListener("submit", saveEmail);
  tg.test.addEventListener("click", () => test("telegram", tg));
  em.test.addEventListener("click", () => test("email", em));
  tg.off.addEventListener("click", () => turnOff("telegram", tg));
  em.off.addEventListener("click", () => turnOff("email", em));
  // Leaving the page forgets what was typed into the secret fields.
  globalThis.addEventListener("pagehide", () => { tg.token.value = ""; em.password.value = ""; });
  void load();
})();
