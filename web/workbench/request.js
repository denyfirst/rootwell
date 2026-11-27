"use strict";

// Request: make the request file (CSR) a certificate provider asks for.
// With a new key, Rootwell makes the key and keeps it: request-keep.js sends
// the typed names, and the key never reaches this page. When the provider's
// certificate is added in Certificates, Rootwell puts it with that key. With a
// key the person already has, the request is signed in a one-shot worker in
// this browser, and the key stays here. This script makes no request itself.
// What was made is forgotten on leaving the page, on starting again, and
// after ten idle minutes.
(function () {
  const ui = globalThis.rootwellUI;
  const $ = (id) => document.getElementById(id);
  const form = $("request-form");
  const names = $("request-names");
  const nameInput = $("request-name");
  const keys = $("request-keys");
  const own = $("request-own");
  const ownFile = $("request-own-file");
  const ownPassword = $("request-own-password");
  const details = {
    organization: $("request-organization"),
    locality: $("request-city"),
    province: $("request-state"),
    country: $("request-country"),
  };
  const create = $("request-create");
  const status = $("request-status");
  const result = $("request-result");
  const resultTitle = $("request-result-title");
  const resultFacts = $("request-facts");
  const resultFiles = $("request-files");
  const encoder = new TextEncoder();
  const none = () => new Uint8Array(0);
  const keyLimit = 64 * 1024;
  const idleLimit = 10 * 60 * 1000;
  const maxNames = 32;
  const maxAddresses = 8;
  const refused = {
    400: "These names cannot go into a request. Check them, then try again.",
    401: "Your session has ended. Sign in again.",
    503: "Rootwell is busy. Try again in a moment.",
  };

  let list = [];
  let nameNote = false;
  let made = null;
  let generation = 0;
  let controller = null;
  let busy = false;
  let idle = 0;

  const wipe = (bytes) => { if (bytes instanceof Uint8Array) bytes.fill(0); };

  function say(kind, text) {
    if (!text) return status.replaceChildren();
    status.replaceChildren(ui.el("span", kind === "bad" ? "error-text" : "meta", text));
  }

  // ── Names ──────────────────────────────────────────────────────────────

  const isAddress = (value) => /^\d{1,3}(\.\d{1,3}){3}$/.test(value) || (value.includes(":") && /^[0-9a-f:.]+$/.test(value));

  // A name as the engine wants it: lower case, no scheme, path or port, and
  // international names in their xn-- form. Null when it cannot be one.
  function clean(raw) {
    let value = raw.trim().toLowerCase().replace(/^[a-z]+:\/\//, "").replace(/[/?#].*$/, "").replace(/\.$/, "");
    if (!value) return null;
    if (isAddress(value)) return value;
    value = value.replace(/:\d+$/, "");
    const wildcard = value.startsWith("*.");
    let host = wildcard ? value.slice(2) : value;
    if (/[^\x00-\x7f]/.test(host)) {
      try { host = new URL("http://" + host).hostname; } catch { return null; }
    }
    const labels = host.split(".");
    if (host.length > 253 - (wildcard ? 2 : 0) || labels.some((l) => !/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l))) return null;
    return (wildcard ? "*." : "") + host;
  }

  function addNames(text) {
    const refusedNames = [];
    for (const raw of String(text).split(/[\s,;]+/)) {
      if (!raw) continue;
      const value = clean(raw);
      if (!value) { refusedNames.push(raw); continue; }
      if (list.includes(value)) continue;
      const addresses = list.filter(isAddress).length;
      if (isAddress(value) ? addresses >= maxAddresses : list.length - addresses >= maxNames) {
        say("bad", "Use up to " + maxNames + " names and " + maxAddresses + " addresses.");
        break;
      }
      list.push(value);
    }
    drawNames();
    if (refusedNames.length) {
      say("bad", refusedNames.join(", ") + (refusedNames.length === 1 ? " is not a name a certificate can hold." : " are not names a certificate can hold."));
      nameNote = true;
    } else if (nameNote) {
      say();
      nameNote = false;
    }
  }

  function drawNames() {
    const chips = list.map((value) => {
      const chip = ui.el("span", "chip", value);
      const remove = ui.el("button");
      remove.type = "button";
      remove.setAttribute("aria-label", "Remove " + value);
      remove.appendChild(ui.icon("x"));
      remove.addEventListener("click", () => { list = list.filter((v) => v !== value); drawNames(); nameInput.focus(); });
      chip.appendChild(remove);
      return chip;
    });
    names.replaceChildren(...chips, nameInput);
    nameInput.placeholder = list.length ? "" : "Type a name, press Enter";
  }

  nameInput.addEventListener("keydown", (event) => {
    if ((event.key === "Enter" || event.key === "," || event.key === " ") && nameInput.value.trim()) {
      event.preventDefault();
      addNames(nameInput.value);
      nameInput.value = "";
    } else if (event.key === "Backspace" && !nameInput.value && list.length) {
      list = list.slice(0, -1);
      drawNames();
    }
  });
  // Pasted lists split into names at once.
  nameInput.addEventListener("input", () => {
    if (/[\s,;]/.test(nameInput.value.trim())) {
      addNames(nameInput.value);
      nameInput.value = "";
    }
  });
  nameInput.addEventListener("blur", () => {
    if (nameInput.value.trim()) { addNames(nameInput.value); nameInput.value = ""; }
  });

  // ── Key ────────────────────────────────────────────────────────────────

  function keyKind() {
    const radio = keys.querySelector("input:checked");
    return radio ? radio.value : "ec-p256";
  }

  function updateKey() {
    own.hidden = keyKind() !== "own";
    touch();
  }

  // ── Making the request ─────────────────────────────────────────────────

  function forgetMade() {
    if (made) wipe(made.bytes);
    made = null;
    resultFiles.replaceChildren();
    resultFacts.replaceChildren();
    result.hidden = true;
  }

  function forget() {
    generation++;
    controller?.abort();
    controller = null;
    busy = false;
    create.disabled = false;
    clearTimeout(idle);
    forgetMade();
    ownPassword.value = "";
    ownFile.value = "";
  }

  function touch() {
    clearTimeout(idle);
    idle = setTimeout(() => {
      if (made) { forget(); say("bad", "The request was cleared from this page after ten idle minutes."); }
    }, idleLimit);
  }

  function factBlock(label, value) {
    const fact = ui.el("div", "fact");
    fact.appendChild(ui.el("span", "", label));
    fact.appendChild(ui.el("strong", "", value));
    return fact;
  }

  function step(title, hint, extra) {
    const item = ui.el("li");
    const words = ui.el("div");
    words.appendChild(ui.el("strong", "", title));
    if (hint) words.appendChild(ui.el("span", "", hint));
    if (extra) words.appendChild(extra);
    item.appendChild(words);
    return item;
  }

  // What happens next, in three steps: the request to send, the provider,
  // and where the certificate goes when it comes back.
  function show(covered, keyType, kept) {
    resultTitle.textContent = "Request ready for " + covered[0];
    resultFacts.replaceChildren(factBlock("Works for", covered.join(", ")), factBlock("Key", kept ? keyType + ", kept in Rootwell" : keyType));
    const buttons = ui.el("div", "input-row");
    const save = ui.el("button", "btn btn-sm");
    save.type = "button";
    save.appendChild(ui.icon("download"));
    save.appendChild(ui.el("span", "", made.name));
    save.addEventListener("click", () => { ui.download(made.bytes, made.name, "application/pkcs10"); touch(); });
    buttons.appendChild(save);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      const copy = ui.el("button", "btn btn-secondary btn-sm", "Copy");
      copy.type = "button";
      copy.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(new TextDecoder().decode(made.bytes));
          copy.textContent = "Copied";
          setTimeout(() => { copy.textContent = "Copy"; }, 2000);
        } catch {
          copy.hidden = true;
        }
        touch();
      });
      buttons.appendChild(copy);
    }
    resultFiles.replaceChildren(
      step("Download the request", "", buttons),
      step("Give it to your certificate provider", "They send the certificate back."),
      step("Add the certificate in Certificates", kept ? "Rootwell puts it with the key it keeps. The request waits there until then." : "Add your key with it."),
    );
    result.hidden = false;
    result.classList.add("result-enter");
  }

  const keyName = (summary) => summary.curve ? summary.algorithm + " " + summary.curve : summary.algorithm === "RSA" ? "RSA " + summary.bits : summary.algorithm;

  async function submit(event) {
    event.preventDefault();
    if (busy) return;
    if (nameInput.value.trim()) { addNames(nameInput.value); nameInput.value = ""; }
    if (!list.length) return say("bad", "Add the name the certificate is for.");
    const country = details.country.value.trim().toUpperCase();
    if (country && !/^[A-Z]{2}$/.test(country)) return say("bad", "Enter the country as two letters, such as DE or US.");
    const params = {
      dns_names: list.filter((n) => !isAddress(n)),
      ip_addresses: list.filter(isAddress),
      organization: details.organization.value.trim(),
      country,
      locality: details.locality.value.trim(),
      province: details.province.value.trim(),
    };
    const kind = keyKind();
    const file = ownFile.files && ownFile.files[0];
    if (kind === "own" && !file) return say("bad", "Choose your key file.");
    if (JSON.stringify(params).length > 16384) return say("bad", "The details are too long.");
    const ticket = ++generation;
    controller?.abort();
    const signal = (controller = new AbortController()).signal;
    busy = true;
    create.disabled = true;
    forgetMade();
    say("plain", kind === "rsa-2048" ? "Making an RSA key takes a few seconds…" : "Making the request…");
    if (kind !== "own") return keepOnServer(ticket, kind, params);
    const password = encoder.encode(ownPassword.value);
    ownPassword.value = "";
    let input = none();
    let answer = null;
    try {
      if (password.byteLength > 256) throw new Error("long");
      const option = JSON.stringify({ algorithm: "", params: { ...params, common_name: "", organizational_unit: "" }, format: "pem" });
      const engine = await globalThis.rootwellWorkbenchReady;
      if (!file.size || file.size > keyLimit) throw new Error("size");
      input = new Uint8Array(await file.slice(0, keyLimit + 1).arrayBuffer());
      if (input.byteLength !== file.size) throw new Error("changed");
      answer = await globalThis.rootwellCSRWorker.run(engine.module, "key", input, none(), password, option, signal);
      if (ticket !== generation) return;
      const value = answer && answer.ok === true && answer.result;
      if (!value || !(value.csr instanceof Uint8Array) || typeof value.summary !== "string") throw new Error("answer");
      const summary = JSON.parse(value.summary);
      if (!Array.isArray(summary.dns_names) || !Array.isArray(summary.ip_addresses)) throw new Error("summary");
      const covered = [...summary.dns_names, ...summary.ip_addresses];
      made = { name: ui.friendlyName(covered[0], "request") + ".csr", bytes: value.csr.slice() };
      show(covered, keyName(summary), false);
      say();
      touch();
    } catch {
      if (ticket === generation) say("bad", "The request could not be made. Check the key file and its password.");
    } finally {
      wipe(input);
      wipe(password);
      if (answer && answer.result) { wipe(answer.result.bytes); wipe(answer.result.csr); }
      if (ticket === generation) { busy = false; create.disabled = false; controller = null; }
    }
  }

  // A new key: Rootwell makes and keeps it, and sends back the request.
  async function keepOnServer(ticket, algorithm, params) {
    try {
      const answer = await globalThis.rootwellKeepRequest({ algorithm, ...params });
      if (ticket !== generation) return;
      if (!answer.request) {
        const message = answer.refusal === "requests-full" ? "50 requests are waiting in Certificates. Finish or cancel one first." :
          refused[answer.status] || "The request could not be made. Try again.";
        return say("bad", message);
      }
      const request = answer.request;
      const covered = [...request.dns_names, ...request.ip_addresses];
      made = { name: ui.friendlyName(covered[0] || "request", "request") + ".csr", bytes: encoder.encode(request.csr) };
      show(covered, request.key_type, true);
      say();
      touch();
    } catch {
      if (ticket === generation) say("bad", "The request could not be made. Check the names and details, then try again.");
    } finally {
      if (ticket === generation) { busy = false; create.disabled = false; controller = null; }
    }
  }

  form.addEventListener("submit", submit);
  for (const radio of keys.querySelectorAll("input")) radio.addEventListener("change", updateKey);
  // Leaving the page forgets the request and any key file chosen.
  globalThis.addEventListener("pagehide", forget);
  drawNames();
  updateKey();
})();
