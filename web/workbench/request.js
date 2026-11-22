"use strict";

// Request: make the request file (CSR) a certificate provider asks for, with
// a new key locked by a password or with a key you already have. The key is
// made and signed in a one-shot worker in this browser; this script makes no
// request. What was made is forgotten on leaving the page, on starting again,
// and after ten idle minutes.
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
  const secretRow = $("request-secret-row");
  const secret = $("request-secret");
  const generate = $("request-generate");
  const copy = $("request-copy");
  const secretNote = $("request-secret-note");
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

  let list = [];
  let nameNote = false;
  let made = [];
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
    const refused = [];
    for (const raw of String(text).split(/[\s,;]+/)) {
      if (!raw) continue;
      const value = clean(raw);
      if (!value) { refused.push(raw); continue; }
      if (list.includes(value)) continue;
      const addresses = list.filter(isAddress).length;
      if (isAddress(value) ? addresses >= maxAddresses : list.length - addresses >= maxNames) {
        say("bad", "Use up to " + maxNames + " names and " + maxAddresses + " addresses.");
        break;
      }
      list.push(value);
    }
    drawNames();
    if (refused.length) {
      say("bad", refused.join(", ") + (refused.length === 1 ? " is not a name a certificate can hold." : " are not names a certificate can hold."));
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
    const mine = keyKind() === "own";
    own.hidden = !mine;
    secretRow.hidden = mine;
    touch();
  }

  generate.addEventListener("click", () => {
    secret.value = ui.strongPassword();
    secret.type = "text";
    const canCopy = !!(navigator.clipboard && navigator.clipboard.writeText);
    copy.hidden = !canCopy;
    generate.hidden = canCopy;
    secretNote.hidden = false;
    touch();
  });
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(secret.value);
      copy.textContent = "Copied";
      setTimeout(() => { copy.textContent = "Copy"; }, 2000);
    } catch {
      copy.hidden = true;
      generate.hidden = false;
    }
  });
  secret.addEventListener("input", () => {
    copy.hidden = true;
    generate.hidden = false;
    if (!secret.value) { secret.type = "password"; secretNote.hidden = true; }
  });

  // ── Making the request ─────────────────────────────────────────────────

  function forgetMade() {
    made.forEach((file) => wipe(file.bytes));
    made = [];
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
    secret.value = "";
    secret.type = "password";
    secretNote.hidden = true;
    copy.hidden = true;
    generate.hidden = false;
    ownPassword.value = "";
    ownFile.value = "";
  }

  function touch() {
    clearTimeout(idle);
    idle = setTimeout(() => {
      if (made.length || secret.value) { forget(); say("bad", "The request and its key were cleared after ten idle minutes."); }
    }, idleLimit);
  }

  function factBlock(label, value) {
    const fact = ui.el("div", "fact");
    fact.appendChild(ui.el("span", "", label));
    fact.appendChild(ui.el("strong", "", value));
    return fact;
  }

  function show(summary) {
    const first = summary.dns_names[0] || summary.ip_addresses[0];
    resultTitle.textContent = "Request ready for " + first;
    const covered = [...summary.dns_names, ...summary.ip_addresses];
    resultFacts.replaceChildren(
      factBlock("Works for", covered.join(", ")),
      factBlock("Key", summary.curve ? summary.algorithm + " " + summary.curve : summary.algorithm === "RSA" ? "RSA " + summary.bits : summary.algorithm),
    );
    resultFiles.replaceChildren(...made.map((file) => {
      const row = ui.el("div", "file-chip");
      const mark = ui.el("span", "cert-mark");
      mark.appendChild(ui.icon(file.icon));
      row.appendChild(mark);
      const words = ui.el("div");
      words.appendChild(ui.el("strong", "", file.name));
      words.appendChild(ui.el("small", "", file.hint));
      row.appendChild(words);
      const button = ui.el("button", file.primary ? "btn btn-sm" : "btn btn-secondary btn-sm");
      button.type = "button";
      button.appendChild(ui.icon("download"));
      button.appendChild(ui.el("span", "", "Download"));
      button.addEventListener("click", () => { ui.download(file.bytes, file.name, file.type); touch(); });
      row.appendChild(button);
      return row;
    }));
    result.hidden = false;
    result.classList.add("result-enter");
  }

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
      common_name: "",
      organization: details.organization.value.trim(),
      organizational_unit: "",
      country,
      locality: details.locality.value.trim(),
      province: details.province.value.trim(),
    };
    const kind = keyKind();
    const file = ownFile.files && ownFile.files[0];
    if (kind === "own" && !file) return say("bad", "Choose your key file.");
    if (kind !== "own" && !ui.isStrongPassword(secret.value)) return say("bad", "Use 20 to 128 letters, digits or symbols for the key password, or press Generate.");
    const password = encoder.encode(kind === "own" ? ownPassword.value : secret.value);
    ownPassword.value = "";
    const option = JSON.stringify({ algorithm: kind === "own" ? "" : kind, params, format: kind === "own" ? "pem" : "" });
    if (password.byteLength > 256 || encoder.encode(option).byteLength > 16384) {
      wipe(password);
      return say("bad", "The details are too long.");
    }
    const ticket = ++generation;
    controller?.abort();
    const signal = (controller = new AbortController()).signal;
    busy = true;
    create.disabled = true;
    forgetMade();
    say("plain", kind === "rsa-2048" ? "Making an RSA key takes a few seconds…" : "Making the request…");
    let input = none();
    let answer = null;
    try {
      const engine = await globalThis.rootwellWorkbenchReady;
      if (kind === "own") {
        if (!file.size || file.size > keyLimit) throw new Error("size");
        input = new Uint8Array(await file.slice(0, keyLimit + 1).arrayBuffer());
        if (input.byteLength !== file.size) throw new Error("changed");
      }
      answer = await globalThis.rootwellCSRWorker.run(engine.module, kind === "own" ? "key" : "generate", input, none(), password, option, signal);
      if (ticket !== generation) return;
      const value = answer && answer.ok === true && answer.result;
      if (!value || !(value.bytes instanceof Uint8Array) || !(value.csr instanceof Uint8Array) || typeof value.summary !== "string") throw new Error("answer");
      const summary = JSON.parse(value.summary);
      if (!Array.isArray(summary.dns_names) || !Array.isArray(summary.ip_addresses)) throw new Error("summary");
      const base = ui.friendlyName(summary.dns_names[0] || summary.ip_addresses[0], "request");
      if (kind !== "own") {
        made.push({ name: base + "-key-and-request.zip", bytes: value.bytes.slice(), type: "application/zip", icon: "lock", primary: true,
          hint: "Your new key, locked with your password, and the request" });
      }
      made.push({ name: base + ".csr", bytes: value.csr.slice(), type: "application/pkcs10", icon: "file", primary: kind === "own",
        hint: "Send this to your certificate provider" });
      show(summary);
      say();
      touch();
    } catch {
      if (ticket === generation) {
        say("bad", kind === "own" ? "The request could not be made. Check the key file and its password." :
          "The request could not be made. Check the names and details, then try again.");
      }
    } finally {
      wipe(input);
      wipe(password);
      if (answer && answer.result) { wipe(answer.result.bytes); wipe(answer.result.csr); }
      if (ticket === generation) { busy = false; create.disabled = false; controller = null; }
    }
  }

  form.addEventListener("submit", submit);
  for (const radio of keys.querySelectorAll("input")) radio.addEventListener("change", updateKey);
  // Leaving the page forgets the request and its key.
  globalThis.addEventListener("pagehide", forget);
  drawNames();
  updateKey();
})();
