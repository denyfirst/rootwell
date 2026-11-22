"use strict";

// Convert: turn a certificate, a private key or a PFX into the format a server
// needs. Everything happens in this browser: public certificates in the page's
// engine, private keys and PFX files in one-shot workers. This script makes no
// request. Files and passwords are forgotten when the page is left, when other
// files are chosen, and after ten idle minutes.
(function () {
  const ui = globalThis.rootwellUI;
  const $ = (id) => document.getElementById(id);
  const zone = $("convert-drop");
  const input = $("convert-file");
  const card = $("convert-card");
  const chip = $("convert-chip");
  const chipName = $("convert-chip-name");
  const chipInfo = $("convert-chip-info");
  const again = $("convert-again");
  const unlock = $("convert-unlock");
  const unlockLabel = $("convert-password-label");
  const unlockPassword = $("convert-password");
  const unlockButton = $("convert-open");
  const unlockError = $("convert-unlock-error");
  const formats = $("convert-formats");
  const choices = $("convert-choices");
  const keyRow = $("convert-key-row");
  const keyFile = $("convert-key-file");
  const secretRow = $("convert-secret-row");
  const secretLabel = $("convert-secret-label");
  const secretOptional = $("convert-secret-optional");
  const secret = $("convert-secret");
  const generate = $("convert-generate");
  const copy = $("convert-copy");
  const secretNote = $("convert-secret-note");
  const go = $("convert-go");
  const download = $("convert-download");
  const downloadName = $("convert-download-name");
  const contents = $("convert-contents");
  const status = $("convert-status");
  const error = $("convert-error");
  const encoder = new TextEncoder();
  const none = () => new Uint8Array(0);
  const maxFiles = 4;
  const keyLimit = 64 * 1024;
  const pfxLimit = 1 << 20;
  const idleLimit = 10 * 60 * 1000;

  let engine = null;
  let generation = 0;
  let source = null;
  let options = [];
  let controller = null;
  let busy = false;
  let idle = 0;

  // A message meant for the person, as opposed to an engine failure.
  class Plain extends Error {}

  const wipe = (bytes) => { if (bytes instanceof Uint8Array) bytes.fill(0); };

  function forget() {
    controller?.abort();
    controller = null;
    busy = false;
    clearTimeout(idle);
    if (source) {
      source.certs?.parts.forEach(wipe);
      if (source.key) { wipe(source.key.bytes); wipe(source.key.password); }
      if (source.pfx) { wipe(source.pfx.bytes); wipe(source.pfx.password); }
    }
    source = null;
    options = [];
    choices.replaceChildren();
    unlockPassword.value = "";
    secret.value = "";
    secret.type = "password";
    secretNote.hidden = true;
    copy.hidden = true;
    generate.hidden = false;
    keyFile.value = "";
  }

  function reset() {
    generation++;
    forget();
    card.hidden = true;
    zone.hidden = false;
    error.hidden = true;
    status.replaceChildren();
  }

  // Ten quiet minutes forget the files and passwords.
  function touch() {
    clearTimeout(idle);
    idle = setTimeout(() => { if (source) { reset(); showError("The files were cleared after ten idle minutes. Choose them again."); } }, idleLimit);
  }

  function showError(text) {
    error.textContent = text;
    error.hidden = false;
  }

  function say(kind, text) {
    if (!text) return status.replaceChildren();
    if (kind === "good") {
      const notice = ui.el("div", "notice good");
      notice.appendChild(ui.icon("ok"));
      notice.appendChild(ui.el("span", "", text));
      return status.replaceChildren(notice);
    }
    status.replaceChildren(ui.el("span", kind === "bad" ? "error-text" : "meta", text));
  }

  async function read(file, limit) {
    if (!file.size || file.size > limit) throw new Plain(file.name + " is empty or too large.");
    const bytes = new Uint8Array(await file.slice(0, limit + 1).arrayBuffer());
    if (bytes.byteLength !== file.size) { bytes.fill(0); throw new Error("changed"); }
    return bytes;
  }

  // ── What a dropped file is ─────────────────────────────────────────────

  // A private key, plain or locked, or null when the bytes are not one.
  async function keyInfo(bytes, password, signal) {
    if (bytes.byteLength > keyLimit) return null;
    try {
      const answer = JSON.parse(await globalThis.rootwellPrivateWorker.run(engine.module, "inspect", bytes, password || none(), "", "", none(), signal));
      if (answer && answer.error === "input-password-required") return { locked: true };
      if (answer && answer.error === "wrong-password") return { locked: true, wrong: true };
      if (!answer || answer.ok !== true || !answer.result || typeof answer.result.public_fingerprint !== "string") return null;
      return { locked: false, info: answer.result };
    } catch {
      if (signal.aborted) throw new Error("stopped");
      return null;
    }
  }

  function certificateSet(parts) {
    const list = parts.flatMap((part) => part.list);
    const where = new Map();
    parts.forEach((part, index) => part.list.forEach((c) => where.set(c.sha256, index)));
    if (where.size !== list.length) throw new Plain("The same certificate appears twice. Choose each file once.");
    const bytes = parts.map((part) => part.bytes);
    const analysis = JSON.parse(engine.analyze(bytes));
    if (!analysis.result || analysis.result.certificates.length !== list.length) throw new Plain("These certificates do not belong together. Convert them one at a time.");
    const order = ui.chainOrder(list, analysis.result);
    const leaf = list[order[0]];
    const intermediates = order.slice(1).filter((i) => !analysis.result.certificates[i].self_signed).map((i) => list[i].sha256);
    const root = order.length > 1 && analysis.result.certificates[order[order.length - 1]].self_signed ? 1 : 0;
    return { parts: bytes, where, name: ui.commonName(leaf.subject), leaf: leaf.sha256, intermediates, root, extra: list.length - 1 - intermediates.length - root };
  }

  // The PFX's own list, ordered leaf first by issuer name. The engine checks
  // every signature again when a new PFX is made.
  function pfxChain(list) {
    const leaf = list.find((c) => c.matching_key);
    const order = [leaf];
    let at = leaf;
    while (at.subject !== at.issuer) {
      const next = list.find((c) => !order.includes(c) && c.subject === at.issuer);
      if (!next) break;
      order.push(next);
      at = next;
    }
    const intermediates = order.slice(1).filter((c) => c.subject !== c.issuer).map((c) => c.fingerprint);
    const root = order.length > 1 && at.subject === at.issuer ? 1 : 0;
    return { name: ui.commonName(leaf.subject), leaf: leaf.fingerprint, intermediates, root, extra: list.length - 1 - intermediates.length - root };
  }

  async function keyMatches(signal) {
    const leaf = certificate(source.certs.leaf, "der");
    const key = source.key.bytes.slice();
    const password = (source.key.password || none()).slice();
    try {
      const answer = JSON.parse(await globalThis.rootwellCSRWorker.run(engine.module, "certificate-key-match", key, leaf, password, "", signal));
      return answer.ok === true && answer.records.some((r) => r.key_status === "matched");
    } finally {
      for (const bytes of [leaf, key, password]) wipe(bytes);
    }
  }

  async function open(files) {
    const ticket = ++generation;
    forget();
    error.hidden = true;
    status.replaceChildren();
    if (files.length > maxFiles) return showError("Choose up to " + maxFiles + " files: one PFX, or certificates with their key.");
    try {
      engine = await globalThis.rootwellWorkbenchReady;
    } catch {
      return showError("Rootwell could not start in this browser. Reload the page.");
    }
    const loaded = [];
    const next = { certs: null, key: null, pfx: null, pending: null, files: files.map((f) => f.name) };
    const signal = (controller = new AbortController()).signal;
    try {
      let total = 0;
      for (const file of files) {
        total += file.size;
        if (total > engine.maxBytes) throw new Plain("The files are larger than 16 MB together.");
        loaded.push({ name: file.name, bytes: await read(file, engine.maxBytes) });
      }
      if (ticket !== generation) throw new Error("stale");
      const certParts = [];
      for (const part of loaded) {
        const answer = JSON.parse(engine.explore(part.bytes));
        if (answer.ok) { certParts.push({ bytes: part.bytes, list: answer.result.certificates }); part.used = true; continue; }
        const named = /\.(pfx|p12)$/i.test(part.name);
        const key = named ? null : await keyInfo(part.bytes, null, signal);
        if (ticket !== generation) throw new Error("stale");
        if (key) {
          if (next.key) throw new Plain("Choose one private key at a time.");
          next.key = { bytes: part.bytes, name: part.name, encrypted: key.locked, info: key.info || null, password: null };
        } else if ((named || part.bytes[0] === 0x30) && part.bytes.byteLength <= pfxLimit) {
          if (next.pfx) throw new Plain("Choose one PFX at a time.");
          next.pfx = { bytes: part.bytes, name: part.name, password: null };
        } else {
          throw new Plain(part.name + " is not a certificate, key or PFX file Rootwell can read.");
        }
        part.used = true;
      }
      if (next.pfx && (certParts.length || next.key)) throw new Plain("Open a PFX on its own. It already holds the certificate and key.");
      if (certParts.length) next.certs = certificateSet(certParts);
      next.pending = next.pfx ? "pfx" : next.key && next.key.encrypted ? "key" : null;
      source = next;
      if (!next.pending && next.certs && next.key && !(await keyMatches(signal))) {
        source = null;
        throw new Plain("This key does not belong to the certificate.");
      }
      if (ticket !== generation) throw new Error("stale");
      draw();
    } catch (failure) {
      if (ticket !== generation) { loaded.forEach((part) => wipe(part.bytes)); return; }
      loaded.forEach((part) => wipe(part.bytes));
      source = null;
      showError(failure instanceof Plain ? failure.message : "The files could not be read. Choose them again.");
    } finally {
      if (ticket === generation) controller = null;
    }
  }

  // A private key chosen after the certificate, for a PFX.
  async function addKey() {
    const file = keyFile.files && keyFile.files[0];
    keyFile.value = "";
    if (!file || !source || !source.certs || busy) return;
    const ticket = generation;
    busy = true;
    say("plain", "Reading the key…");
    let bytes = null;
    try {
      bytes = await read(file, keyLimit);
      const signal = (controller = new AbortController()).signal;
      const key = await keyInfo(bytes, null, signal);
      if (ticket !== generation) return wipe(bytes);
      if (!key) throw new Plain(file.name + " is not a private key Rootwell can read.");
      source.key = { bytes, name: file.name, encrypted: key.locked, info: key.info || null, password: null };
      bytes = null;
      if (!key.locked && !(await keyMatches(signal))) {
        wipe(source.key.bytes);
        source.key = null;
        throw new Plain("This key does not belong to the certificate.");
      }
      if (key.locked) source.pending = "key";
      say();
      draw();
    } catch (failure) {
      wipe(bytes);
      if (ticket === generation) say("bad", failure instanceof Plain ? failure.message : "The key could not be read. Choose it again.");
    } finally {
      if (ticket === generation) { busy = false; controller = null; }
    }
  }

  // ── A password that opens the PFX or the key ───────────────────────────

  async function openLocked(event) {
    event.preventDefault();
    if (!source || !source.pending || busy) return;
    const ticket = generation;
    const password = encoder.encode(unlockPassword.value);
    unlockPassword.value = "";
    unlockError.textContent = "";
    if (password.byteLength > (source.pending === "pfx" ? 128 : 256)) {
      wipe(password);
      unlockError.textContent = "That password is too long.";
      return;
    }
    busy = true;
    unlockButton.disabled = true;
    const signal = (controller = new AbortController()).signal;
    try {
      if (source.pending === "pfx") {
        const answer = JSON.parse(await globalThis.rootwellPFXWorker.run(engine.module, "inspect", [source.pfx.bytes, none(), none()], password, none(), "", signal));
        const list = answer && answer.ok === true && answer.result && answer.result.certificates;
        if (!Array.isArray(list) || list.filter((c) => c.matching_key).length !== 1) throw new Plain("That password does not open this PFX.");
        if (ticket !== generation) return wipe(password);
        source.pfx.password = password;
        source.pfx.chain = pfxChain(list);
      } else {
        const key = await keyInfo(source.key.bytes, password, signal);
        if (ticket !== generation) return wipe(password);
        if (!key || key.locked) throw new Plain("That password does not open this key.");
        source.key.info = key.info;
        source.key.password = password;
        if (source.certs && !(await keyMatches(signal))) {
          if (ticket !== generation) return;
          wipe(source.key.bytes); wipe(source.key.password);
          source.key = null;
          source.pending = null;
          draw();
          say("bad", "This key does not belong to the certificate.");
          return;
        }
      }
      if (ticket !== generation) return;
      source.pending = null;
      draw();
    } catch (failure) {
      wipe(password);
      if (ticket === generation) unlockError.textContent = failure instanceof Plain ? failure.message : "That password does not open this file.";
    } finally {
      if (ticket === generation) { busy = false; unlockButton.disabled = false; controller = null; }
    }
  }

  // ── Drawing ────────────────────────────────────────────────────────────

  function chain() {
    return source.pfx ? source.pfx.chain : source.certs;
  }

  function baseName() {
    const named = chain() && chain().name;
    const fromFile = source.key ? source.key.name.replace(/\.[^.]*$/, "") : "";
    return ui.friendlyName(named || fromFile, "certificate");
  }

  function describe() {
    if (source.pending === "pfx") return "PFX · locked";
    const parts = [];
    const c = chain();
    if (c) {
      parts.push("certificate");
      if (c.intermediates.length) parts.push(c.intermediates.length === 1 ? "1 intermediate" : c.intermediates.length + " intermediates");
      if (c.root) parts.push("the root");
      if (c.extra > 0) parts.push(c.extra === 1 ? "1 more certificate" : c.extra + " more certificates");
    }
    if (source.pfx || source.key) parts.push(c ? "the private key" : "Private key");
    let text = parts.length > 1 ? parts.slice(0, -1).join(", ") + " and " + parts[parts.length - 1] : parts[0];
    text = text.charAt(0).toUpperCase() + text.slice(1);
    if (!c && source.key) {
      const info = source.key.info;
      if (info) text += " · " + (info.curve ? info.algorithm + " " + info.curve : info.algorithm === "RSA" ? "RSA " + info.bits : info.algorithm);
      if (source.key.encrypted) text += " · protected";
    }
    return text;
  }

  function formatsFor() {
    const key = !!(source.pfx || source.key);
    if (chain()) {
      return [
        key ? { id: "pem-files", title: "PEM files", hint: "nginx, Apache, most Linux servers", secret: "optional" }
          : { id: "pem", title: "PEM", hint: chain().intermediates.length ? "Full chain · nginx, Apache" : ".pem · nginx, Apache" },
        { id: "crt", title: "Certificate only", hint: ".crt · Windows, browsers" },
        { id: "der", title: "DER", hint: ".cer · Java, older systems" },
        { id: "pfx", title: source.pfx ? "New PFX" : "PFX", hint: source.pfx ? "Same contents, new password" : key ? "With the key · IIS, Windows" : "With the key · add it next", secret: "required", needsKey: !key },
      ];
    }
    const list = [
      { id: "key-pem", title: "PEM", hint: ".key · nginx, Apache", secret: "optional" },
      { id: "key-der", title: "DER", hint: ".der · Java, older systems" },
    ];
    const algorithm = source.key.info.algorithm;
    if (algorithm === "RSA" || algorithm === "ECDSA") list.push({ id: "key-traditional", title: "Older PEM", hint: algorithm === "RSA" ? "RSA PRIVATE KEY · older software" : "EC PRIVATE KEY · older software" });
    return list;
  }

  function plan(choice) {
    const base = baseName();
    const c = chain();
    switch (choice.id) {
      case "pem": return { name: base + (c.intermediates.length ? "-fullchain.pem" : ".pem") };
      case "pem-files": return { name: base + ".zip", files: ["fullchain.pem", "cert.pem", ...(c.intermediates.length ? ["chain.pem"] : []), "privkey.pem"] };
      case "crt": return { name: base + ".crt" };
      case "der": return { name: base + ".cer" };
      case "pfx": return { name: base + ".pfx" };
      case "key-der": return { name: base + "-key.der" };
      default: return { name: base + ".key" };
    }
  }

  function selected() {
    const radio = choices.querySelector("input:checked");
    return options.find((o) => radio && o.id === radio.value) || options[0];
  }

  function tile(option, checked) {
    const label = ui.el("label", "choice");
    const radio = ui.el("input");
    radio.type = "radio";
    radio.name = "convert-format";
    radio.value = option.id;
    radio.checked = checked;
    radio.addEventListener("change", update);
    label.appendChild(radio);
    label.appendChild(ui.el("strong", "", option.title));
    label.appendChild(ui.el("span", "", option.hint));
    return label;
  }

  function draw() {
    touch();
    zone.hidden = true;
    card.hidden = false;
    chip.hidden = false;
    error.hidden = true;
    const files = source.files.length === 1 ? source.files[0] : source.files.length + " files";
    const named = !source.pending && chain();
    chipName.textContent = named ? chain().name : files;
    chipInfo.textContent = (named ? files + " · " : "") + describe();
    unlock.hidden = !source.pending;
    unlockError.textContent = "";
    if (source.pending) {
      unlockLabel.textContent = source.pending === "pfx" ? "PFX password" : "Key password";
      formats.hidden = keyRow.hidden = secretRow.hidden = go.hidden = true;
      unlockPassword.focus();
      return;
    }
    const previous = options.length ? selected().id : "";
    options = formatsFor();
    const keep = options.some((o) => o.id === previous) ? previous : options[0].id;
    choices.replaceChildren(...options.map((o) => tile(o, o.id === keep)));
    formats.hidden = false;
    update();
  }

  function update() {
    if (!source) return;
    touch();
    const choice = selected();
    const waiting = !!(choice.needsKey && !source.key);
    keyRow.hidden = !waiting;
    secretRow.hidden = !choice.secret || waiting;
    if (choice.secret) {
      secretLabel.textContent = choice.secret === "required" ? "Password for the PFX" : "Password for the key";
      secretOptional.hidden = choice.secret === "required";
      secret.placeholder = choice.secret === "required" ? "" : "Leave empty for none";
    }
    const target = plan(choice);
    go.hidden = waiting;
    downloadName.textContent = "Download " + target.name;
    contents.textContent = target.files ? target.files.join(" · ") : "";
    say();
  }

  // ── Making the file ────────────────────────────────────────────────────

  function certificate(fingerprint, format) {
    const answer = engine.exportPublic(source.certs.parts[source.certs.where.get(fingerprint)], fingerprint, format);
    if (!answer || answer.ok !== true || !(answer.result.bytes instanceof Uint8Array)) throw new Error("export");
    return answer.result.bytes;
  }

  async function pfxRun(operation, inputs, password, second, option, signal) {
    const answer = await globalThis.rootwellPFXWorker.run(engine.module, operation, inputs, password, second, option, signal);
    if (!answer || answer.ok !== true || !answer.result || !(answer.result.bytes instanceof Uint8Array) || !answer.result.bytes.byteLength) throw new Error("pfx");
    return answer.result.bytes;
  }

  async function cert(fingerprint, format, signal) {
    if (!source.pfx) return certificate(fingerprint, format);
    return pfxRun("certificate", [source.pfx.bytes, none(), none()], source.pfx.password, none(), fingerprint + ":" + format, signal);
  }

  async function joined(fingerprints, signal) {
    const parts = [];
    try {
      for (const fingerprint of fingerprints) parts.push(await cert(fingerprint, "pem", signal));
      return ui.concat(parts);
    } finally {
      parts.forEach(wipe);
    }
  }

  // The private key, plain or locked with the new password.
  async function key(format, password, signal) {
    const locked = format === "encrypted-pkcs8-pem";
    if (source.pfx) {
      return pfxRun(locked ? "key" : "reveal", [source.pfx.bytes, none(), none()], source.pfx.password, locked ? password : none(), source.pfx.chain.leaf, signal);
    }
    const answer = await globalThis.rootwellPrivateWorker.run(engine.module, "export", source.key.bytes, source.key.password || none(),
      source.key.info.public_fingerprint, format, locked ? password : none(), signal);
    if (!answer || answer.ok !== true || !answer.result || !(answer.result.bytes instanceof Uint8Array) || !answer.result.bytes.byteLength) throw new Error("key");
    return answer.result.bytes;
  }

  async function pfx(password, signal) {
    const c = chain();
    const parts = [];
    try {
      parts.push(await cert(c.leaf, "pem", signal));
      parts.push(await joined(c.intermediates, signal));
      let keyPassword;
      if (source.pfx) {
        parts.push(await key("pkcs8-pem", null, signal));
        keyPassword = none();
      } else {
        parts.push(source.key.bytes.slice());
        keyPassword = (source.key.password || none()).slice();
      }
      parts.push(keyPassword);
      return await pfxRun("create", [parts[0], parts[2], parts[1]], password, keyPassword, "", signal);
    } finally {
      parts.forEach(wipe);
    }
  }

  async function pemFiles(password, signal) {
    const c = chain();
    const files = [];
    try {
      files.push({ name: "fullchain.pem", bytes: await joined([c.leaf, ...c.intermediates], signal) });
      files.push({ name: "cert.pem", bytes: await cert(c.leaf, "pem", signal) });
      if (c.intermediates.length) files.push({ name: "chain.pem", bytes: await joined(c.intermediates, signal) });
      files.push({ name: "privkey.pem", bytes: await key(password.byteLength ? "encrypted-pkcs8-pem" : "pkcs8-pem", password, signal) });
      return ui.zip(files);
    } finally {
      files.forEach((file) => wipe(file.bytes));
    }
  }

  async function make(choice, password, signal) {
    const c = chain();
    switch (choice.id) {
      case "pem": return { bytes: await joined([c.leaf, ...c.intermediates], signal), type: "application/x-pem-file" };
      case "pem-files": return { bytes: await pemFiles(password, signal), type: "application/zip" };
      case "crt": return { bytes: await cert(c.leaf, "pem", signal), type: "application/x-x509-ca-cert" };
      case "der": return { bytes: await cert(c.leaf, "der", signal), type: "application/pkix-cert" };
      case "pfx": return { bytes: await pfx(password, signal), type: "application/x-pkcs12" };
      case "key-pem": return { bytes: await key(password.byteLength ? "encrypted-pkcs8-pem" : "pkcs8-pem", password, signal), type: "application/x-pem-file" };
      case "key-der": return { bytes: await key("pkcs8-der", null, signal), type: "application/octet-stream" };
      default: return { bytes: await key(source.key.info.algorithm === "RSA" ? "pkcs1-pem" : "sec1-pem", null, signal), type: "application/x-pem-file" };
    }
  }

  async function save() {
    if (!source || source.pending || busy) return;
    const choice = selected();
    const typed = choice.secret ? secret.value : "";
    if (choice.secret === "required" && !ui.isStrongPassword(typed)) return say("bad", "Use 20 to 128 letters, digits or symbols, or press Generate.");
    if (choice.secret === "optional" && typed && !ui.isStrongPassword(typed)) return say("bad", "Use 20 to 128 letters, digits or symbols, press Generate, or leave it empty.");
    const current = source.pfx ? source.pfx.password : source.key && source.key.password;
    const password = encoder.encode(typed);
    if (current && password.byteLength && current.byteLength === password.byteLength && current.every((b, i) => b === password[i])) {
      wipe(password);
      return say("bad", "Choose a password different from the current one.");
    }
    const ticket = generation;
    const target = plan(choice);
    busy = true;
    download.disabled = true;
    say("plain", "Making " + target.name + "…");
    const signal = (controller = new AbortController()).signal;
    let made = null;
    try {
      made = await make(choice, password, signal);
      if (ticket !== generation) return;
      ui.download(made.bytes, target.name, made.type);
      say("good", "Downloaded " + target.name);
    } catch {
      if (ticket === generation) say("bad", choice.id === "pfx" && !source.pfx ? "The PFX could not be made. Check that the key belongs to this certificate." : target.name + " could not be made. Try again.");
    } finally {
      wipe(password);
      if (made) wipe(made.bytes);
      if (ticket === generation) { busy = false; download.disabled = false; controller = null; touch(); }
    }
  }

  // ── Passwords a person does not have to think up ───────────────────────

  generate.addEventListener("click", () => {
    secret.value = ui.strongPassword();
    secret.type = "text";
    // Once made, the one button copies it; typing brings Generate back.
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

  ui.dropZone(zone, input, open);
  again.addEventListener("click", () => { reset(); input.click(); });
  unlock.addEventListener("submit", openLocked);
  keyFile.addEventListener("change", addKey);
  download.addEventListener("click", save);
  // Leaving the page forgets every file and password.
  globalThis.addEventListener("pagehide", reset);
})();
