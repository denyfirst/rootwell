"use strict";

// Inspect: drop certificate files and see, at a glance, who a certificate is
// for, who issued it, how long it lasts and whether its chain is complete.
// An optional private key is checked against it in a one-shot worker. Files
// never leave this browser: this script makes no request.
(function () {
  const ui = globalThis.rootwellUI;
  const zone = document.getElementById("inspect-drop");
  const input = document.getElementById("inspect-file");
  const chip = document.getElementById("inspect-chip");
  const chipName = document.getElementById("inspect-chip-name");
  const chipInfo = document.getElementById("inspect-chip-info");
  const again = document.getElementById("inspect-again");
  const error = document.getElementById("inspect-error");
  const result = document.getElementById("inspect-result");
  const keyCard = document.getElementById("key-card");
  const keyFile = document.getElementById("key-file");
  const keyPassword = document.getElementById("key-password");
  const keyCheck = document.getElementById("key-check");
  const keyStatus = document.getElementById("key-status");
  const maxFiles = 8;
  let generation = 0;
  let certificateBytes = null;
  let keyController = null;
  // A key that came in the same file as the certificates.
  let fileKey = null;

  const messages = {
    "empty-input": "The file is empty.",
    "input-too-large": "The files are larger than 16 MB together.",
    "certificate-count-limit": "There are more than 64 certificates in these files.",
    "duplicate-certificate": "The same certificate appears twice. Choose each file once.",
  };

  function forget() {
    if (certificateBytes) certificateBytes.fill(0);
    certificateBytes = null;
    if (fileKey) fileKey.fill(0);
    fileKey = null;
    keyController?.abort();
    keyController = null;
    keyStatus.replaceChildren();
    keyPassword.value = "";
  }

  function fail(text) {
    error.textContent = text;
    error.hidden = false;
    result.replaceChildren();
    result.hidden = true;
    keyCard.hidden = true;
  }

  async function read(files) {
    const parts = [];
    let total = 0;
    for (const file of files) {
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (bytes.byteLength !== file.size) throw new Error("changed");
      total += bytes.byteLength;
      parts.push(bytes);
    }
    return { parts, total };
  }

  function role(certificate, index, parents, certificates) {
    if (!certificate.is_ca) return "Website certificate";
    const selfSigned = parents.certificates[index] && parents.certificates[index].self_signed;
    return selfSigned ? "Root" : "Intermediate";
  }

  function factBlock(label, value) {
    const fact = ui.el("div", "fact");
    fact.appendChild(ui.el("span", "", label));
    fact.appendChild(ui.el("strong", "", value));
    return fact;
  }

  function heroCard(detail, certificate) {
    const card = ui.el("section", "card result-enter");
    const body = ui.el("div", "card-body stack");
    const top = ui.el("div", "between");
    const hero = ui.el("div", "cert-hero");
    const mark = ui.el("span", "cert-mark");
    mark.appendChild(ui.icon("certificate"));
    hero.appendChild(mark);
    const words = ui.el("div");
    words.appendChild(ui.el("h2", "", ui.commonName(detail.subject)));
    words.appendChild(ui.el("p", "", "Issued by " + ui.commonName(detail.issuer)));
    hero.appendChild(words);
    top.appendChild(hero);
    top.appendChild(ui.pill(detail.validity.not_after));
    body.appendChild(top);
    body.appendChild(ui.lifetimeBar(detail.validity.not_before, detail.validity.not_after));
    const facts = ui.el("div", "facts gap-top");
    const names = detail.subject_alternative_names || {};
    const covered = [...(names.dns || []), ...(names.ip || [])];
    facts.appendChild(factBlock("Works for", covered.length ? covered.join(", ") : "No names in the certificate"));
    const key = detail.public_key || {};
    facts.appendChild(factBlock("Key", key.curve ? key.algorithm + " " + key.curve : key.algorithm === "RSA" && key.bits ? "RSA " + key.bits : key.algorithm));
    const fingerprint = factBlock("Fingerprint", ui.shortFingerprint(certificate.sha256));
    fingerprint.querySelector("strong").className = "mono";
    fingerprint.title = certificate.sha256;
    facts.appendChild(fingerprint);
    body.appendChild(facts);
    card.appendChild(body);
    return card;
  }

  // A certificate request: what it asks for and its key. It is checked in
  // the one-shot request worker; nothing is kept.
  function requestCard(summary) {
    const card = ui.el("section", "card result-enter");
    const body = ui.el("div", "card-body stack");
    const hero = ui.el("div", "cert-hero");
    const mark = ui.el("span", "cert-mark");
    mark.appendChild(ui.icon("file"));
    hero.appendChild(mark);
    const words = ui.el("div");
    const asked = [...(summary.dns_names || []), ...(summary.ip_addresses || [])];
    words.appendChild(ui.el("h2", "", ui.unicodeName(ui.commonName(summary.subject) || asked[0] || "Certificate request")));
    words.appendChild(ui.el("p", "", "A certificate request. Send it to your certificate provider; the certificate they return goes in Certificates."));
    hero.appendChild(words);
    body.appendChild(hero);
    const facts = ui.el("div", "facts gap-top");
    facts.appendChild(factBlock("Asks for", asked.length ? asked.map(ui.unicodeName).join(", ") : "No names in the request"));
    facts.appendChild(factBlock("Key", summary.curve ? summary.algorithm + " " + summary.curve : summary.bits ? summary.algorithm + " " + summary.bits : summary.algorithm));
    facts.appendChild(factBlock("Signature", summary.signature_checked ? "Made with its own key" : "Not checked"));
    body.appendChild(facts);
    card.appendChild(body);
    return card;
  }

  function chainCard(certificates, analysis, order) {
    const card = ui.el("section", "card result-enter");
    const head = ui.el("div", "card-head");
    head.appendChild(ui.el("h3", "", "Chain"));
    const last = certificates[order[order.length - 1]];
    const complete = analysis.certificates[order[order.length - 1]].self_signed;
    head.appendChild(ui.el("span", complete ? "pill pill-good" : "pill pill-plain", complete ? "Complete" : "Ends at " + ui.commonName(last.issuer)));
    card.appendChild(head);
    const body = ui.el("div", "card-body");
    const chain = ui.el("div", "chain");
    const now = Date.now();
    for (const index of order) {
      const certificate = certificates[index];
      const expired = Date.parse(certificate.not_after) <= now;
      const link = ui.el("div", "link " + (expired ? "broken" : "ok"));
      const mark = ui.el("span", "link-mark");
      const label = role(certificate, index, analysis, certificates);
      mark.appendChild(ui.icon(label === "Root" ? "root" : "certificate"));
      link.appendChild(mark);
      const words = ui.el("span");
      words.appendChild(ui.el("strong", "", ui.commonName(certificate.subject)));
      words.appendChild(ui.el("small", "", label));
      link.appendChild(words);
      link.appendChild(ui.pill(certificate.not_after, now));
      chain.appendChild(link);
    }
    body.appendChild(chain);
    const others = certificates.length - order.length;
    if (others > 0) body.appendChild(ui.el("p", "meta gap-top", others === 1 ? "1 more certificate in these files is not part of this chain." : others + " more certificates in these files are not part of this chain."));
    card.appendChild(body);
    return card;
  }

  async function showRequest(ticket, name, bytes, engine) {
    let summary = null;
    const controller = new AbortController();
    try {
      const answer = JSON.parse(await globalThis.rootwellCSRWorker.run(engine.module, "inspect", bytes, new Uint8Array(0), new Uint8Array(0), "", controller.signal));
      summary = answer && answer.ok === true && answer.result;
    } catch {
      summary = null;
    } finally {
      bytes.fill(0);
    }
    if (ticket !== generation) return;
    if (!summary || typeof summary.subject !== "string") return fail(name + " is a certificate request Rootwell could not read.");
    chipName.textContent = name;
    chipInfo.textContent = "Certificate request";
    zone.hidden = true;
    chip.hidden = false;
    result.replaceChildren(requestCard(summary));
    result.hidden = false;
    keyCard.hidden = true;
  }

  async function open(files) {
    const ticket = ++generation;
    forget();
    error.hidden = true;
    if (files.length > maxFiles) return fail("Choose up to " + maxFiles + " files at once.");
    let engine, data;
    try {
      engine = await globalThis.rootwellWorkbenchReady;
      data = await read(files);
    } catch {
      return ticket === generation && fail("The files could not be read. Choose them again.");
    }
    if (ticket !== generation) return data.parts.forEach((p) => p.fill(0));
    // The certificates of each file in their strict form: a P7B, a byte order
    // mark or text around the blocks are read here, by content.
    const sources = [];
    let key = null;
    try {
      if (data.total > engine.maxBytes) return fail(messages["input-too-large"]);
      const certificates = [];
      for (let i = 0; i < data.parts.length; i++) {
        const read = engine.readFile(data.parts[i]);
        const parts = read && read.ok === true && read.result;
        if (!parts) {
          const code = read && read.error;
          if (code === "certificate-request" && data.parts.length === 1) return showRequest(ticket, files[0].name, data.parts[0], engine);
          return fail(code === "certificate-request" ? "Open a certificate request on its own." :
            messages[code] || ui.fileProblem(files[i].name, code));
        }
        for (const name of ["certificates", "key"]) if (parts[name] instanceof Uint8Array) sources.push(parts[name]);
        if (parts.kind === "pfx") return fail("This is a PFX file. Open it in Convert to see what is inside.");
        if (parts.kind === "key") return fail("This is a private key, not a certificate. Use Check a private key after opening its certificate.");
        if (parts.key) {
          if (key) return fail("These files hold more than one private key. Open them one at a time.");
          key = { bytes: parts.key.slice(), locked: parts.key_locked === true };
        }
        const answer = JSON.parse(engine.explore(parts.certificates));
        if (!answer.ok) return fail(messages[answer.error && answer.error.code] || ui.fileProblem(files[i].name));
        certificates.push(...answer.result.certificates);
        data.parts[i].fill(0);
        data.parts[i] = parts.certificates;
      }
      const analysis = JSON.parse(engine.analyze(data.parts));
      if (analysis.error || !analysis.result || analysis.result.certificates.length !== certificates.length) return fail("These files do not belong together. Open them one at a time.");
      const order = ui.chainOrder(certificates, analysis.result);
      const first = order[0];
      // The details come from the certificate's own bytes, read again.
      let source = 0, seen = 0;
      while (source < data.parts.length) {
        const count = JSON.parse(engine.explore(data.parts[source])).result.certificates.length;
        if (first < seen + count) break;
        seen += count;
        source++;
      }
      const exported = engine.exportPublic(data.parts[source], certificates[first].sha256, "der");
      if (!exported.ok) return fail("The certificate could not be read.");
      const detail = JSON.parse(engine.inspect(exported.result.bytes));
      certificateBytes = exported.result.bytes;
      if (!detail.ok) return fail("The certificate could not be read.");
      chipName.textContent = files.length === 1 ? files[0].name : files.length + " files";
      chipInfo.textContent = certificates.length === 1 ? "1 certificate" : certificates.length + " certificates";
      zone.hidden = true;
      chip.hidden = false;
      const cards = [heroCard(detail.result, certificates[first])];
      if (certificates.length > 1) cards.push(chainCard(certificates, analysis.result, order));
      result.replaceChildren(...cards);
      result.hidden = false;
      keyCard.hidden = false;
      // A key in the same file is checked at once, or after its password.
      if (key) {
        fileKey = key.bytes;
        const locked = key.locked;
        key = null;
        if (locked) keyStatus.replaceChildren(ui.el("span", "meta", "This file also holds a locked private key. Enter its password, then press Check key."));
        else void checkKey();
      }
    } catch {
      fail("The files could not be read. Choose them again.");
    } finally {
      data.parts.forEach((p) => p.fill(0));
      sources.forEach((p) => p.fill(0));
      if (key) key.bytes.fill(0);
    }
  }

  async function checkKey() {
    const file = keyFile.files && keyFile.files[0];
    if ((!file && !fileKey) || !certificateBytes) {
      keyStatus.replaceChildren(ui.el("span", "error-text", "Choose the private key file first."));
      return;
    }
    keyController?.abort();
    const controller = new AbortController();
    keyController = controller;
    keyCheck.disabled = true;
    keyStatus.replaceChildren(ui.el("span", "meta", "Checking…"));
    let key = null, password = null, certificate = null;
    try {
      const engine = await globalThis.rootwellWorkbenchReady;
      key = file ? new Uint8Array(await file.slice(0, 64 * 1024 + 1).arrayBuffer()) : fileKey.slice();
      if (key.byteLength > 64 * 1024) throw new Error("too large");
      password = new TextEncoder().encode(keyPassword.value);
      keyPassword.value = "";
      certificate = certificateBytes.slice();
      const answer = JSON.parse(await globalThis.rootwellCSRWorker.run(engine.module, "certificate-key-match", key, certificate, password, "", controller.signal));
      if (controller !== keyController) return;
      if (!answer.ok) {
        keyStatus.replaceChildren(ui.el("span", "error-text", answer.error === "input-password-required" ? "This key is protected. Enter its password and check again." :
          answer.error === "wrong-password" ? "That password does not open the key." : "This is not a private key Rootwell can read."));
        return;
      }
      const matched = answer.records.some((r) => r.key_status === "matched");
      const notice = ui.el("div", "notice " + (matched ? "good" : "bad"));
      notice.appendChild(ui.icon(matched ? "ok" : "bad"));
      notice.appendChild(ui.el("span", "", matched ? "This key belongs to the certificate." : "This key does not belong to the certificate."));
      keyStatus.replaceChildren(notice);
    } catch {
      if (controller === keyController) keyStatus.replaceChildren(ui.el("span", "error-text", "The key could not be checked. Try again."));
    } finally {
      for (const bytes of [key, password, certificate]) if (bytes) bytes.fill(0);
      keyFile.value = "";
      if (controller === keyController) { keyController = null; keyCheck.disabled = false; }
    }
  }

  ui.dropZone(zone, input, open);
  again.addEventListener("click", () => {
    generation++;
    forget();
    result.replaceChildren();
    result.hidden = true;
    keyCard.hidden = true;
    chip.hidden = true;
    zone.hidden = false;
    error.hidden = true;
    input.click();
  });
  keyCheck.addEventListener("click", checkKey);
  // Leaving the page or hiding it forgets the certificate and any key.
  document.addEventListener("visibilitychange", () => { if (document.hidden) forget(); });
  globalThis.addEventListener("pagehide", forget);
})();
