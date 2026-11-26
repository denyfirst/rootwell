"use strict";

// Certificates: the saved list at a glance, one certificate in a side sheet,
// and a dialog to add more. Every element is built with textContent; no
// server or certificate text is read as HTML. Requests go only to this
// Rootwell's own /api/inventory and /api/certificates endpoints.
(function () {
  const ui = globalThis.rootwellUI;
  const $ = (id) => document.getElementById(id);
  const encoder = new TextEncoder();
  const day = 86400000;
  const soonDays = 30;
  const fingerprintPattern = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/;

  // A message meant for the person.
  class Plain extends Error {}

  let records = [];
  let generation = 0;
  let filter = "all";
  let loading = null;
  let open = null;
  // The certificate the delete dialog asks about, fixed when it opens.
  let deleteTarget = null;

  const messages = {
    401: "Your session has ended. Sign in again.",
    409: "The list changed in the meantime. It is up to date now; try again.",
    422: "This key is protected. Enter its password.",
    429: "Too many wrong tries. Wait a little, then try again.",
    503: "Rootwell is busy. Try again in a moment.",
  };
  const wrongKeyPassword = "That password does not open the key.";

  // A key download, or deleting a certificate with a key, needs a code from the
  // phone in the last ten minutes. The server answers 428 without one: the page
  // asks for it once, then sends the same request again.
  async function call(path, body, expect, asked) {
    const response = await fetch(path, {
      method: body ? "POST" : "GET", credentials: "same-origin", cache: "no-store", redirect: "error",
      headers: body ? { "Content-Type": "application/json", "X-Rootwell-Request": "1" } : { "X-Rootwell-Request": "1" },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (response.status === 428 && !asked) {
      if (await globalThis.rootwellFresh()) return call(path, body, expect, true);
      throw new Plain("Nothing changed. That needs a code from your phone.");
    }
    if (!response.ok) {
      if (response.status === 409 && response.headers.get("X-Rootwell-Refusal") === "duplicate-certificate") throw new Plain("This certificate is already saved.");
      if (response.status === 422 && response.headers.get("X-Rootwell-Refusal") === "key-password-wrong") throw new Plain(wrongKeyPassword);
      if (response.status === 409) void load();
      throw new Plain(messages[response.status] || expect || "Rootwell could not do that. Try again.");
    }
    return response;
  }

  async function json(response) {
    const text = await response.text();
    if (text.length > 4 * 1024 * 1024) throw new Error("large");
    return JSON.parse(text);
  }

  function base64(bytes) {
    let text = "";
    for (let at = 0; at < bytes.length; at += 8192) text += String.fromCharCode(...bytes.subarray(at, at + 8192));
    return btoa(text);
  }

  const nameOf = (record) => ui.unicodeName(ui.commonName(record.subject) || (record.dns_names && record.dns_names[0]) || (record.ip_addresses && record.ip_addresses[0]) || "Certificate");
  const hashOf = (record) => record.fingerprint.replace(/:/g, "").toLowerCase();
  function kindOf(record, now) {
    const end = Date.parse(record.not_after);
    if (!Number.isFinite(end) || end <= now) return "bad";
    return end - now <= soonDays * day ? "soon" : "good";
  }

  // ── The list ───────────────────────────────────────────────────────────

  const list = $("list");
  const stats = $("stats");
  const search = $("search");
  const searchRow = $("search-row");
  const empty = $("empty");
  const listError = $("list-error");
  const pageStatus = $("page-status");

  function notice(kind, text) {
    if (!text) return pageStatus.replaceChildren();
    const box = ui.el("div", "notice " + kind);
    box.appendChild(ui.icon(kind === "good" ? "ok" : "bad"));
    box.appendChild(ui.el("span", "", text));
    pageStatus.replaceChildren(box);
  }

  // load reads the list again. A read already under way may predate the
  // change that asked for this one, so it is waited for, never reused.
  async function load() {
    while (loading) await loading;
    loading = (async () => {
      try {
        const answer = await json(await call("/api/inventory", null, "The list could not be read. Reload the page."));
        if (!Array.isArray(answer.records) || !Number.isSafeInteger(answer.generation)) throw new Error("answer");
        records = answer.records.filter((r) => r && fingerprintPattern.test(r.fingerprint));
        generation = answer.generation;
        listError.hidden = true;
        draw();
      } catch (failure) {
        listError.textContent = failure instanceof Plain ? failure.message : "The list could not be read. Reload the page.";
        listError.hidden = false;
      } finally {
        loading = null;
      }
    })();
    return loading;
  }

  function statTile(key, label, count, icon) {
    const tile = ui.el("button", "stat");
    tile.type = "button";
    tile.setAttribute("aria-pressed", String(filter === key));
    const mark = ui.el("span", "stat-mark " + (key === "all" ? "all" : key));
    mark.appendChild(ui.icon(icon));
    tile.appendChild(mark);
    const words = ui.el("span");
    words.appendChild(ui.el("strong", "", count));
    words.appendChild(ui.el("span", "", label));
    tile.appendChild(words);
    tile.addEventListener("click", () => { filter = filter === key ? "all" : key; draw(); });
    return tile;
  }

  function row(record, now) {
    const link = ui.el("a", "row");
    link.href = "#" + hashOf(record);
    const name = ui.el("span", "row-name");
    const mark = ui.el("span", "cert-mark");
    mark.appendChild(ui.icon("certificate"));
    name.appendChild(mark);
    const words = ui.el("span");
    words.appendChild(ui.el("strong", "", nameOf(record)));
    words.appendChild(ui.el("small", "", ui.issuerName(record.issuer)));
    name.appendChild(words);
    link.appendChild(name);
    const places = record.locations && record.locations.length ? record.locations : [];
    link.appendChild(ui.el("span", places.length ? "row-cell" : "row-cell row-empty", places.length ? places.join(", ") : "—"));
    const pill = ui.el("span");
    pill.appendChild(ui.pill(record.not_after, now));
    link.appendChild(pill);
    const key = ui.el("span");
    if (record.has_private_key && record.key_status === "matched") {
      const yes = ui.el("span", "key-yes");
      yes.appendChild(ui.icon("key"));
      yes.appendChild(ui.el("span", "", "Saved"));
      key.appendChild(yes);
    } else {
      key.appendChild(ui.el("span", "row-cell", record.has_private_key ? "Does not match" : "Not saved"));
    }
    link.appendChild(key);
    const chevron = ui.el("span", "chevron");
    chevron.appendChild(ui.icon("chevron"));
    link.appendChild(chevron);
    return link;
  }

  function draw() {
    const now = Date.now();
    const counts = { all: records.length, good: 0, soon: 0, bad: 0 };
    for (const record of records) counts[kindOf(record, now)]++;
    const any = records.length > 0;
    empty.hidden = any;
    stats.hidden = !any;
    searchRow.hidden = records.length < 8;
    list.hidden = !any;
    if (!any) { closeSheet(); return; }
    stats.replaceChildren(
      statTile("all", "All", counts.all, "certificate"),
      statTile("good", "Good", counts.good, "ok"),
      statTile("soon", "Expiring soon", counts.soon, "alert"),
      statTile("bad", "Expired", counts.bad, "bad"),
    );
    const query = searchRow.hidden ? "" : search.value.trim().toLowerCase();
    const shown = records
      .filter((r) => filter === "all" || kindOf(r, now) === filter)
      .filter((r) => !query || [nameOf(r), r.issuer || "", ...(r.dns_names || []), ...(r.dns_names || []).map(ui.unicodeName), ...(r.ip_addresses || []), ...(r.locations || []), r.owner || ""].some((v) => v.toLowerCase().includes(query)))
      .sort((a, b) => Date.parse(a.not_after) - Date.parse(b.not_after));
    const head = ui.el("div", "list-head");
    for (const label of ["Certificate", "Used on", "Expires", "Private key", ""]) head.appendChild(ui.el("span", "", label));
    list.replaceChildren(head, ...shown.map((r) => row(r, now)));
    if (!shown.length) list.appendChild(ui.el("p", "card-body meta", "No certificate matches."));
    if (open) {
      const fresh = records.find((r) => r.fingerprint === open.fingerprint);
      if (fresh) showSheet(fresh); else closeSheet();
    } else {
      fromHash();
    }
  }

  search.addEventListener("input", draw);

  // ── One certificate ────────────────────────────────────────────────────

  const sheet = $("sheet");
  const sheetChain = $("sheet-chain");
  const sheetScrim = $("sheet-scrim");
  const sheetPill = $("sheet-pill");
  const sheetHero = $("sheet-hero");
  const sheetNames = $("sheet-names");
  const sheetFacts = $("sheet-facts");
  const places = $("sheet-places");
  const placeInput = $("sheet-place");
  const owner = $("sheet-owner");
  const ownerSave = $("sheet-owner-save");
  const sheetStatus = $("sheet-status");
  const website = $("sheet-website");
  const downloadPanel = $("download-panel");
  const keyPanel = $("key-panel");

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

  function fact(label, value, extra) {
    const block = ui.el("div", "fact");
    block.appendChild(ui.el("span", "", label));
    const strong = ui.el("strong", "", value);
    block.appendChild(strong);
    if (extra) block.appendChild(extra);
    return { block, strong };
  }

  // Who vouches for the certificate, nearest first, from the issuers saved
  // with it. A chain that stops before a root says so.
  function drawChain(record, now) {
    const links = [{ subject: record.subject, not_after: record.not_after, root: false, own: true }, ...(record.chain || [])];
    const nodes = links.map((link) => {
      const node = ui.el("div", "link " + (Date.parse(link.not_after) > now ? "ok" : "broken"));
      const mark = ui.el("span", "link-mark");
      mark.appendChild(ui.icon(link.root ? "root" : "certificate"));
      node.appendChild(mark);
      const words = ui.el("span");
      words.appendChild(ui.el("strong", "", ui.unicodeName(ui.commonName(link.subject)) || "Certificate"));
      words.appendChild(ui.el("small", "", link.own ? "This certificate" : link.root ? "Root" : "Intermediate"));
      node.appendChild(words);
      node.appendChild(ui.pill(link.not_after, now));
      return node;
    });
    const last = links[links.length - 1];
    if (!last.root) {
      const missing = ui.el("div", "link gap");
      const mark = ui.el("span", "link-mark");
      mark.appendChild(ui.icon("certificate"));
      missing.appendChild(mark);
      const words = ui.el("span");
      words.appendChild(ui.el("strong", "", ui.commonName(last.own ? record.issuer : last.issuer) || "Issuer"));
      words.appendChild(ui.el("small", "", "Not saved with this certificate"));
      missing.appendChild(words);
      nodes.push(missing);
    }
    sheetChain.replaceChildren(...nodes);
  }

  function showSheet(record) {
    const same = open && open.fingerprint === record.fingerprint;
    // Another certificate's sheet never inherits a delete dialog.
    if (!same && deleteTarget) closeDelete();
    open = record;
    const now = Date.now();
    sheetPill.replaceChildren(ui.pill(record.not_after, now));
    const hero = ui.el("div", "cert-hero");
    const mark = ui.el("span", "cert-mark");
    mark.appendChild(ui.icon("certificate"));
    hero.appendChild(mark);
    const words = ui.el("div");
    const title = ui.el("h2", "", nameOf(record));
    title.id = "sheet-title";
    words.appendChild(title);
    const issuerOrganization = ui.organization(record.issuer);
    const issuerCertificate = ui.commonName(record.issuer);
    words.appendChild(ui.el("p", "", "Issued by " + (issuerOrganization && issuerOrganization !== issuerCertificate ? issuerOrganization + " \u00b7 " + issuerCertificate : issuerCertificate)));
    hero.appendChild(words);
    sheetHero.replaceChildren(hero, ui.lifetimeBar(record.not_before, record.not_after, now));
    const covered = [...(record.dns_names || []).map((n) => (ui.unicodeName(n) === n ? n : ui.unicodeName(n) + " (" + n + ")")), ...(record.ip_addresses || [])];
    sheetNames.replaceChildren(...(covered.length ? covered : ["No names in the certificate"]).map((n) => ui.el("span", "", n)));
    drawChain(record, now);
    let keyText = "Not saved";
    let addKey = null;
    if (record.has_private_key) keyText = record.key_status === "matched" ? "Saved" : "Saved, but it does not match";
    else {
      addKey = ui.el("button", "btn btn-secondary btn-sm gap-top", "Add the key");
      addKey.type = "button";
      addKey.addEventListener("click", () => { downloadPanel.hidden = true; keyPanel.hidden = false; resetKeyPanel(); });
    }
    const fingerprint = fact("Fingerprint", ui.shortFingerprint(record.fingerprint));
    fingerprint.strong.className = "mono";
    fingerprint.block.title = record.fingerprint;
    sheetFacts.replaceChildren(
      fact("Private key", keyText, addKey).block,
      fact("Key type", record.key_type || "\u2014").block,
      fingerprint.block,
      fact("Added", record.imported_at ? ui.formatDate(record.imported_at) : "—").block,
    );
    drawPlaces(record);
    if (!same || document.activeElement !== owner) owner.value = record.owner || "";
    ownerSave.hidden = owner.value.trim() === (record.owner || "");
    const host = (record.dns_names || []).find((n) => !n.startsWith("*.")) || ((record.dns_names || [])[0] || "").replace(/^\*\./, "") || (record.ip_addresses || [])[0] || "";
    website.href = "/website-check" + (host ? "#" + encodeURIComponent(host) : "");
    website.hidden = !host;
    if (!same) {
      say(sheetStatus);
      downloadPanel.hidden = true;
      keyPanel.hidden = true;
    }
    sheet.hidden = false;
    sheetScrim.hidden = false;
    if (location.hash !== "#" + hashOf(record)) history.replaceState(null, "", "#" + hashOf(record));
  }

  function closeSheet() {
    if (deleteTarget) closeDelete();
    if (!open && sheet.hidden) return;
    open = null;
    sheet.hidden = true;
    sheetScrim.hidden = true;
    resetDownload();
    resetKeyPanel();
    if (location.hash) history.replaceState(null, "", location.pathname);
  }

  function fromHash() {
    const wanted = decodeURIComponent(location.hash.slice(1)).toLowerCase();
    if (!wanted) return closeSheet();
    const record = records.find((r) => hashOf(r) === wanted);
    if (record) showSheet(record);
  }

  globalThis.addEventListener("hashchange", fromHash);
  $("sheet-close").addEventListener("click", closeSheet);
  sheetScrim.addEventListener("click", closeSheet);

  // Small edits: where it is used, and who looks after it. One at a time: a
  // second click while one is saving would carry the same list generation and
  // be refused as if someone else had changed the list.
  let editing = false;
  async function edit(path, body, done) {
    if (!open || editing) return;
    editing = true;
    ownerSave.disabled = true;
    say(sheetStatus, "plain", "Saving…");
    try {
      await call(path, { fingerprint: open.fingerprint, expected_generation: generation, ...body }, "That change was not saved.");
      await load();
      say(sheetStatus, "good", done);
    } catch (failure) {
      say(sheetStatus, "bad", failure instanceof Plain ? failure.message : "That change was not saved.");
    } finally {
      editing = false;
      ownerSave.disabled = false;
    }
  }

  function drawPlaces(record) {
    const chips = (record.locations || []).map((place) => {
      const chip = ui.el("span", "chip", place);
      const remove = ui.el("button");
      remove.type = "button";
      remove.setAttribute("aria-label", "Remove " + place);
      remove.appendChild(ui.icon("x"));
      remove.addEventListener("click", () => edit("/api/inventory/locations/change", { old_location: place, action: "remove" }, "Removed " + place + "."));
      chip.appendChild(remove);
      return chip;
    });
    places.replaceChildren(...chips, placeInput);
    placeInput.placeholder = chips.length ? "" : "Add a server or service, press Enter";
  }

  placeInput.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") return;
    event.preventDefault();
    const place = placeInput.value.trim();
    if (!place || !open || editing) return;
    if ((open.locations || []).includes(place)) { placeInput.value = ""; return; }
    placeInput.value = "";
    void edit("/api/inventory/locations", { location: place }, "Added " + place + ".");
  });
  owner.addEventListener("input", () => { ownerSave.hidden = !open || owner.value.trim() === (open.owner || ""); });
  ownerSave.addEventListener("click", () => {
    const value = owner.value.trim();
    if (!open || value === (open.owner || "")) { ownerSave.hidden = true; return; }
    return edit("/api/inventory/owner", { owner: value }, "Owner saved.");
  });

  // ── Download ───────────────────────────────────────────────────────────

  const downloadChoices = $("download-choices");
  const downloadSecret = $("download-secret");
  const keyPassword = $("download-key-password");
  const generate = $("download-generate");
  const copy = $("download-copy");
  const note = $("download-note");
  const downloadGo = $("download-go");
  const downloadName = $("download-go-name");
  let downloadOptions = [];

  function resetDownload() {
    keyPassword.value = "";
    keyPassword.type = "password";
    note.hidden = true;
    copy.hidden = true;
    generate.hidden = false;
  }

  function downloadChoice() {
    const radio = downloadChoices.querySelector("input:checked");
    return downloadOptions.find((o) => radio && o.id === radio.value) || downloadOptions[0];
  }

  function updateDownload() {
    const choice = downloadChoice();
    downloadSecret.hidden = !choice.secret;
    downloadName.textContent = "Download " + choice.file(ui.friendlyName(nameOf(open), "certificate"));
  }

  function openDownload() {
    if (!open) return;
    keyPanel.hidden = true;
    const matched = open.has_private_key && open.key_status === "matched";
    downloadOptions = [
      { id: "certificate", title: "Certificate", hint: ".pem · the certificate alone", file: (n) => n + ".pem", body: {} },
      ...(open.bundle_count > 0 ? [{ id: "bundle", title: "Full chain", hint: ".pem · with its issuers", file: (n) => n + "-fullchain.pem", body: { bundle: true } }] : []),
      ...(matched ? [{ id: "pair", title: "Certificate and key", hint: ".zip · key locked with a password", file: (n) => n + ".zip", body: { pair: true }, secret: true }] : []),
      ...(open.has_private_key ? [{ id: "key", title: "Key only", hint: ".key · locked with a password", file: (n) => n + ".key", body: { key_only: true }, secret: true }] : []),
    ];
    downloadChoices.replaceChildren(...downloadOptions.map((option, index) => {
      const label = ui.el("label", "choice");
      const radio = ui.el("input");
      radio.type = "radio";
      radio.name = "download-kind";
      radio.value = option.id;
      radio.checked = index === 0;
      radio.addEventListener("change", updateDownload);
      label.appendChild(radio);
      label.appendChild(ui.el("strong", "", option.title));
      label.appendChild(ui.el("span", "", option.hint));
      return label;
    }));
    resetDownload();
    say(sheetStatus);
    downloadPanel.hidden = false;
    updateDownload();
    downloadPanel.scrollIntoView({ block: "nearest" });
  }

  async function download() {
    if (!open) return;
    const choice = downloadChoice();
    const body = { fingerprint: open.fingerprint, expected_generation: generation, pair: false, ...choice.body };
    if (choice.secret) {
      if (!ui.isStrongPassword(keyPassword.value)) return say(sheetStatus, "bad", "Use 20 to 128 letters, digits or symbols for the key file, or press Generate.");
      const bytes = encoder.encode(keyPassword.value);
      body.output_password = base64(bytes);
      bytes.fill(0);
    }
    downloadGo.disabled = true;
    const name = choice.file(ui.friendlyName(nameOf(open), "certificate"));
    say(sheetStatus, "plain", "Preparing " + name + "…");
    let bytes = null;
    try {
      const response = await call("/api/certificates/download", body, "The download did not start. Try again.");
      bytes = new Uint8Array(await response.arrayBuffer());
      if (!bytes.byteLength || bytes.byteLength > 1200 * 1024) throw new Error("size");
      ui.download(bytes, name, choice.id === "pair" ? "application/zip" : "application/x-pem-file");
      say(sheetStatus, "good", "Downloaded " + name);
    } catch (failure) {
      say(sheetStatus, "bad", failure instanceof Plain ? failure.message : "The download did not start. Try again.");
    } finally {
      if (bytes) bytes.fill(0);
      downloadGo.disabled = false;
    }
  }

  $("sheet-download").addEventListener("click", openDownload);
  downloadGo.addEventListener("click", download);
  generate.addEventListener("click", () => {
    keyPassword.value = ui.strongPassword();
    keyPassword.type = "text";
    const canCopy = !!(navigator.clipboard && navigator.clipboard.writeText);
    copy.hidden = !canCopy;
    generate.hidden = canCopy;
    note.hidden = false;
  });
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(keyPassword.value);
      copy.textContent = "Copied";
      setTimeout(() => { copy.textContent = "Copy"; }, 2000);
    } catch {
      copy.hidden = true;
      generate.hidden = false;
    }
  });
  keyPassword.addEventListener("input", () => {
    copy.hidden = true;
    generate.hidden = false;
    if (!keyPassword.value) { keyPassword.type = "password"; note.hidden = true; }
  });

  // ── A key for a saved certificate ──────────────────────────────────────

  const keyFile = $("key-file");
  const keyFilePassword = $("key-password");
  const keyFilePasswordField = $("key-password-field");
  const keySave = $("key-save");

  function resetKeyPanel() {
    keyFile.value = "";
    keyFilePassword.value = "";
    keyFilePasswordField.hidden = true;
  }

  async function saveKey() {
    if (!open) return;
    const file = keyFile.files && keyFile.files[0];
    if (!file) return say(sheetStatus, "bad", "Choose the key file.");
    if (!file.size || file.size > 64 * 1024) return say(sheetStatus, "bad", "This is not a key file Rootwell can read.");
    const target = open;
    let key = null, password = null;
    keySave.disabled = true;
    say(sheetStatus, "plain", "Checking the key…");
    try {
      key = new Uint8Array(await file.arrayBuffer());
      password = encoder.encode(keyFilePassword.value);
      const body = { fingerprint: target.fingerprint, expected_generation: generation, private_key: base64(key), key_password: base64(password) };
      const checked = await json(await call("/api/certificates/key/check", body, "This is not a key Rootwell can read."));
      const record = checked.records && checked.records[0];
      if (!record || record.fingerprint !== target.fingerprint) throw new Error("answer");
      if (record.key_status !== "matched") throw new Plain("This key does not belong to the certificate.");
      // The person closed or switched the sheet while the key was checked: save nothing.
      if (open !== target) return;
      await call("/api/certificates/key/save", { ...body, allow_mismatch: false }, "The key was not saved. Try again.");
      keyPanel.hidden = true;
      resetKeyPanel();
      await load();
      say(sheetStatus, "good", "The key is saved with the certificate.");
    } catch (failure) {
      if (failure instanceof Plain && (failure.message === messages[422] || failure.message === wrongKeyPassword)) keyFilePasswordField.hidden = false;
      say(sheetStatus, "bad", failure instanceof Plain ? failure.message : "The key was not saved. Try again.");
    } finally {
      if (key) key.fill(0);
      if (password) password.fill(0);
      keySave.disabled = false;
    }
  }

  keySave.addEventListener("click", saveKey);
  keyFile.addEventListener("change", () => { keyFilePasswordField.hidden = true; keyFilePassword.value = ""; });

  // ── Delete ─────────────────────────────────────────────────────────────

  const deleteDialog = $("delete-dialog");
  const deleteScrim = $("delete-scrim");
  const deleteText = $("delete-text");
  const deleteGo = $("delete-go");

  function askDelete() {
    if (!open) return;
    deleteTarget = open;
    deleteText.textContent = nameOf(deleteTarget) + (deleteTarget.has_private_key ? " and its saved key leave" : " leaves") + " Rootwell. Servers that use it are not changed.";
    deleteDialog.hidden = false;
    deleteScrim.hidden = false;
    deleteGo.focus();
  }
  function closeDelete() {
    deleteTarget = null;
    deleteDialog.hidden = true;
    deleteScrim.hidden = true;
  }
  async function confirmDelete() {
    // Only the certificate the dialog named, and only while its sheet is open.
    const target = deleteTarget;
    if (!target || !open || open.fingerprint !== target.fingerprint) return closeDelete();
    deleteGo.disabled = true;
    try {
      await call("/api/inventory/delete", { fingerprint: target.fingerprint, typed_fingerprint: target.fingerprint,
        confirmation: "delete-public-record", expected_generation: generation }, "The certificate was not deleted.");
      closeDelete();
      closeSheet();
      await load();
      notice("good", "Deleted " + nameOf(target) + ".");
    } catch (failure) {
      closeDelete();
      say(sheetStatus, "bad", failure instanceof Plain ? failure.message : "The certificate was not deleted.");
    } finally {
      deleteGo.disabled = false;
    }
  }
  $("sheet-delete").addEventListener("click", askDelete);
  $("delete-cancel").addEventListener("click", closeDelete);
  deleteScrim.addEventListener("click", closeDelete);
  deleteGo.addEventListener("click", confirmDelete);

  // ── Add ────────────────────────────────────────────────────────────────

  const addDialog = $("add-dialog");
  const addScrim = $("add-scrim");
  const addZone = $("add-drop");
  const addInput = $("add-file");
  const addChip = $("add-chip");
  const addChipName = $("add-chip-name");
  const addChipInfo = $("add-chip-info");
  const addPasswordField = $("add-password-field");
  const addPasswordLabel = $("add-password-label");
  const addPassword = $("add-password");
  const addPick = $("add-pick");
  const addChoices = $("add-choices");
  const addPreview = $("add-preview");
  const addPlaceField = $("add-place-field");
  const addPlace = $("add-place");
  const addStatus = $("add-status");
  const addSave = $("add-save");
  let add = null;
  let addTicket = 0;

  function wipeAdd() {
    if (add) for (const bytes of [add.certificate, add.key, add.pfx, add.keySecret]) if (bytes instanceof Uint8Array) bytes.fill(0);
    add = null;
  }

  function resetAdd() {
    addTicket++;
    wipeAdd();
    addZone.hidden = false;
    addChip.hidden = true;
    addPasswordField.hidden = true;
    addPassword.value = "";
    addPassword.placeholder = "";
    addPick.hidden = true;
    addChoices.replaceChildren();
    addPreview.replaceChildren();
    addPlaceField.hidden = true;
    addPlace.value = "";
    addSave.disabled = true;
    say(addStatus);
  }

  function openAdd() {
    resetAdd();
    notice();
    addDialog.hidden = false;
    addScrim.hidden = false;
  }
  function closeAdd() {
    resetAdd();
    addDialog.hidden = true;
    addScrim.hidden = true;
  }

  async function readFile(file, limit) {
    if (!file.size || file.size > limit) throw new Plain(file.name + " is empty or too large.");
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (bytes.byteLength !== file.size) { bytes.fill(0); throw new Error("changed"); }
    return bytes;
  }

  // The password field, for a PFX, which may have none, or a locked key.
  function askPassword(label, optional) {
    addPasswordLabel.textContent = label;
    addPassword.placeholder = optional ? "Leave empty if it has none" : "";
    addPasswordField.hidden = false;
    addPassword.focus();
  }

  // Each file is read by what it holds, not by its name: a PFX named .bin,
  // a P7B, or one PEM with the certificate, its key and its chain.
  async function chooseFiles(files) {
    resetAdd();
    const ticket = addTicket;
    const loaded = [];
    const found = [];
    try {
      if (files.length > 9) throw new Plain("Choose up to 8 certificate files and one key.");
      const engine = await globalThis.rootwellWorkbenchReady;
      for (const file of files) loaded.push({ name: file.name, bytes: await readFile(file, 1 << 20) });
      if (ticket !== addTicket) throw new Error("stale");
      const certParts = [];
      let key = null, pfx = null;
      for (const part of loaded) {
        const answer = engine.readFile(part.bytes);
        const parts = answer && answer.ok === true && answer.result;
        if (!parts) throw new Plain(ui.fileProblem(part.name, answer && answer.error));
        for (const name of ["certificates", "key"]) if (parts[name] instanceof Uint8Array) found.push(parts[name]);
        if (parts.kind === "pfx") {
          if (pfx) throw new Plain("Choose one PFX at a time.");
          pfx = part;
          continue;
        }
        if (parts.certificates) {
          const explored = JSON.parse(engine.explore(parts.certificates));
          if (!explored.ok) throw new Plain(explored.error && explored.error.code === "duplicate-certificate" ? part.name + " holds the same certificate twice." : ui.fileProblem(part.name));
          certParts.push({ bytes: parts.certificates, list: explored.result.certificates });
        }
        if (parts.key) {
          if (key) throw new Plain("Choose one private key at a time.");
          key = { bytes: parts.key, oldStyle: parts.key_old_style === true };
        }
      }
      if (pfx && (certParts.length || key)) throw new Plain("Add a PFX on its own. It already holds the certificate and key.");
      if (!pfx && !certParts.length) throw new Plain("Choose the certificate too, not only the key.");
      add = { engine, files: files.map((f) => f.name), pfx: pfx && pfx.bytes, key: key && key.bytes.slice(), keyOldStyle: !!(key && key.oldStyle),
        certificate: null, keyPassword: "", keySecret: null, primary: "", record: null };
      if (certParts.length) add.certificate = bundle(engine, certParts);
      addZone.hidden = true;
      addChip.hidden = false;
      addChipName.textContent = files.length === 1 ? files[0].name : files.length + " files";
      addChipInfo.textContent = pfx ? "PFX" : key ? "Certificate and private key" : "Certificate";
      if (pfx) return askPassword("PFX password", true);
      if (add.keyOldStyle) {
        askPassword("Key password", false);
        return say(addStatus, "plain", "This key is locked. Enter its password.");
      }
      await check();
    } catch (failure) {
      if (ticket !== addTicket) return;
      wipeAdd();
      say(addStatus, "bad", failure instanceof Plain ? failure.message : "The files could not be read. Choose them again.");
    } finally {
      // Only the PFX is kept as chosen; everything else lives on in add.
      for (const part of loaded) if (!add || part.bytes !== add.pfx) part.bytes.fill(0);
      for (const bytes of found) bytes.fill(0);
    }
  }

  // Several certificate files become one PEM bundle, leaf first.
  function bundle(engine, parts) {
    if (parts.length === 1) return parts[0].bytes.slice();
    const list = parts.flatMap((p) => p.list);
    const analysis = JSON.parse(engine.analyze(parts.map((p) => p.bytes)));
    if (!analysis.result || analysis.result.certificates.length !== list.length) throw new Plain("These certificates do not belong together. Add them one at a time.");
    const order = ui.chainOrder(list, analysis.result);
    const rest = list.map((_, i) => i).filter((i) => !order.includes(i));
    const where = [];
    parts.forEach((p, index) => p.list.forEach(() => where.push(index)));
    const pems = [...order, ...rest].map((i) => {
      const answer = engine.exportPublic(parts[where[i]].bytes, list[i].sha256, "pem");
      if (!answer || answer.ok !== true) throw new Error("export");
      return answer.result.bytes;
    });
    try { return ui.concat(pems); } finally { pems.forEach((b) => b.fill(0)); }
  }

  async function unlock() {
    if (!add) return;
    if (add.pfx && !add.certificate) {
      const ticket = addTicket;
      const password = encoder.encode(addPassword.value);
      addPassword.value = "";
      // An empty password opens a PFX saved without one.
      if (password.byteLength > 128) { password.fill(0); return say(addStatus, "bad", "That password is too long."); }
      const empty = password.byteLength === 0;
      say(addStatus, "plain", "Opening the PFX. This takes a few seconds…");
      let prepared = null;
      try {
        prepared = await globalThis.rootwellCertificatePFX.run(add.engine.module, add.pfx, password, new AbortController().signal);
        if (ticket !== addTicket) return;
        add.certificate = prepared.certificate.slice();
        add.key = prepared.private_key.slice();
        add.keySecret = prepared.key_password.slice();
        add.expected = prepared.fingerprint;
        addPasswordField.hidden = true;
        await check();
      } catch (failure) {
        if (ticket === addTicket) say(addStatus, "bad", ui.pfxProblem(failure && failure.code, empty));
      } finally {
        password.fill(0);
        if (prepared) for (const name of ["certificate", "private_key", "key_password"]) if (prepared[name] instanceof Uint8Array) prepared[name].fill(0);
      }
      return;
    }
    if (add.keyOldStyle) {
      // An old-style locked key is opened here; the server takes it opened.
      const password = encoder.encode(addPassword.value);
      addPassword.value = "";
      let answer = null;
      try {
        answer = add.engine.unlockKey(add.key, password);
      } finally {
        password.fill(0);
      }
      if (!answer || answer.ok !== true || !(answer.result.key instanceof Uint8Array)) {
        return say(addStatus, "bad", answer && answer.error === "wrong-password" ? wrongKeyPassword :
          answer && answer.error === "input-password-required" ? "This key is locked. Enter its password." : "Rootwell could not open this key.");
      }
      add.key.fill(0);
      add.key = answer.result.key;
      add.keyOldStyle = false;
      addPasswordField.hidden = true;
      return check();
    }
    add.keyPassword = addPassword.value;
    addPassword.value = "";
    await check();
  }

  function request() {
    const password = add.keySecret ? add.keySecret.slice() : encoder.encode(add.keyPassword || "");
    try {
      return { certificate: base64(add.certificate), private_key: base64(add.key || new Uint8Array(0)), key_password: base64(password),
        location: addPlace.value.trim(), expected_generation: generation };
    } finally {
      password.fill(0);
    }
  }

  async function check() {
    const ticket = addTicket;
    say(addStatus, "plain", "Checking…");
    addSave.disabled = true;
    try {
      const body = request();
      if (add.primary) body.primary_fingerprint = add.primary;
      const response = await call("/api/certificates/check", body, "Rootwell could not read these files.");
      const answer = await json(response);
      if (ticket !== addTicket) return;
      if (response.headers.get("X-Rootwell-Selection") === "required") return pick(answer.records || []);
      const record = answer.records && answer.records[0];
      if (!record || !fingerprintPattern.test(record.fingerprint) || (add.expected && record.fingerprint !== add.expected)) throw new Error("answer");
      add.record = record;
      // The key opened, or never needed a password.
      addPasswordField.hidden = true;
      preview(record);
      if (record.key_status === "mismatch") return say(addStatus, "bad", "This key does not belong to the certificate. Choose the right key, or add the certificate alone.");
      addPlaceField.hidden = false;
      addSave.disabled = false;
      say(addStatus);
    } catch (failure) {
      if (ticket !== addTicket) return;
      if (failure instanceof Plain && (failure.message === messages[422] || failure.message === wrongKeyPassword)) askPassword("Key password", false);
      say(addStatus, "bad", failure instanceof Plain ? failure.message : "Rootwell could not read these files.");
    }
  }

  function pick(candidates) {
    addPick.hidden = false;
    addChoices.replaceChildren(...candidates.filter((c) => fingerprintPattern.test(c.fingerprint)).slice(0, 16).map((candidate) => {
      const label = ui.el("label", "choice");
      const radio = ui.el("input");
      radio.type = "radio";
      radio.name = "add-primary";
      radio.value = candidate.fingerprint;
      radio.addEventListener("change", () => { add.primary = candidate.fingerprint; addPick.hidden = true; void check(); });
      label.appendChild(radio);
      label.appendChild(ui.el("strong", "", nameOf(candidate)));
      label.appendChild(ui.el("span", "", "Until " + ui.formatDate(candidate.not_after)));
      return label;
    }));
    say(addStatus, "plain", "These files hold more than one certificate. Choose the one to keep.");
  }

  function preview(record) {
    const card = ui.el("div", "file-chip");
    const mark = ui.el("span", "cert-mark");
    mark.appendChild(ui.icon("certificate"));
    card.appendChild(mark);
    const words = ui.el("div");
    words.appendChild(ui.el("strong", "", nameOf(record)));
    words.appendChild(ui.el("small", "", ui.commonName(record.issuer) + " · until " + ui.formatDate(record.not_after)));
    card.appendChild(words);
    card.appendChild(record.key_status === "matched" ? ui.el("span", "pill pill-good", "Key matches") :
      record.key_status === "mismatch" ? ui.el("span", "pill pill-bad", "Key does not match") : ui.pill(record.not_after));
    addPreview.replaceChildren(card);
  }

  async function save() {
    if (!add || !add.record) return;
    const ticket = addTicket;
    addSave.disabled = true;
    say(addStatus, "plain", "Saving…");
    try {
      const body = { ...request(), fingerprint: add.record.fingerprint, allow_mismatch: false };
      const saved = await json(await call("/api/certificates/save", body, "The certificate was not saved."));
      if (ticket !== addTicket) return;
      // The answer carries the list's new count: the next change uses it at
      // once, without waiting for the list to come back.
      if (Number.isSafeInteger(saved.generation) && saved.generation > generation) generation = saved.generation;
      const name = nameOf(add.record);
      closeAdd();
      notice("good", "Saved " + name + ".");
      await load();
    } catch (failure) {
      if (ticket === addTicket) {
        addSave.disabled = false;
        say(addStatus, "bad", failure instanceof Plain ? failure.message : "The certificate was not saved.");
      }
    }
  }

  ui.dropZone(addZone, addInput, chooseFiles);
  $("add-again").addEventListener("click", () => { resetAdd(); addInput.click(); });
  $("add-unlock").addEventListener("click", unlock);
  addPassword.addEventListener("keydown", (event) => { if (event.key === "Enter") { event.preventDefault(); void unlock(); } });
  addSave.addEventListener("click", save);
  for (const id of ["add-start", "empty-add"]) $(id).addEventListener("click", openAdd);
  for (const id of ["add-close", "add-cancel"]) $(id).addEventListener("click", closeAdd);
  addScrim.addEventListener("click", closeAdd);

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    if (!deleteDialog.hidden) closeDelete();
    else if (!addDialog.hidden) closeAdd();
    else if (!sheet.hidden) closeSheet();
  });
  // Leaving the page forgets files, keys and passwords.
  globalThis.addEventListener("pagehide", () => { resetAdd(); resetDownload(); resetKeyPanel(); });

  void load();
})();
