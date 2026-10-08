"use strict";

(function () {
  const byId = id => document.getElementById(id);
  const form = byId("certificate-pair-form"), cert = byId("pair-certificate"), key = byId("pair-key");
  const keyPassword = byId("pair-key-password"), note = byId("pair-note"), check = byId("pair-check"), save = byId("pair-save");
  const status = byId("pair-status"), preview = byId("pair-preview");
  const primary = byId("pair-primary"), acknowledgement = byId("pair-mismatch");
  const download = byId("certificate-download"), downloadForm = byId("certificate-download-form"), kind = byId("download-kind");
  const password = byId("download-password"), outputPassword = byId("download-key-password"), confirm = byId("download-key-confirm");
  const downloadStatus = byId("download-status"), downloadGo = byId("download-go");
  const encoder = new TextEncoder();
  // Parser, file and network errors can contain uploaded data or local paths.
  // Only fixed messages authored here may reach the UI.
  class LibraryError extends Error {
    constructor(message, refused = false) { super(message); this.refused = refused; }
  }
  let generation = 0, serial = 0, pending = null, selected = null, controller = null, busy = false;
  const readOnly = form.dataset.readOnly === "true";
  if (readOnly) for (const input of [cert, key, keyPassword, note, primary, acknowledgement]) input.disabled = true;
  const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
  const fingerprint = value => typeof value === "string" && /^(?:[A-Fa-f0-9]{2}:){31}[A-Fa-f0-9]{2}$/.test(value);

  function controls() {
    check.disabled = busy || document.hidden || !generation || readOnly;
    save.disabled = busy || document.hidden || !generation || !cert.files?.length || readOnly;
    downloadGo.disabled = busy || document.hidden || !selected || selected.generation !== generation || readOnly;
  }
  function invalidate() {
    globalThis.rootwellSavedKey?.reset();
    serial++;
    controller?.abort(); controller = null; busy = false;
    pending = null; selected = null; preview.hidden = true; download.hidden = true;
    password.value = ""; outputPassword.value = ""; confirm.value = "";
    byId("pair-name").textContent = ""; byId("pair-expiry").textContent = ""; byId("pair-match").textContent = "";
    acknowledgement.checked = false; byId("pair-mismatch-box").hidden = true;
    controls();
  }
  function boundary() {
    invalidate(); keyPassword.value = ""; cert.value = ""; key.value = ""; note.value = "";
    primary.replaceChildren(); primary.value = ""; byId("pair-choice-box").hidden = true;
    status.textContent = ""; downloadStatus.textContent = "";
  }
  async function body(response, max) {
    if (!response.ok || response.headers.get("cache-control") !== "no-store" || !response.body) {
      const messages = { 401: "Sign in again or check your Rootwell password.", 409: "The list or selection changed. Refresh, then check again.",
        422: "This private key is password-protected. Enter its current password below, then check again.",
        429: "Too many password attempts. Wait one minute.", 501: "Saving keys requires the Linux Rootwell daemon; this is a preview.",
        400: "Files or passwords were not accepted. Check the matching key and supported format.", 503: "Rootwell is busy or storage is unavailable. Refresh before retrying." };
      const message = response.status === 409 && response.headers.get("X-Rootwell-Refusal") === "duplicate-certificate" ?
        "This certificate is already saved. No duplicate was added." : messages[response.status];
      throw new LibraryError(message || "Rootwell did not confirm this operation. Refresh before retrying.", [400, 401, 403, 409, 415, 422, 429, 501].includes(response.status));
    }
    const reader = response.body.getReader(), parts = [];
    let size = 0;
    try {
      while (true) {
        const part = await reader.read(); if (part.done) break;
        size += part.value.byteLength;
        if (size > max) { part.value.fill(0); throw new LibraryError("Response exceeded its limit."); }
        parts.push(part.value);
      }
      const result = new Uint8Array(size); let offset = 0;
      for (const part of parts) { result.set(part, offset); offset += part.length; }
      return result;
    } finally { for (const part of parts) part.fill(0); await reader.cancel().catch(() => {}); }
  }
  function base64(bytes) {
    let value = "";
    for (let offset = 0; offset < bytes.length; offset += 8192) value += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
    return btoa(value);
  }
  async function selection(current) {
    const files = Array.from(cert.files || []), c = files[0], k = key.files?.[0];
    if (!files.length || files.length > 8 || files.some(f => !Number.isSafeInteger(f.size) || f.size < 1) || files.reduce((n,f) => n + f.size,0) > 768 * 1024 || key.files?.length > 1 || (k && (!Number.isSafeInteger(k.size) || k.size === 0 || k.size > 64 * 1024)) || encoder.encode(keyPassword.value).length > 256) {
      throw new LibraryError("Select one bundle or 1–8 related public files (up to 768 KiB), and an optional private key (up to 64 KiB).");
    }
    let cb, kb, pb;
    try {
      if (files.length === 1) cb = new Uint8Array(await c.arrayBuffer());
      else {
        const entries = await rootwellInventoryImport.preview(files,current);
        if (entries.length > 16) throw new LibraryError("Use up to 16 certificates for one saved record.");
        cb = await rootwellInventoryImport.prepare(files,entries.map(r => r.sha256),current);
      }
      if (!current()) throw new LibraryError("Selection changed.");
      kb = k ? new Uint8Array(await k.arrayBuffer()) : new Uint8Array();
      pb = encoder.encode(keyPassword.value);
      if (!current() || !cb.length || cb.length > 768 * 1024 || (files.length === 1 && cb.length !== c.size) || kb.length !== (k?.size || 0) || (!k && pb.length) || files.length !== cert.files.length || files.some((file,i) => cert.files[i] !== file)) throw new LibraryError("Selection changed or a key password has no selected key.");
      const digest = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", cb))) + ":" +
        hex(new Uint8Array(await crypto.subtle.digest("SHA-256", kb)));
      if (!current()) throw new LibraryError("Selection changed.");
      return { certificate: base64(cb), private_key: base64(kb), key_password: base64(pb), digest, c, k, files };
    } finally { cb?.fill(0); kb?.fill(0); pb?.fill(0); }
  }
  async function run(action) {
    if (busy || readOnly || document.hidden || !generation) return;
    if (action === "save" && !pending) {
      await run("check");
      if (pending && pending.keyStatus !== "mismatch") return run("save");
      return;
    }
    if (action === "save" && pending.keyStatus === "mismatch" && !acknowledgement.checked) {
      status.textContent = "The key does not match. Confirm the separate-attachment warning before saving."; return;
    }
    const checked = pending;
    if (action === "check") invalidate();
    const ticket = ++serial, gen = generation;
    controller = new AbortController(); const ownController = controller;
    busy = true; controls();
    const current = () => serial === ticket && !document.hidden && generation === gen && !ownController.signal.aborted;
    let posted = false;
    const timeout = setTimeout(() => { if (serial === ticket) { invalidate(); status.textContent = posted && action === "save" ? "Save outcome is uncertain. Refresh before retrying." : "Check timed out. Check the selection again."; } }, 30000);
    try {
      const input = await selection(current);
      if (!current()) return;
      if (action === "save" && (!checked || checked.digest !== input.digest || checked.c !== input.c || checked.k !== input.k || checked.files.length !== input.files.length || checked.files.some((f,i) => f !== input.files[i]) || checked.generation !== gen || Date.now() - checked.at >= 120000 || Date.now() < checked.at)) {
        throw new LibraryError("Selection or checked result changed. Check the files again.");
      }
      const request = { certificate: input.certificate, private_key: input.private_key, key_password: input.key_password,
        location: note.value.trim(), expected_generation: gen };
      if (action === "save") { request.fingerprint = checked.fingerprint; request.allow_mismatch = checked.keyStatus === "mismatch" && acknowledgement.checked; }
      else if (primary.value) request.primary_fingerprint = primary.value;
      status.textContent = action === "check" ? "Checking on your own Rootwell… nothing is saved yet." : "Saving certificate and optional key together…";
      posted = true;
      const response = await fetch("/api/certificates/" + action, { method: "POST", credentials: "same-origin", cache: "no-store", signal: ownController.signal,
        headers: { "Content-Type": "application/json", "X-Rootwell-Request": "1" }, body: JSON.stringify(request) });
      const bytes = await body(response, 4 * 1024 * 1024);
      let result;
      try { result = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } finally { bytes.fill(0); }
      if (!current()) return;
      if (action === "check" && response.headers.get("X-Rootwell-Selection") === "required") {
        if (result.verification !== "not-performed" || result.generation !== gen || !Array.isArray(result.records) || result.records.length < 2 || result.records.length > 16 || result.records.some(r => !fingerprint(r.fingerprint) || typeof r.subject !== "string" || r.subject.length > 4096)) throw new LibraryError("Certificate choices were not recognized.");
        primary.replaceChildren(); const placeholder = document.createElement("option"); placeholder.value = ""; placeholder.textContent = "Choose a certificate"; primary.appendChild(placeholder);
        const seen = new Set();
        for (const r of result.records) { if (seen.has(r.fingerprint)) throw new LibraryError("Duplicate certificate choices refused."); seen.add(r.fingerprint); const option = document.createElement("option"); option.value = r.fingerprint; option.textContent = (r.subject || "Certificate") + " · " + r.not_after?.slice(0, 10) + " · " + r.fingerprint; primary.appendChild(option); }
        primary.value = ""; byId("pair-choice-box").hidden = false;
        status.textContent = "Choose the primary certificate, then Check or Save again. Nothing was saved."; return;
      }
      const record = result?.records?.[0];
      if (result.verification !== "not-performed" || result.records?.length !== 1 || !record || !fingerprint(record.fingerprint) ||
          typeof record.subject !== "string" || typeof record.not_after !== "string" || !Number.isFinite(Date.parse(record.not_after)) ||
          typeof record.has_private_key !== "boolean" || record.has_private_key !== Boolean(input.k) ||
          !["matched", "mismatch", "not-added"].includes(record.key_status) || (record.key_status === "not-added") !== !input.k ||
          result.generation !== (action === "check" ? gen : gen + 1) || (action === "save" && record.fingerprint !== checked.fingerprint)) {
        throw new LibraryError("Response did not match the selected certificate. Refresh before retrying.");
      }
      if (action === "check") {
        pending = { fingerprint: record.fingerprint, digest: input.digest, c: input.c, k: input.k, files: input.files, generation: gen, at: Date.now(), keyStatus: record.key_status };
        byId("pair-name").textContent = record.subject || "Certificate";
        byId("pair-expiry").textContent = "Expires " + record.not_after.slice(0, 10) + (Number.isSafeInteger(record.expiry?.days_left) ? " · " + record.expiry.days_left + " days remaining (server clock)" : "");
        byId("pair-match").textContent = record.key_status === "matched" ? "Private key matches this certificate." : record.key_status === "mismatch" ? "Private key does NOT match. It can only be saved as a separate attachment, not a usable pair." : "Certificate only. You can save without a private key.";
        byId("pair-mismatch-box").hidden = record.key_status !== "mismatch";
        preview.hidden = false; status.textContent = "Checked. Add an optional service note, or skip it and save.";
      } else {
        boundary(); status.textContent = "Saved. Make a new full backup; backup is manual.";
        byId("refresh-button").click();
      }
    } catch (error) {
      if (current()) {
        invalidate();
        status.textContent = posted && action === "save" && !(error instanceof LibraryError && error.refused) ?
          "Save was not confirmed and may have completed. Refresh before retrying." :
          error instanceof LibraryError ? error.message : "Check refused; nothing was saved. Check the files and try again.";
        if (key.files?.length) byId("pair-password-options").open = true;
      }
    } finally { clearTimeout(timeout); if (serial === ticket) { busy = false; controller = null; controls(); } }
  }
  function sourceChanged() { invalidate(); keyPassword.value = ""; primary.value = ""; primary.replaceChildren(); byId("pair-choice-box").hidden = true; status.textContent = ""; }
  cert.addEventListener("change", sourceChanged);
  key.addEventListener("change", sourceChanged);
  primary.addEventListener("change", () => { invalidate(); status.textContent = "Selection changed. Check or Save to revalidate."; });
  keyPassword.addEventListener("input", () => { invalidate(); status.textContent = "Check the files with this password before saving."; });
  check.addEventListener("click", () => run("check"));
  form.addEventListener("submit", event => { event.preventDefault(); return run("save"); });
  function privateOptions() {
    password.value = ""; outputPassword.value = ""; confirm.value = "";
    byId("download-private-options").hidden = !["pair", "key"].includes(kind.value);
  }
  kind.addEventListener("change", privateOptions);
  byId("download-close").addEventListener("click", boundary);
  downloadForm.addEventListener("submit", async event => {
    event.preventDefault();
    if (busy || readOnly || document.hidden || !selected || selected.generation !== generation) return;
    const pair = kind.value === "pair", keyOnly = kind.value === "key", secret = pair || keyOnly, source = selected;
    if (pair && source.keyStatus !== "matched") { downloadStatus.textContent = "This key does not match. Download it separately; a usable pair cannot be created."; return; }
    if (secret && (!source.hasPrivateKey || !password.value || !/^[!-~]{20,128}$/.test(outputPassword.value) || outputPassword.value !== confirm.value || outputPassword.value === password.value)) {
      downloadStatus.textContent = "Confirm your Rootwell password and a separate matching key password of 20–128 non-space ASCII characters."; return;
    }
    const ticket = ++serial; controller = new AbortController(); const ownController = controller;
    busy = true; controls();
    const current = () => serial === ticket && !document.hidden && selected === source && generation === source.generation && !ownController.signal.aborted;
    const timeout = setTimeout(() => { if (serial === ticket) { boundary(); downloadStatus.textContent = "Download timed out. Open it again to retry."; } }, 30000);
    let bytes = null, url = null;
    try {
      const request = { fingerprint: source.fingerprint, expected_generation: source.generation, pair };
      if (keyOnly) request.key_only = true;
      if (kind.value === "bundle") request.bundle = true;
      if (secret) { request.password = password.value; const p = encoder.encode(outputPassword.value); try { request.output_password = base64(p); } finally { p.fill(0); } }
      password.value = ""; outputPassword.value = ""; confirm.value = "";
      const response = await fetch("/api/certificates/download", { method: "POST", credentials: "same-origin", cache: "no-store", signal: ownController.signal,
        headers: { "Content-Type": "application/json", "X-Rootwell-Request": "1" }, body: JSON.stringify(request) });
      const name = response.headers.get("content-disposition")?.match(/^attachment; filename="(rootwell-certificate-[a-f0-9]{32}\.(?:pem|zip))"$/)?.[1];
      bytes = await body(response, 1200 * 1024);
      if (!current()) return;
      if (!name || !name.endsWith(pair ? ".zip" : ".pem") || response.headers.get("content-type") !== (pair ? "application/zip" : "application/x-pem-file") || bytes.length === 0) throw new LibraryError("Download response was not recognized.");
      url = URL.createObjectURL(new Blob([bytes], { type: pair ? "application/zip" : "application/x-pem-file" }));
      const link = document.createElement("a"); link.href = url; link.download = name; document.body.appendChild(link); link.click(); link.remove();
      downloadStatus.textContent = pair ? "Encrypted key and certificate downloaded. The ZIP itself is not encrypted." : keyOnly ? "Encrypted private key downloaded separately. This does not assert certificate/key match." : "Public certificate material downloaded. Included roots are not automatically trusted.";
    } catch (error) { if (current()) downloadStatus.textContent = error instanceof LibraryError ? error.message : "Download refused. Open it again to retry."; }
    finally { bytes?.fill(0); if (url) URL.revokeObjectURL(url); clearTimeout(timeout); if (serial === ticket) { busy = false; controller = null; controls(); } }
  });
  document.addEventListener("visibilitychange", () => { if (document.hidden) boundary(); });
  window.addEventListener("pagehide", boundary);
  globalThis.rootwellCertificateLibrary = Object.freeze({
    snapshot(value) { globalThis.rootwellSavedKey?.snapshot(value); if (!Number.isSafeInteger(value) || value < 1) { generation = 0; boundary(); return; } if (generation !== value) invalidate(); generation = value; controls(); },
    isEditing() { return busy || pending !== null || !download.hidden || Boolean(cert.files?.length) || Boolean(key.files?.length) || globalThis.rootwellSavedKey?.isEditing() === true; },
    openAttach(record, gen) {
      if (busy || document.hidden || readOnly || gen !== generation || !fingerprint(record.fingerprint) || record.has_private_key === true) return;
      boundary(); globalThis.rootwellSavedKey?.open(record, gen);
    },
    openDownload(record, gen) {
      if (busy || document.hidden || readOnly || gen !== generation || !fingerprint(record.fingerprint)) return;
      invalidate(); selected = { fingerprint: record.fingerprint, generation: gen, hasPrivateKey: record.has_private_key === true, keyStatus: record.key_status };
      kind.value = "certificate"; kind.options[1].disabled = !selected.hasPrivateKey || selected.keyStatus !== "matched"; kind.options[2].disabled = !selected.hasPrivateKey; kind.options[3].disabled = !record.bundle_count; privateOptions();
      byId("download-name").textContent = record.subject || "Certificate"; downloadStatus.textContent = ""; download.hidden = false; controls();
      download.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  });
  controls();
})();
