"use strict";
(function () {
  const byId = id => document.getElementById(id), encoder = new TextEncoder();
  const panel = byId("saved-key-panel"), form = byId("saved-key-form"), file = byId("saved-key-file");
  const inputPassword = byId("saved-key-input-password"), auth = byId("saved-key-auth");
  const check = byId("saved-key-check"), save = byId("saved-key-save"), status = byId("saved-key-status"), consent = byId("saved-key-consent");
  const readOnly = byId("certificate-pair-form").dataset.readOnly === "true";
  const fp = value => typeof value === "string" && /^(?:[A-Fa-f0-9]{2}:){31}[A-Fa-f0-9]{2}$/.test(value);
  class AttachmentError extends Error { constructor(message, refused) { super(message); this.refused = refused; } }
  let generation = 0, target = null, pending = null, serial = 0, controller = null, busy = false, savePosted = false;
  if (readOnly) for (const input of [file, inputPassword, auth, consent]) input.disabled = true;
  function controls() { check.disabled = save.disabled = busy || readOnly || document.hidden || !target || !file.files?.length; }
  function invalidate() { if (savePosted) byId("pair-status").textContent = "Save outcome is uncertain. Refresh before retrying."; savePosted = false; serial++; controller?.abort(); controller = null; busy = false; pending = null; consent.checked = false; byId("saved-key-warning").hidden = true; controls(); }
  function reset() { invalidate(); target = null; panel.hidden = true; file.value = ""; inputPassword.value = ""; auth.value = ""; byId("saved-key-name").textContent = ""; status.textContent = ""; controls(); }
  file.addEventListener("change", () => { invalidate(); inputPassword.value = ""; auth.value = ""; status.textContent = ""; });
  inputPassword.addEventListener("input", () => { invalidate(); auth.value = ""; status.textContent = "Check or Save with this key password."; });
  byId("saved-key-close").addEventListener("click", reset);
  async function responseBody(response) {
    if (!response.ok || response.headers.get("cache-control") !== "no-store" || !response.body) {
      const messages = {400:"Key or consent not accepted. Check the supported format and password.",401:"Sign in again or check your Rootwell password.",409:"The record changed or already has a key. Refresh; no existing key is replaced.",422:"Enter the key's current password, then check again.",429:"Too many password attempts. Wait one minute.",501:"This preview cannot save keys.",503:"Rootwell is busy or storage is unavailable. Refresh before retrying."};
      throw new AttachmentError(messages[response.status] || "Rootwell did not confirm the operation. Refresh before retrying.",[400,401,403,409,415,422,429,501].includes(response.status));
    }
    const reader = response.body.getReader(), parts = []; let size = 0, bytes;
    try {
      while (true) { const p = await reader.read(); if (p.done) break; size += p.value.byteLength; if (size > 256 * 1024) { p.value.fill(0); throw new Error(); } parts.push(p.value); }
      bytes = new Uint8Array(size); let offset = 0; for (const p of parts) { bytes.set(p,offset); offset += p.length; }
      return JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));
    } finally { bytes?.fill(0); for (const p of parts) p.fill(0); await reader.cancel().catch(() => {}); }
  }
  function base64(bytes) { let value = ""; for (let i = 0; i < bytes.length; i += 8192) value += String.fromCharCode(...bytes.subarray(i,i+8192)); return btoa(value); }
  async function run(action) {
    if (busy || readOnly || document.hidden || !target || target.generation !== generation) return;
    if (action === "save" && !pending) { const original = target; await run("check"); if (target === original && pending?.target === original && pending.keyStatus !== "mismatch") return run("save"); return; }
    if (action === "save" && pending.keyStatus === "mismatch" && !consent.checked) { status.textContent = "Confirm the separate-attachment warning first. This key is not a usable pair."; return; }
    if (action === "save" && (!auth.value || encoder.encode(auth.value).length > 256)) { status.textContent = "Enter your Rootwell password to save the key."; return; }
    const source = target, selectedFile = file.files?.[0], checked = pending;
    if (!selectedFile || file.files.length !== 1 || !Number.isSafeInteger(selectedFile.size) || selectedFile.size < 1 || selectedFile.size > 64*1024 || encoder.encode(inputPassword.value).length > 256) { invalidate(); auth.value = ""; status.textContent = "Choose one supported key up to 64 KiB."; return; }
    if (action === "check") invalidate();
    const ticket = ++serial; controller = new AbortController(); const own = controller; busy = true; controls();
    const current = () => serial === ticket && target === source && generation === source.generation && !document.hidden && !panel.hidden && file.files[0] === selectedFile && !own.signal.aborted;
    let posted = false, kb, pb;
    const timeout = setTimeout(() => { if (serial === ticket) { reset(); status.textContent = action === "save" && posted ? "Save outcome is uncertain. Refresh before retrying." : "Check timed out. Open Add private key again."; } },30000);
    try {
      kb = new Uint8Array(await selectedFile.arrayBuffer()); if (!current()) return;
      pb = encoder.encode(inputPassword.value); if (kb.length !== selectedFile.size) throw new Error();
      const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",kb)), b => b.toString(16).padStart(2,"0")).join(""); if (!current()) return;
      if (action === "save" && (!checked || checked.file !== selectedFile || checked.digest !== digest || checked.target !== source || Date.now() < checked.at || Date.now() - checked.at >= 120000)) throw new Error();
      const request = {fingerprint:source.fingerprint,expected_generation:source.generation,private_key:base64(kb),key_password:base64(pb)};
      if (action === "save") { request.password = auth.value; request.allow_mismatch = checked.keyStatus === "mismatch" && consent.checked; auth.value = ""; }
      status.textContent = action === "check" ? "Checking against your saved certificate… nothing is saved." : "Saving the key with your existing certificate…";
      posted = true;
      savePosted = action === "save";
      const response = await fetch("/api/certificates/key/" + action,{method:"POST",credentials:"same-origin",cache:"no-store",signal:own.signal,headers:{"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify(request)});
      const data = await responseBody(response); if (!current()) return;
      const r = data.records?.[0];
      if (data.verification !== "not-performed" || data.generation !== source.generation + (action === "save" ? 1 : 0) || data.records?.length !== 1 || !r || r.fingerprint !== source.fingerprint || r.has_private_key !== true || !["matched","mismatch"].includes(r.key_status) || (action === "save" && r.key_status !== checked.keyStatus)) throw new Error();
      if (action === "check") {
        pending = {target:source,file:selectedFile,digest,at:Date.now(),keyStatus:r.key_status};
        byId("saved-key-warning").hidden = r.key_status !== "mismatch";
        status.textContent = r.key_status === "matched" ? "Key matches. Confirm your Rootwell password and Save." : "Key does NOT match. It may be saved only as a separate attachment after your confirmation.";
      } else { savePosted = false; reset(); byId("pair-status").textContent = "Key saved with your existing certificate. Make a new full backup."; byId("refresh-button").click(); }
    } catch (error) {
      if (current()) { if (error instanceof AttachmentError && error.refused) savePosted = false; invalidate(); auth.value = ""; status.textContent = action === "save" && posted && !(error instanceof AttachmentError && error.refused) ? "Save was not confirmed and may have completed. Refresh before retrying." : error instanceof AttachmentError ? error.message : "Check refused. Selection changed or response was invalid; check again."; }
    } finally { kb?.fill(0); pb?.fill(0); clearTimeout(timeout); if (serial === ticket) { controller = null; busy = false; controls(); } }
  }
  check.addEventListener("click", () => run("check"));
  form.addEventListener("submit", event => { event.preventDefault(); return run("save"); });
  document.addEventListener("visibilitychange", () => { if (document.hidden) reset(); }); window.addEventListener("pagehide", reset);
  globalThis.rootwellSavedKey = Object.freeze({reset,
    snapshot(value) { if (!Number.isSafeInteger(value) || value < 1 || value !== generation) reset(); generation = Number.isSafeInteger(value) && value > 0 ? value : 0; },
    isEditing() { return target !== null || busy; },
    open(record, gen) { if (readOnly || document.hidden || gen !== generation || !fp(record.fingerprint) || record.has_private_key === true) return; reset(); target = {fingerprint:record.fingerprint,generation:gen}; byId("saved-key-name").textContent = record.subject || "Saved certificate"; panel.hidden = false; controls(); panel.scrollIntoView({behavior:"smooth",block:"start"}); }
  });
  controls();
})();
