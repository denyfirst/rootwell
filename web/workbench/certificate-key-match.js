"use strict";
(function () {
  const byId = id => document.getElementById(id);
  const cert = byId("match-certificate"), key = byId("match-key"), password = byId("match-password");
  const button = byId("match-check"), status = byId("match-status"), results = byId("match-results");
  let engine = null, serial = 0, controller = null, busy = false;
  const encoder = new TextEncoder(), fp = /^(?:[A-Fa-f0-9]{2}:){31}[A-Fa-f0-9]{2}$/;
  function controls() { button.disabled = !engine || busy || document.hidden || !cert.files?.length || !key.files?.length; }
  function reset(clearFiles = false) {
    serial++; controller?.abort(); controller = null; busy = false;
    results.replaceChildren(); status.textContent = "";
    if (clearFiles) { cert.value = ""; key.value = ""; password.value = ""; }
    controls();
  }
  for (const input of [cert, key]) input.addEventListener("change", () => { reset(); password.value = ""; });
  password.addEventListener("input", () => reset());
  rootwellWorkbenchReady.then(ready => { engine = ready.module; controls(); }, () => { status.textContent = "Local engine unavailable."; });
  button.addEventListener("click", async () => {
    if (button.disabled || busy || document.hidden) return;
    reset(); const ticket = ++serial, c = cert.files[0], k = key.files[0];
    if (cert.files.length !== 1 || key.files.length !== 1 || !c.size || c.size > 768 * 1024 || !k.size || k.size > 64 * 1024 || encoder.encode(password.value).length > 256) {
      password.value = ""; status.textContent = "Choose one certificate/bundle up to 768 KiB and one key up to 64 KiB."; return;
    }
    busy = true; controller = new AbortController(); const own = controller;
    const current = () => serial === ticket && !document.hidden && !byId("inspect-panel").hidden && cert.files[0] === c && key.files[0] === k && !own.signal.aborted;
    const deadline = setTimeout(() => { if (serial === ticket) { reset(true); status.textContent = "Check timed out. Select the files again."; } }, 30000);
    controls(); let cb, kb, pb;
    try {
      pb = encoder.encode(password.value); password.value = "";
      cb = new Uint8Array(await c.arrayBuffer()); if (!current()) return;
      kb = new Uint8Array(await k.arrayBuffer()); if (!current()) return;
      if (cb.length !== c.size || kb.length !== k.size) throw new Error();
      status.textContent = "Comparing locally… nothing is saved.";
      const answer = await rootwellCSRWorker.run(engine, "certificate-key-match", kb, cb, pb, "", own.signal);
      if (!current()) return;
      if (typeof answer !== "string" || answer.length > 32768) throw new Error();
      const data = JSON.parse(answer);
      if (data.schema_version !== "rootwell.browser.key-match.v1" || data.ok !== true || data.error !== null) {
        status.textContent = data.error === "input-password-required" ? "Enter the private key's current password and check again." : "Could not read these files. Check the key password and supported format; this is not a mismatch result.";
        return;
      }
      if (!Array.isArray(data.records) || !data.records.length || data.records.length > 16 || data.records.some(r => !fp.test(r.fingerprint) || typeof r.subject !== "string" || r.subject.length > 4096 || !["matched", "mismatch"].includes(r.key_status))) throw new Error();
      const seen = new Set();
      for (const r of data.records) { if (seen.has(r.fingerprint)) throw new Error(); seen.add(r.fingerprint); }
      for (const r of data.records) {
        const item = document.createElement("li");
        item.textContent = (r.key_status === "matched" ? "Key matches · " : "Key does not match · ") + (r.subject || "Certificate") + " · " + r.fingerprint;
        results.appendChild(item);
      }
      status.textContent = "Comparison complete. Match is not certificate trust; use Verify for that.";
    } catch { if (current()) { results.replaceChildren(); status.textContent = "Check failed. No result was accepted; select supported files and check again."; } }
    finally { cb?.fill(0); kb?.fill(0); pb?.fill(0); clearTimeout(deadline); if (serial === ticket) { busy = false; controller = null; controls(); } }
  });
  for (const tab of document.querySelectorAll("[data-tool]")) tab.addEventListener("click", () => reset(true));
  byId("key-match-tools").addEventListener("toggle", () => { if (!byId("key-match-tools").open) reset(true); });
  document.addEventListener("visibilitychange", () => { if (document.hidden) reset(true); });
  window.addEventListener("pagehide", () => reset(true));
  controls();
})();
