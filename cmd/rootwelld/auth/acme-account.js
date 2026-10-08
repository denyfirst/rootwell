(() => {
  "use strict";
  const el = id => document.getElementById(id);
  const form = el("acme-account-form"), refresh = el("acme-account-refresh"), button = el("acme-account-prepare");
  const password = el("acme-account-password"), consent = el("acme-account-consent"), status = el("acme-account-status");
  const details = el("acme-account-details"), identity = el("acme-account-identity");
  let snapshot = null, active = null, generation = 0;
  const enable = () => { button.disabled = !!active || snapshot?.state !== "not-prepared" || !consent.checked || !password.value || document.hidden; };
  const reset = () => {
    generation += 1; active?.abort(); active = null; snapshot = null;
    password.value = ""; consent.checked = false; consent.disabled = false; refresh.disabled = false;
    details.hidden = true; identity.textContent = ""; form.hidden = true; status.textContent = "Status not checked. Check again before preparing a key."; enable();
  };
  const render = data => {
    snapshot = data; details.hidden = !data.saved; form.hidden = data.saved;
    identity.textContent = data.saved ? "Public key SHA-256: " + data.fingerprint + " · Prepared: " + data.prepared_at : "";
    status.textContent = data.saved ? "Test account key saved encrypted. Make a new complete backup. Not registered with the provider; no certificate can be requested yet." : "No test account key saved. You can prepare one below; it stays on your Rootwell.";
  };
  const read = async (response, current, controller) => {
    if (!response.ok || response.headers.get("cache-control") !== "no-store" || !response.headers.get("content-type")?.startsWith("application/json") || !response.body) throw new Error();
    const reader = response.body.getReader(), decoder = new TextDecoder("utf-8", { fatal:true });
    let text = "", size = 0;
    try {
      while (true) {
        const {value, done} = await reader.read(); if (done) break;
        size += value.byteLength;
        if (size > 4096 || current !== generation || document.hidden || controller.signal.aborted) throw new Error();
        text += decoder.decode(value, {stream:true});
      }
      text += decoder.decode();
    } finally { await reader.cancel(); reader.releaseLock(); }
    const data = JSON.parse(text), fingerprint = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/;
    if (!data || Array.isArray(data) || Object.keys(data).length !== 11 || data.schema_version !== "rootwell.acme.account-key.v1" ||
        data.provider !== "letsencrypt-staging" || !Number.isSafeInteger(data.generation) || data.generation < 1 || data.generation > 1000000 ||
        data.network_used !== false || data.account_created !== false || data.terms_accepted !== false || data.can_issue !== false ||
        !(data.state === "not-prepared" && data.saved === false && data.fingerprint === "" && data.prepared_at === "" ||
          data.state === "key-prepared" && data.saved === true && data.generation >= 2 && fingerprint.test(data.fingerprint) &&
          typeof data.prepared_at === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(data.prepared_at) &&
          Number.isFinite(Date.parse(data.prepared_at)) && new Date(data.prepared_at).toISOString() === data.prepared_at.replace("Z", ".000Z"))) throw new Error();
    return data;
  };
  const run = async prepare => {
    if (active || document.hidden || el("acme-provider").value !== "letsencrypt-staging") return;
    if (prepare && (snapshot?.state !== "not-prepared" || !consent.checked || !password.value)) return;
    const expected = snapshot?.generation;
    const input = prepare ? {provider:"letsencrypt-staging", expected_generation:expected, password:password.value, confirm:true} : {provider:"letsencrypt-staging"};
    const current = ++generation, controller = new AbortController(); active = controller;
    snapshot = null; password.value = ""; consent.checked = false; consent.disabled = true; refresh.disabled = true; button.disabled = true;
    details.hidden = true; identity.textContent = ""; form.hidden = true;
    const uncertain = "Status could not be confirmed. Check saved key status before retrying; a preparation may already have been saved. No key will be replaced.";
    status.textContent = prepare ? "Preparing an encrypted local key… No provider connection." : "Reading local saved key status…";
    const timer = setTimeout(() => { if (current === generation) { reset(); status.textContent = uncertain; } }, 10000);
    try {
      const request = {method:"POST", credentials:"same-origin", cache:"no-store", signal:controller.signal,
        headers:{"Content-Type":"application/json", "X-Rootwell-Request":"1"}, body:JSON.stringify(input)};
      input.password = "";
      const response = await fetch(prepare ? "/api/acme/account/prepare" : "/api/acme/account/status", request);
      request.body = "";
      if (current !== generation || document.hidden || controller.signal.aborted) return;
      if (response.status === 401 || response.status === 403) { status.textContent = "Password or session not accepted. Sign in if needed, then check saved key status."; return; }
      if (response.status === 429) { status.textContent = "Too many password attempts. Wait one minute, then check status again."; return; }
      if (response.status === 409) { status.textContent = "Store changed, is not initialized, or a key already exists. Check status; no existing key is replaced. Initialize full backup/recovery first if needed."; return; }
      if (response.status === 503) { status.textContent = "Storage unavailable or save outcome uncertain. Account-key storage requires Linux or Linux Docker. Check status before retrying."; return; }
      const data = await read(response, current, controller);
      if (prepare && (response.status !== 201 || !data.saved || data.generation !== expected+1) || !prepare && response.status !== 200) throw new Error();
      if (current !== generation || document.hidden || controller.signal.aborted) return;
      render(data);
    } catch { if (current === generation && !document.hidden) status.textContent = uncertain;
    } finally {
      input.password = ""; clearTimeout(timer);
      if (current === generation) { active = null; consent.disabled = false; refresh.disabled = false; password.value = ""; enable(); }
    }
  };
  refresh.addEventListener("click", () => run(false));
  form.addEventListener("submit", event => { event.preventDefault(); return run(true); });
  password.addEventListener("input", () => { if (active) reset(); enable(); });
  consent.addEventListener("change", () => { if (active) reset(); enable(); });
  el("acme-provider").addEventListener("change", reset); el("acme-clear").addEventListener("click", reset);
  document.addEventListener("visibilitychange", () => { if (document.hidden) reset(); });
  window.addEventListener("pagehide", reset);
  reset();
})();
