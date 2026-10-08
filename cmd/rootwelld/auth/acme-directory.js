(() => {
  "use strict";
  const consent = document.getElementById("acme-connect-consent");
  const button = document.getElementById("acme-connect");
  const status = document.getElementById("acme-connect-status");
  let active = null, generation = 0;
  const reset = () => {
    generation += 1;
    active?.abort(); active = null;
    consent.checked = false; consent.disabled = false; button.disabled = true; status.textContent = "";
  };
  consent.addEventListener("change", () => {
    generation += 1; active?.abort(); active = null;
    consent.disabled = false;
    button.disabled = !consent.checked; status.textContent = "";
  });
  document.getElementById("acme-clear").addEventListener("click", reset);
  document.getElementById("acme-provider").addEventListener("change", reset);
  document.addEventListener("visibilitychange", () => { if (document.hidden) reset(); });
  window.addEventListener("pagehide", reset);
  button.addEventListener("click", async () => {
    if (document.hidden || !consent.checked || active || document.getElementById("acme-provider").value !== "letsencrypt-staging") return;
    const current = ++generation, controller = new AbortController(); active = controller;
    consent.checked = false; consent.disabled = true; button.disabled = true;
    status.textContent = "Checking the staging connection… No account is being created.";
    const timer = setTimeout(() => { if (current === generation) { generation += 1; controller.abort(); active = null; consent.disabled = false; status.textContent = "Connection check timed out. Confirm again to retry."; } }, 10000);
    try {
      const response = await fetch("/api/acme/directory", {
        method: "POST", credentials: "same-origin", cache: "no-store", signal: controller.signal,
        headers: { "Content-Type": "application/json", "X-Rootwell-Request": "1" },
        body: JSON.stringify({ provider: "letsencrypt-staging", confirm: true })
      });
      if (current !== generation || controller.signal.aborted || document.hidden) return;
      if (response.status === 429) { status.textContent = "Wait 30 seconds, then confirm again to check the provider."; return; }
      if (response.status === 401 || response.status === 403) { status.textContent = "Sign in again before checking the provider."; return; }
      if (response.status === 503) { status.textContent = "Provider connections require Linux or Linux Docker. Your native preview stays offline; local certificate tools still work."; return; }
      if (!response.ok || response.headers.get("cache-control") !== "no-store" || !response.body) throw new Error("refused");
      const reader = response.body.getReader(), decoder = new TextDecoder("utf-8", { fatal: true });
      let text = "", size = 0;
      try {
        while (true) {
          const { value, done } = await reader.read(); if (done) break;
          size += value.byteLength;
          if (size > 4096 || current !== generation || controller.signal.aborted || document.hidden) throw new Error("refused");
          text += decoder.decode(value, { stream: true });
        }
        text += decoder.decode();
      } finally { await reader.cancel(); reader.releaseLock(); }
      const result = JSON.parse(text);
      if (!result || Array.isArray(result) || Object.keys(result).length !== 9 ||
          result.schema_version !== "rootwell.acme.directory.v1" || result.provider !== "letsencrypt-staging" ||
          result.directory !== "https://acme-staging-v02.api.letsencrypt.org/directory" || result.state !== "directory-checked" ||
          result.network_used !== true || result.domains_sent !== false || result.saved !== false || result.account_created !== false || result.can_issue !== false) throw new Error("refused");
      if (current !== generation || controller.signal.aborted || document.hidden) return;
      status.textContent = "Staging directory reached securely. No domains or keys sent. No account or certificate created. This does not prove issuance will succeed.";
    } catch {
      if (current === generation && !document.hidden) status.textContent = "Connection could not be safely checked. No account or certificate created. Confirm again to retry.";
    } finally {
      clearTimeout(timer);
      if (current === generation) { active = null; consent.disabled = false; button.disabled = true; }
    }
  });
  reset();
})();
