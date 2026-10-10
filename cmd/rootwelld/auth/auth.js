"use strict";
(() => {
  const mode = document.body.dataset.mode;
  const form = document.getElementById("auth-form");
  const status = document.getElementById("status");
  const password = document.getElementById("password");
  const next = document.getElementById("next");
  const confirm = document.getElementById("confirm");
  const headers = {"Content-Type":"application/json","X-Rootwell-Request":"1"};
  const signOut = document.getElementById("sign-out");
  const submit = form.querySelector("button");
  const fields = [password, next, confirm].filter(Boolean);
  let active = null;

  function clearFields() { for (const field of fields) field.value = ""; }
  function lock(value) {
    submit.disabled = value;
    if (signOut) signOut.disabled = value;
    for (const field of fields) field.disabled = value;
  }

  // One deadline covers both headers and body. Cancellation cannot undo a
  // server-side password change or sign-out, so failure never claims either.
  async function request(path, method, body, needsMode = false) {
    const controller = new AbortController();
    let reader;
    let stop;
    const stopped = new Promise((_, reject) => { stop = () => {
      controller.abort();
      if (reader) void reader.cancel().catch(() => {});
      reject(new Error("request unconfirmed"));
    }; });
    active = { stop };
    const timer = setTimeout(stop, 15000);
    try {
      const response = await Promise.race([fetch(path, {
        method, headers, credentials:"same-origin", cache:"no-store",
        signal:controller.signal, body:body === undefined ? undefined : JSON.stringify(body)
      }), stopped]);
      if (controller.signal.aborted) throw new Error("request unconfirmed");
      if (!response.ok || !needsMode) {
        if (response.body) void response.body.cancel().catch(() => {});
        return {status:response.status, ok:response.ok};
      }
      if (response.headers.get("content-type")?.split(";")[0].trim().toLowerCase() !== "application/json" || !response.body) {
        if (response.body) void response.body.cancel().catch(() => {});
        throw new Error("unexpected response");
      }
      reader = response.body.getReader();
      const chunks = [];
      let size = 0;
      while (true) {
        const part = await Promise.race([reader.read(), stopped]);
        if (controller.signal.aborted) throw new Error("request unconfirmed");
        if (part.done) break;
        if (part.value.byteLength === 0) throw new Error("empty response chunk");
        size += part.value.byteLength;
        if (size > 8192) throw new Error("response limit");
        chunks.push(part.value);
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      const text = new TextDecoder("utf-8", {fatal:true}).decode(bytes);
      // The server's entire login contract is one field with two fixed values.
      // Refuse aliases, duplicate fields, extra data and remote error text.
      const match = /^[ \t\r\n]*\{[ \t\r\n]*"mode"[ \t\r\n]*:[ \t\r\n]*"(setup|ready)"[ \t\r\n]*\}[ \t\r\n]*$/.exec(text);
      if (!match) throw new Error("unexpected sign-in state");
      return {status:response.status, ok:true, mode:match[1]};
    } finally {
      clearTimeout(timer);
      if (reader) { void reader.cancel().catch(() => {}); reader.releaseLock(); }
      active = null;
    }
  }

  function leave() { clearFields(); active?.stop(); }
  document.addEventListener("visibilitychange", () => { if (document.hidden) leave(); });
  window.addEventListener("pagehide", leave);

  if (signOut) signOut.addEventListener("click", async () => {
    if (active || document.hidden) return;
    clearFields();
    lock(true);
    try {
      const response = await request("/api/session", "DELETE");
      if (document.hidden || !response.ok || response.status !== 204) throw new Error("sign-out failed");
      window.location.assign("/login");
    } catch (_) {
      status.textContent = "Sign-out could not be confirmed. Try again before leaving this device.";
    } finally { clearFields(); lock(false); }
  });
  form.addEventListener("submit", async event => {
    event.preventDefault();
    if (active || document.hidden) return;
    status.textContent = "";
    if (next && next.value !== confirm.value) { status.textContent = "New passwords do not match."; return; }
    const value = password.value;
    const replacement = next ? next.value : undefined;
    clearFields();
    lock(true);
    try {
      const response = await request(mode === "login" ? "/api/session" : "/api/password", "POST",
        replacement === undefined ? {password:value} : {password:value,next:replacement}, mode === "login");
      if (document.hidden) throw new Error("request unconfirmed");
      if (!response.ok) {
        status.textContent = response.status === 429 ? "Too many attempts. Wait one minute." :
          response.status === 401 ? "The current password was not accepted." :
          response.status === 400 ? "Choose a different password with at least 15 characters and at most 1024 bytes." :
          "The request could not be completed. Try again or ask the installation operator.";
        return;
      }
      password.value = "";
      if (next) {
        if (response.status !== 204) throw new Error("unexpected response");
        next.value = ""; confirm.value = ""; window.location.assign("/login"); return;
      }
      if (response.status !== 200) throw new Error("unexpected response");
      if (response.mode === "setup") window.location.assign("/setup");
      else if (response.mode === "ready") window.location.assign("/");
    } catch (_) { status.textContent = mode === "login" ?
      "Sign-in could not be confirmed. Refresh this page to check your session before trying again." :
      "Password change could not be confirmed. Refresh this page and sign in with the password that is active; do not assume the old password still works."; }
    finally { clearFields(); lock(false); }
  });
})();
