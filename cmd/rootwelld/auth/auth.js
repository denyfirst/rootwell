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
  if (signOut) signOut.addEventListener("click", async () => {
    signOut.disabled = true;
    try {
      const response = await fetch("/api/session", {method:"DELETE",headers,credentials:"same-origin",cache:"no-store"});
      if (!response.ok) throw new Error("sign-out failed");
      window.location.assign("/login");
    } catch (_) {
      status.textContent = "Sign-out could not be confirmed. Try again before leaving this device.";
      signOut.disabled = false;
    }
  });
  form.addEventListener("submit", async event => {
    event.preventDefault();
    status.textContent = "";
    if (next && next.value !== confirm.value) { status.textContent = "New passwords do not match."; return; }
    const value = password.value;
    const replacement = next ? next.value : undefined;
    form.querySelector("button").disabled = true;
    try {
      const response = await fetch(mode === "login" ? "/api/session" : "/api/password", {
        method:"POST",headers,credentials:"same-origin",cache:"no-store",
        body:JSON.stringify(replacement === undefined ? {password:value} : {password:value,next:replacement})
      });
      if (!response.ok) {
        status.textContent = response.status === 429 ? "Too many attempts. Wait one minute." :
          response.status === 401 ? "The current password was not accepted." :
          response.status === 400 ? "Choose a different password with at least 15 characters and at most 1024 bytes." :
          "The request could not be completed. Try again or ask the installation operator.";
        return;
      }
      password.value = "";
      if (next) { next.value = ""; confirm.value = ""; window.location.assign("/login"); return; }
      const result = await response.json();
      if (result.mode === "setup") window.location.assign("/setup");
      else if (result.mode === "ready") window.location.assign("/");
      else status.textContent = "The installation returned an unexpected sign-in state.";
    } catch (_) { status.textContent = "The local installation could not be reached."; }
    finally { form.querySelector("button").disabled = false; }
  });
})();
