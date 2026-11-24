"use strict";

// Showing or downloading a key, deleting a certificate that has one, and
// changing how the account signs in need a code from the phone entered in the
// last ten minutes. When Rootwell asks for one (it answers 428), a page calls
// rootwellFresh(): it asks for the code in a dialog and sends it. It resolves
// true once Rootwell accepted a code, and false when the person cancels.
(function () {
  let pending = null;
  let parts = null;

  function build() {
    const scrim = document.createElement("div");
    scrim.className = "scrim";
    const dialog = document.createElement("div");
    dialog.className = "dialog";
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("aria-modal", "true");
    dialog.setAttribute("aria-labelledby", "fresh-title");
    const form = document.createElement("form");
    form.method = "post";
    form.action = "/api/fresh";
    form.noValidate = true;
    const head = document.createElement("div");
    head.className = "dialog-head";
    const title = document.createElement("h2");
    title.id = "fresh-title";
    title.textContent = "Enter a code from your phone";
    head.appendChild(title);
    const body = document.createElement("div");
    body.className = "dialog-body stack";
    const hint = document.createElement("p");
    hint.className = "soft";
    hint.textContent = "Open the authenticator app and enter the six-digit code for Rootwell. A recovery code works too.";
    const field = document.createElement("div");
    field.className = "field";
    const label = document.createElement("label");
    label.htmlFor = "fresh-code";
    label.textContent = "Code";
    const input = document.createElement("input");
    input.className = "input mono";
    input.id = "fresh-code";
    input.autocomplete = "one-time-code";
    input.maxLength = 64;
    input.spellcheck = false;
    field.append(label, input);
    const error = document.createElement("p");
    error.className = "error-text";
    error.setAttribute("role", "alert");
    body.append(hint, field, error);
    const foot = document.createElement("div");
    foot.className = "dialog-foot";
    const cancel = document.createElement("button");
    cancel.className = "btn btn-secondary";
    cancel.type = "button";
    cancel.textContent = "Cancel";
    const go = document.createElement("button");
    go.className = "btn";
    go.type = "submit";
    go.textContent = "Continue";
    foot.append(cancel, go);
    form.append(head, body, foot);
    dialog.appendChild(form);
    scrim.hidden = true;
    dialog.hidden = true;
    document.body.append(scrim, dialog);
    return { scrim, dialog, form, input, error, cancel, go };
  }

  function close(result) {
    parts.input.value = "";
    parts.error.textContent = "";
    parts.dialog.hidden = true;
    parts.scrim.hidden = true;
    const done = pending;
    pending = null;
    if (done) done(result);
  }

  async function send(event) {
    event.preventDefault();
    const code = parts.input.value.trim();
    if (!code) {
      parts.error.textContent = "Enter the code your phone shows.";
      return;
    }
    parts.go.disabled = true;
    try {
      const response = await fetch("/api/fresh", {
        method: "POST", credentials: "same-origin", cache: "no-store", redirect: "error",
        headers: { "Content-Type": "application/json", "X-Rootwell-Request": "1" },
        body: JSON.stringify({ code }),
      });
      const text = response.ok ? "" : await response.text().catch(() => "");
      if (response.status === 204) return close(true);
      if (response.status === 409 || (response.status === 401 && /signed out|sign in/i.test(text))) {
        window.location.assign("/login");
        return;
      }
      parts.input.value = "";
      parts.error.textContent = response.status === 429 ? "Too many wrong tries. Wait a little, then try again." :
        response.status === 401 ? "That code does not match." : "Rootwell could not check the code. Try again.";
      parts.input.focus();
    } catch {
      parts.error.textContent = "Rootwell could not check the code. Try again.";
    } finally {
      parts.go.disabled = false;
    }
  }

  globalThis.rootwellFresh = function () {
    if (pending) return Promise.resolve(false);
    if (!parts) {
      parts = build();
      parts.form.addEventListener("submit", send);
      parts.cancel.addEventListener("click", () => close(false));
      parts.dialog.addEventListener("keydown", (event) => { if (event.key === "Escape") close(false); });
      window.addEventListener("pagehide", () => { if (pending) close(false); });
    }
    return new Promise((resolve) => {
      pending = resolve;
      parts.error.textContent = "";
      parts.input.value = "";
      parts.scrim.hidden = false;
      parts.dialog.hidden = false;
      parts.input.focus();
    });
  };
})();
