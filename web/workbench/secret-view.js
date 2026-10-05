"use strict";

(function () {
  const views = new Set();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const pem = /^-----BEGIN PRIVATE KEY-----\n[A-Za-z0-9+/=\n]+-----END PRIVATE KEY-----\n$/;

  function create(panel, content, hideButton, onBoundary, onHide) {
    if (!panel || !content || !hideButton || typeof onBoundary !== "function" || typeof onHide !== "function") throw new Error("private view unavailable");
    let timer;
    function hide() {
      const visible = !panel.hidden;
      clearTimeout(timer);
      content.textContent = "";
      panel.hidden = true;
      if (visible) onHide();
    }
    function boundary() { hide(); onBoundary(); }
    function show(bytes) {
      for (const item of views) { if (item.view === view) hide(); else item.boundary(); }
      if (document.hidden || !(bytes instanceof Uint8Array) || bytes.length < 64 || bytes.length > 96 << 10) throw new Error("private view refused");
      const text = decoder.decode(bytes);
      if (!pem.test(text)) throw new Error("private view refused");
      content.textContent = text;
      panel.hidden = false;
      timer = setTimeout(hide, 30000);
    }
    const view = Object.freeze({ show, hide });
    views.add({ view, boundary });
    hideButton.addEventListener("click", hide);
    for (const id of ["inspect-tab", "convert-tab", "verify-tab", "request-tab", "convert-open-inspect"]) {
      const button = document.getElementById(id);
      if (button) button.addEventListener("click", boundary);
    }
    document.addEventListener("visibilitychange", () => { if (document.hidden) boundary(); });
    globalThis.addEventListener("blur", boundary);
    globalThis.addEventListener("pagehide", boundary);
    globalThis.addEventListener("hashchange", boundary);
    hide();
    return view;
  }
  Object.defineProperty(globalThis, "rootwellSecretView", {
    configurable: false, enumerable: false, writable: false, value: Object.freeze({ create })
  });
})();
