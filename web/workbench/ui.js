"use strict";

// Small, shared drawing helpers for Rootwell's pages. They build elements with
// textContent only, so no file, certificate or server text is ever read as
// HTML. This script reads no file and makes no request.
(function () {
  const ns = "http://www.w3.org/2000/svg";
  const shapes = {
    certificate: [["soft-fill", "path", "M5 3.5h10l4 4v13H5z"], ["", "path", "M15 3.5v4h4M8.5 11h7M8.5 14.5h4.5"]],
    root: [["soft-fill", "path", "M12 3.5l7 3v5c0 4.4-3 8-7 9.5-4-1.5-7-5.1-7-9.5v-5z"], ["", "path", "M9 12l2.2 2.2L15.5 10"]],
    file: [["soft-fill", "path", "M6 3.5h8l4 4v13H6z"], ["", "path", "M14 3.5v4h4"]],
    key: [["soft-fill", "circle", "8,15.5,4"], ["", "path", "M11 12.5L19 4.5M16 7.5l2.2 2.2M13.8 9.7l1.8 1.8"]],
    lock: [["soft-fill", "rect", "5,10.5,14,10,2"], ["", "path", "M8 10.5V8a4 4 0 0 1 8 0v2.5"]],
    ok: [["soft-fill", "circle", "12,12,8.5"], ["", "path", "M8.3 12.4l2.6 2.6 4.8-5"]],
    bad: [["soft-fill", "circle", "12,12,8.5"], ["", "path", "M9 9l6 6M15 9l-6 6"]],
    alert: [["soft-fill", "circle", "12,12,8.5"], ["", "path", "M12 7.5v5.5M12 16.3v.2"]],
    download: [["", "path", "M12 4v11M7.5 10.5L12 15l4.5-4.5M5 20h14"]],
  };

  function icon(name, extra) {
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("class", "icon" + (extra ? " " + extra : ""));
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("aria-hidden", "true");
    for (const [cls, kind, value] of shapes[name] || []) {
      const shape = document.createElementNS(ns, kind);
      if (kind === "path") shape.setAttribute("d", value);
      if (kind === "circle") {
        const [cx, cy, r] = value.split(",");
        shape.setAttribute("cx", cx); shape.setAttribute("cy", cy); shape.setAttribute("r", r);
      }
      if (kind === "rect") {
        const [x, y, w, h, rx] = value.split(",");
        shape.setAttribute("x", x); shape.setAttribute("y", y); shape.setAttribute("width", w); shape.setAttribute("height", h); shape.setAttribute("rx", rx);
      }
      if (cls) shape.setAttribute("class", cls);
      svg.appendChild(shape);
    }
    return svg;
  }

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  const day = 86400000;

  // Whole days, counted up: 73.9 days to go is 74 left; ended an hour ago is
  // "Expired today".
  function lifetime(notAfter, now) {
    const end = Date.parse(notAfter);
    if (!Number.isFinite(end)) return { kind: "plain", text: "Unknown end date" };
    if (end <= now) {
      const ago = Math.floor((now - end) / day);
      return { kind: "bad", text: ago === 0 ? "Expired today" : ago === 1 ? "Expired yesterday" : "Expired " + ago + " days ago" };
    }
    const left = Math.ceil((end - now) / day);
    // Days while they matter; months and years for a long life.
    const text = left === 1 ? "1 day left" : left <= 120 ? left + " days left" :
      left < 730 ? Math.floor(left / 30.44) + " months left" : Math.floor(left / 365.25) + " years left";
    return { kind: left <= 30 ? "soon" : "good", text };
  }

  function pill(notAfter, now) {
    const state = lifetime(notAfter, now === undefined ? Date.now() : now);
    return el("span", "pill pill-" + state.kind, state.text);
  }

  // The lifetime bar: start, end, and where today falls.
  function lifetimeBar(notBefore, notAfter, now) {
    const start = Date.parse(notBefore), end = Date.parse(notAfter);
    const wrap = el("div", "lifetime");
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return wrap;
    const at = now === undefined ? Date.now() : now;
    const share = Math.max(0, Math.min(1, (at - start) / (end - start)));
    const bar = el("div", "lifetime-bar");
    const fill = el("div", "lifetime-fill " + lifetime(notAfter, at).kind);
    fill.style.width = (share * 100).toFixed(1) + "%";
    const today = el("div", "lifetime-today");
    today.style.left = "calc(" + (share * 100).toFixed(1) + "% - 1px)";
    bar.appendChild(fill);
    bar.appendChild(today);
    const dates = el("div", "lifetime-dates");
    dates.appendChild(el("span", "", formatDate(notBefore)));
    dates.appendChild(el("span", "", formatDate(notAfter)));
    wrap.appendChild(bar);
    wrap.appendChild(dates);
    return wrap;
  }

  function formatDate(value) {
    const when = new Date(value);
    if (!Number.isFinite(when.getTime())) return "";
    return when.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
  }

  // The common name of a distinguished name as Go prints it ("CN=a,O=b"),
  // or the whole name when there is none.
  function commonName(dn) {
    const match = /(?:^|,)CN=((?:\\.|[^,\\])+)/.exec(String(dn || ""));
    return match ? match[1].replace(/\\(.)/g, "$1") : String(dn || "");
  }

  function shortFingerprint(fingerprint) {
    const parts = String(fingerprint || "").split(":");
    return parts.length > 8 ? parts.slice(0, 4).join(":") + ":…:" + parts.slice(-2).join(":") : String(fingerprint || "");
  }

  // One browser download; the object URL lives 30 seconds, long enough for
  // every browser to start saving.
  function download(bytes, filename, type) {
    const url = URL.createObjectURL(new Blob([bytes], { type: type || "application/octet-stream" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.rel = "noopener";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 30000);
  }

  // A file name a person recognises: the certificate's own name, made safe.
  function friendlyName(name, fallback) {
    const base = String(name || "").replace(/^\*\./, "wildcard.").replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^[-.]+|[-.]+$/g, "").slice(0, 80);
    return base || fallback;
  }

  // A drop zone: click or drop, then onFiles(files).
  function dropZone(zone, input, onFiles) {
    input.addEventListener("change", function () { if (input.files && input.files.length) onFiles(Array.from(input.files)); input.value = ""; });
    zone.addEventListener("dragover", function (event) { event.preventDefault(); zone.classList.add("is-over"); });
    zone.addEventListener("dragleave", function () { zone.classList.remove("is-over"); });
    zone.addEventListener("drop", function (event) {
      event.preventDefault();
      zone.classList.remove("is-over");
      const files = event.dataTransfer && event.dataTransfer.files;
      if (files && files.length) onFiles(Array.from(files));
    });
  }

  Object.defineProperty(globalThis, "rootwellUI", {
    value: Object.freeze({ icon, el, lifetime, pill, lifetimeBar, formatDate, commonName, shortFingerprint, download, friendlyName, dropZone }),
    writable: false, configurable: false, enumerable: false,
  });
})();
