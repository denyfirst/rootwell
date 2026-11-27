"use strict";

// Website check: one connection from this Rootwell to an HTTPS website or
// internal server, drawn as a verdict, the chain, and what to fix. A check
// saves nothing; a site the person chooses to watch is checked once a day. The page builds every element with textContent; no server or
// certificate text is ever parsed as HTML.
(function () {
  const form = document.getElementById("site-form");
  const input = document.getElementById("site");
  const button = document.getElementById("site-check");
  const status = document.getElementById("site-status");
  const result = document.getElementById("site-result");
  let active = null;

  const svg = (paths) => {
    const ns = "http://www.w3.org/2000/svg";
    const el = document.createElementNS(ns, "svg");
    el.setAttribute("class", "icon");
    el.setAttribute("viewBox", "0 0 24 24");
    el.setAttribute("aria-hidden", "true");
    for (const [cls, d] of paths) {
      const p = document.createElementNS(ns, d.startsWith("c:") ? "circle" : "path");
      if (d.startsWith("c:")) {
        const [cx, cy, r] = d.slice(2).split(",");
        p.setAttribute("cx", cx); p.setAttribute("cy", cy); p.setAttribute("r", r);
      } else {
        p.setAttribute("d", d);
      }
      if (cls) p.setAttribute("class", cls);
      el.appendChild(p);
    }
    return el;
  };
  const glyph = {
    ok: [["soft-fill", "c:12,12,8.5"], ["", "M8.3 12.4l2.6 2.6 4.8-5"]],
    bad: [["soft-fill", "c:12,12,8.5"], ["", "M9 9l6 6M15 9l-6 6"]],
    alert: [["soft-fill", "c:12,12,8.5"], ["", "M12 7.5v5.5M12 16.3v.2"]],
    certificate: [["soft-fill", "M5 3.5h10l4 4v13H5z"], ["", "M15 3.5v4h4M8.5 11h7M8.5 14.5h4.5"]],
    root: [["soft-fill", "M12 3.5l7 3v5c0 4.4-3 8-7 9.5-4-1.5-7-5.1-7-9.5v-5z"], ["", "M9 12l2.2 2.2L15.5 10"]],
  };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }

  // Whole days, counted up: a certificate with 73.9 days to go has 74 left,
  // and one that ended an hour ago expired today.
  function lifetimePill(notAfter, now) {
    const end = Date.parse(notAfter);
    if (!Number.isFinite(end)) return null;
    const day = 86400000;
    if (end <= now) {
      const ago = Math.floor((now - end) / day);
      return el("span", "pill pill-bad", ago === 0 ? "Expired today" : ago === 1 ? "Expired yesterday" : `Expired ${ago} days ago`);
    }
    const left = Math.ceil((end - now) / day);
    // The words every page uses: days while they matter, then months and years.
    const text = left === 1 ? "1 day left" : left <= 120 ? `${left} days left` :
      left < 730 ? `${Math.floor(left / 30.44)} months left` : `${Math.floor(left / 365.25)} years left`;
    return el("span", left <= 30 ? "pill pill-soon" : "pill pill-good", text);
  }

  // What a person typed, as the server expects it: a name or address, an
  // optional port and an optional https:// in front. A name in another
  // script (bakı.az) goes in the xn-- form DNS uses. The server checks again.
  function target(value) {
    const text = value.trim();
    if (!text || text.length > 280 || /\s/.test(text)) return null;
    if (!/[^\x00-\x7f]/.test(text)) return text;
    try {
      const url = new URL(text.includes("://") ? text : "https://" + text);
      if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/") return null;
      return url.host;
    } catch {
      return null;
    }
  }

  function siteName(report) {
    const host = report.hostname.includes(":") ? `[${report.hostname}]` : report.hostname;
    return report.port && report.port !== 443 ? `${host}:${report.port}` : report.hostname;
  }

  // Each finding names the certificates it is about; the worst one marks them.
  function marks(report) {
    const worst = new Map();
    for (const finding of report.findings) {
      if (finding.level !== "failed" && finding.level !== "attention") continue;
      for (const fp of finding.certificates || []) {
        if (worst.get(fp) !== "broken") worst.set(fp, finding.level === "failed" ? "broken" : "warn");
      }
    }
    return worst;
  }

  function roleLabel(certificate, report, last) {
    if (certificate.role === "leaf") return "Website certificate";
    if (certificate.role === "trust-anchor" || certificate.role === "root") {
      if (certificate.role === "trust-anchor" && last && report.trust_source === "saved") return "Your saved root";
      return "Root";
    }
    return "Intermediate";
  }

  function node(certificate, state, facts, now) {
    const link = el("div", "link " + state);
    const mark = el("span", "link-mark");
    mark.appendChild(svg(certificate.role === "root" || certificate.role === "trust-anchor" || certificate.use === "root" ? glyph.root : glyph.certificate));
    link.appendChild(mark);
    const words = el("span");
    words.appendChild(el("strong", "", certificate.subject || certificate.fingerprint));
    words.appendChild(el("small", "", facts.join(" · ")));
    link.appendChild(words);
    const pill = certificate.not_after ? lifetimePill(certificate.not_after, now) : null;
    if (pill) link.appendChild(pill);
    return link;
  }

  function chainCard(report, now) {
    const card = el("section", "card");
    const head = el("div", "card-head");
    head.appendChild(el("h3", "", "The chain visitors get"));
    card.appendChild(head);
    const body = el("div", "card-body stack");
    const marked = marks(report);
    const chain = el("div", "chain");
    const path = report.path.length ? report.path : report.presented.slice(0, 1);
    path.forEach((certificate, i) => {
      const last = i === path.length - 1;
      const facts = [roleLabel(certificate, report, last)];
      if (!certificate.sent && certificate.role === "intermediate") facts.push("Not sent by the server");
      if (!certificate.sent && certificate.role === "trust-anchor" && report.trust_source === "public") facts.push("Built into devices");
      const state = !certificate.in_date ? "broken" : marked.get(certificate.fingerprint) || "ok";
      if (state !== "ok") facts.push("Needs a fix");
      chain.appendChild(node(certificate, state, facts, now));
    });
    // The issuer the server should send but does not.
    const missing = report.findings.find((f) => f.code === "missing-issuer");
    if (missing && path.length) {
      const absent = { subject: path[path.length - 1].issuer, role: "intermediate" };
      chain.appendChild(node(absent, "missing", ["Missing", "The server does not send it"], now));
    }
    body.appendChild(chain);
    // Everything else the server sends, and why.
    const extras = report.presented.filter((c) => c.use && c.use !== "path");
    if (extras.length) {
      body.appendChild(el("p", "label", "Also sent by the server"));
      const more = el("div", "chain extras");
      for (const certificate of extras) {
        const facts = certificate.use === "older-path" ? ["Intermediate", "For older devices"] :
          certificate.use === "root" ? ["Root", "Devices already have it"] : ["Not part of this chain"];
        let state = certificate.use === "unrelated" ? "warn" : "extra";
        if (!certificate.in_date || marked.get(certificate.fingerprint) === "broken") state = "broken";
        else if (marked.get(certificate.fingerprint) === "warn") state = "warn";
        if (state === "warn" || state === "broken") facts.push("Needs a fix");
        more.appendChild(node(certificate, state, facts, now));
      }
      body.appendChild(more);
    }
    card.appendChild(body);
    return card;
  }

  // The finding the verdict already explains shows only its fix here.
  function findingItem(finding, explained) {
    const item = el("div", "stack");
    item.appendChild(el("strong", "", finding.title));
    if (finding.detail && !explained) item.appendChild(el("p", "soft", finding.detail));
    if (finding.action) item.appendChild(el("p", "", finding.action));
    return item;
  }

  function fixCard(report) {
    const card = el("section", "card");
    const head = el("div", "card-head");
    const problems = report.findings.filter((f) => f.level === "failed" || f.level === "attention");
    const notes = report.findings.filter((f) => f.level === "note");
    head.appendChild(el("h3", "", problems.length ? "How to fix it" : "Nothing to fix"));
    card.appendChild(head);
    const body = el("div", "card-body stack");
    if (!problems.length) {
      body.appendChild(el("p", "soft", "The certificate covers this name, the chain is complete and every date is valid."));
    }
    const lead = problems.find((f) => f.level === "failed") || problems[0];
    for (const finding of problems) body.appendChild(findingItem(finding, finding === lead));
    if (notes.length) {
      body.appendChild(el("p", "label", "Good to know"));
      for (const finding of notes) body.appendChild(findingItem(finding, false));
    }
    const when = new Date(report.observed_at);
    const where = report.address ? (report.address.includes(":") ? `[${report.address}]` : report.address) + ":" + (report.port || 443) : "";
    const meta = [Number.isFinite(when.getTime()) ? "Checked " + when.toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "numeric", minute: "2-digit" }) : "", report.tls_version, where].filter(Boolean);
    body.appendChild(el("p", "meta", meta.join(" · ")));
    body.appendChild(el("p", "meta", "Rootwell does not check whether the certificate authority has revoked a certificate."));
    card.appendChild(body);
    return card;
  }

  function verdict(report) {
    const failed = report.findings.find((f) => f.level === "failed");
    const attention = report.findings.find((f) => f.level === "attention");
    const first = failed || attention || { title: "Worth a look", detail: "" };
    const kind = report.state === "verified" ? "good" : report.state === "failed" ? "bad" : "soon";
    const box = el("div", "verdict " + kind);
    const mark = svg(kind === "good" ? glyph.ok : kind === "bad" ? glyph.bad : glyph.alert);
    mark.setAttribute("class", "icon icon-xl");
    box.appendChild(mark);
    const words = el("div");
    words.appendChild(el("h2", "", kind === "good" ? "Everything is in order" : first.title));
    const good = report.trust_source === "saved" && report.saved_root ?
      `${siteName(report)} sends a complete, valid certificate, trusted through your root “${report.saved_root}”.` :
      `${siteName(report)} sends a complete, valid certificate.`;
    words.appendChild(el("p", "", kind === "good" ? good : first.detail));
    box.appendChild(words);
    return box;
  }


  // ── Watched websites ───────────────────────────────────────────────────
  // Rootwell checks these once a day and writes when one serves another
  // certificate or has a problem. Watching needs a signed-in session;
  // stopping silences a watch, so it needs a code from the phone.

  const watchedCard = document.getElementById("watched");
  const watchedList = document.getElementById("watched-list");
  const watchedCount = document.getElementById("watched-count");
  let watchedSites = [];

  async function watchCall(path, body, asked) {
    const response = await fetch(path, {
      method: body ? "POST" : "GET", credentials: "same-origin", cache: "no-store", redirect: "error",
      headers: body ? { "Content-Type": "application/json", "X-Rootwell-Request": "1" } : { "X-Rootwell-Request": "1" },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (response.status === 428 && !asked && typeof rootwellFresh === "function") {
      if (await rootwellFresh()) return watchCall(path, body, true);
      throw new Error("Nothing changed. That needs a code from your phone.");
    }
    const text = await response.text();
    if (!response.ok) {
      let said = "";
      try { said = JSON.parse(text).error || ""; } catch { said = ""; }
      throw new Error(typeof said === "string" && said && said.length < 300 ? said : response.status === 401 ? "Your session has ended. Sign in again." : "That did not work. Try again.");
    }
    return text ? JSON.parse(text) : null;
  }

  const watchState = {
    verified: ["pill pill-good", "Good"], attention: ["pill pill-soon", "Needs a look"],
    failed: ["pill pill-bad", "Problem"], unreachable: ["pill pill-bad", "No answer"],
  };

  function dateOf(value) {
    const when = new Date(value);
    return Number.isFinite(when.getTime()) ? when.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" }) : "";
  }

  function drawWatched() {
    watchedCard.hidden = !watchedSites.length;
    watchedCount.textContent = watchedSites.length === 1 ? "1 website" : watchedSites.length + " websites";
    watchedList.replaceChildren(...watchedSites.map((site) => {
      const row = el("div", "file-chip");
      const words = el("div");
      const name = el("button", "link-button", site.target);
      name.type = "button";
      name.addEventListener("click", () => { input.value = site.target; form.requestSubmit ? form.requestSubmit() : check({ preventDefault() {} }); });
      words.appendChild(name);
      const facts = [];
      if (site.checked_at) facts.push("Checked " + dateOf(site.checked_at));
      else facts.push("Checked within the hour");
      if (site.not_after) facts.push("its certificate lasts until " + dateOf(site.not_after));
      words.appendChild(el("small", "", facts.join(" · ")));
      if (site.problem) words.appendChild(el("small", "error-text", site.problem));
      row.appendChild(words);
      const [pillClass, pillText] = watchState[site.state] || ["pill pill-plain", "Not checked yet"];
      row.appendChild(el("span", pillClass, pillText));
      const stop = el("button", "btn btn-ghost btn-sm", "Stop watching");
      stop.type = "button";
      stop.addEventListener("click", async () => {
        stop.disabled = true;
        try {
          await watchCall("/api/watch/remove", { target: site.target });
          await loadWatched();
        } catch (failure) {
          status.textContent = failure.message;
          status.className = "error-text";
        } finally {
          stop.disabled = false;
        }
      });
      row.appendChild(stop);
      return row;
    }));
  }

  async function loadWatched() {
    try {
      const answer = await watchCall("/api/watch");
      watchedSites = answer && Array.isArray(answer.sites) ? answer.sites.filter((s) => s && typeof s.target === "string") : [];
    } catch {
      watchedSites = [];
    }
    drawWatched();
  }

  // Under a result: watch this site, or say it is watched. The site is named
  // as the server wrote it, as the watched list names it.
  function watchRow(site) {
    const row = el("div", "inline");
    const draw = () => {
      if (watchedSites.some((s) => s.target === site)) {
        return row.replaceChildren(el("span", "pill pill-plain", "Watched"), el("span", "meta", "Rootwell checks it once a day."));
      }
      const watch = el("button", "btn btn-secondary", "Watch this site");
      watch.type = "button";
      watch.addEventListener("click", async () => {
        watch.disabled = true;
        try {
          await watchCall("/api/watch/add", { target: site });
          await loadWatched();
          draw();
        } catch (failure) {
          watch.disabled = false;
          status.textContent = failure.message;
          status.className = "error-text";
        }
      });
      row.replaceChildren(watch, el("span", "meta", "Rootwell checks it once a day and writes to you when it changes certificate or has a problem."));
    };
    draw();
    return row;
  }

  function show(report) {
    const now = Date.now();
    const split = el("div", "split");
    split.appendChild(chainCard(report, now));
    split.appendChild(fixCard(report));
    result.replaceChildren(verdict(report), watchRow(siteName(report)), split);
    result.hidden = false;
    result.classList.add("result-enter");
  }

  async function check(event) {
    event.preventDefault();
    const site = target(input.value);
    // A new check clears the last result, so an old answer never stands
    // under a new name or a new failure.
    result.replaceChildren();
    result.hidden = true;
    if (!site) {
      status.textContent = "Enter a website, for example example.com or 10.0.0.5:8443.";
      status.className = "error-text";
      return;
    }
    active?.abort();
    const controller = new AbortController();
    active = controller;
    const timer = setTimeout(() => controller.abort(), 20000);
    button.disabled = true;
    status.textContent = "Checking " + site + "…";
    status.className = "meta";
    try {
      const response = await fetch("/api/website-check", {
        method: "POST", credentials: "same-origin", cache: "no-store", redirect: "error", signal: controller.signal,
        headers: { "Content-Type": "application/json", "X-Rootwell-Request": "1" },
        body: JSON.stringify({ target: site, confirm: true }),
      });
      const text = await response.text();
      if (controller !== active) return;
      if (!response.ok) {
        status.textContent = response.status === 401 ? "Your session has ended. Sign in again." :
          text.length > 0 && text.length < 300 ? text.trim() : "The website could not be checked.";
        status.className = "error-text";
        return;
      }
      const report = JSON.parse(text);
      if (!report || !Array.isArray(report.findings) || !Array.isArray(report.presented) || !Array.isArray(report.path)) {
        throw new Error("unexpected answer");
      }
      status.textContent = "";
      show(report);
    } catch {
      if (controller === active) {
        status.textContent = "The check did not finish. Try again.";
        status.className = "error-text";
      }
    } finally {
      clearTimeout(timer);
      if (controller === active) {
        active = null;
        button.disabled = false;
      }
    }
  }

  form.addEventListener("submit", check);
  void loadWatched();
  // Certificates links here as /website-check#name.
  const named = decodeURIComponent(location.hash.slice(1));
  if (target(named)) input.value = named;
  document.addEventListener("visibilitychange", () => { if (document.hidden) active?.abort(); });
})();
