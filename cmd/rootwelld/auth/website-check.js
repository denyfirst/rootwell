"use strict";

// Website check: one connection from this Rootwell to a public HTTPS site,
// drawn as a verdict, the chain the server sends, and what to fix. Nothing is
// saved. The page builds every element with textContent; no server or
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

  // The host name a person typed, as the server expects it: a DNS name or an
  // https:// origin, nothing else. The server checks it again.
  function target(value) {
    const text = value.trim();
    if (!text || text.length > 260 || /\s/.test(text)) return null;
    return text;
  }

  function roleLabel(certificate) {
    if (certificate.role === "leaf") return "Website certificate";
    if (certificate.role === "root" || certificate.role === "trust-anchor") return "Trusted root";
    return "Intermediate";
  }

  function chainCard(report, now) {
    const card = el("section", "card");
    const head = el("div", "card-head");
    head.appendChild(el("h3", "", "What the server sends"));
    card.appendChild(head);
    const body = el("div", "card-body");
    const chain = el("div", "chain");
    const nodes = report.trusted && report.path.length ? report.path : report.presented;
    for (const certificate of nodes) {
      const broken = !certificate.in_date;
      const link = el("div", "link " + (broken ? "broken" : "ok"));
      const mark = el("span", "link-mark");
      mark.appendChild(svg(certificate.role === "root" || certificate.role === "trust-anchor" ? glyph.root : glyph.certificate));
      link.appendChild(mark);
      const words = el("span");
      words.appendChild(el("strong", "", certificate.subject || certificate.fingerprint));
      const facts = [roleLabel(certificate)];
      if (!certificate.sent && certificate.role !== "leaf") facts.push(certificate.role === "intermediate" ? "Not sent by the server" : "Built into every device");
      words.appendChild(el("small", "", facts.join(" · ")));
      link.appendChild(words);
      const pill = lifetimePill(certificate.not_after, now);
      if (pill) link.appendChild(pill);
      chain.appendChild(link);
    }
    body.appendChild(chain);
    card.appendChild(body);
    return card;
  }

  function fixCard(report) {
    const card = el("section", "card");
    const head = el("div", "card-head");
    head.appendChild(el("h3", "", report.findings.length ? "How to fix it" : "Nothing to fix"));
    card.appendChild(head);
    const body = el("div", "card-body stack");
    if (!report.findings.length) {
      body.appendChild(el("p", "soft", "The certificate covers this name, the chain is complete and every date is valid."));
    }
    for (const finding of report.findings) {
      const item = el("div", "stack");
      item.appendChild(el("strong", "", finding.title));
      if (finding.action) item.appendChild(el("p", "soft", finding.action));
      body.appendChild(item);
    }
    const when = new Date(report.observed_at);
    const meta = [Number.isFinite(when.getTime()) ? "Checked " + when.toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "numeric", minute: "2-digit" }) : "", report.tls_version, report.address].filter(Boolean);
    body.appendChild(el("p", "meta", meta.join(" · ")));
    card.appendChild(body);
    return card;
  }

  function verdict(report) {
    const failed = report.findings.find((f) => f.level === "failed");
    const first = failed || report.findings[0] || { title: "Worth a look", detail: "" };
    const kind = report.state === "verified" ? "good" : report.state === "failed" ? "bad" : "soon";
    const box = el("div", "verdict " + kind);
    const mark = svg(kind === "good" ? glyph.ok : kind === "bad" ? glyph.bad : glyph.alert);
    mark.setAttribute("class", "icon icon-xl");
    box.appendChild(mark);
    const words = el("div");
    words.appendChild(el("h2", "", kind === "good" ? "Everything is in order" : first.title));
    words.appendChild(el("p", "", kind === "good" ? `${report.hostname} sends a complete, valid certificate.` : first.detail));
    box.appendChild(words);
    return box;
  }

  function show(report) {
    const now = Date.now();
    const split = el("div", "split");
    split.appendChild(chainCard(report, now));
    split.appendChild(fixCard(report));
    result.replaceChildren(verdict(report), split);
    result.hidden = false;
    result.classList.add("result-enter");
  }

  async function check(event) {
    event.preventDefault();
    const site = target(input.value);
    if (!site) {
      status.textContent = "Enter a website, for example example.com.";
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
  // Certificates links here as /website-check#name.
  const named = decodeURIComponent(location.hash.slice(1));
  if (target(named)) input.value = named;
  document.addEventListener("visibilitychange", () => { if (document.hidden) active?.abort(); });
})();
