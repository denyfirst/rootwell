(() => {
  "use strict";
  const $ = id => document.getElementById(id);
  const form = $("website-form"), target = $("website-target"), consent = $("website-consent"), submit = $("website-submit"), status = $("website-status"), result = $("website-result");
  let active = null, epoch = 0;
  const buttons = [$("example-valid"), $("example-missing"), $("example-wrong")];
  const element = (tag, text, cls) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; };
  const text = (v, max) => typeof v === "string" && v.length <= max;
  const date = v => text(v, 40) && Number.isFinite(Date.parse(v));
  function certificate(c) {
    return c && /^[a-f0-9]{64}$/.test(c.fingerprint) && text(c.subject, 480) && text(c.issuer, 480) && date(c.not_before) && date(c.not_after) && ["leaf", "intermediate", "trust-anchor", "root"].includes(c.role) && typeof c.sent === "boolean" && Number.isInteger(c.position) && c.position >= 0 && c.position <= 10 && c.sent === (c.position > 0) && typeof c.in_date === "boolean";
  }
  function valid(r) {
    return r && r.schema_version === "rootwell.website-chain.v1" && text(r.hostname,253) && r.hostname.length > 0 && text(r.address,64) && ["TLS 1.2","TLS 1.3"].includes(r.tls_version) && date(r.observed_at) && ["verified","attention","failed"].includes(r.state) && typeof r.trusted === "boolean" && typeof r.hostname_matches === "boolean" && Array.isArray(r.path) && r.path.length >= 1 && r.path.length <= 11 && r.path.every(certificate) && r.path[0].role === "leaf" && Array.isArray(r.presented) && r.presented.length >= 1 && r.presented.length <= 10 && r.presented.every(certificate) && Array.isArray(r.findings) && r.findings.length <= 40 && r.findings.every(f => f && text(f.code,64) && ["failed","attention"].includes(f.level) && text(f.title,200) && text(f.detail,800) && text(f.action,800)) && text(r.trust_source,120) && r.revocation === "not-checked" &&
      (r.state === "failed" ? r.findings.some(f => f.level === "failed") : r.trusted && r.hostname_matches && !r.findings.some(f => f.level === "failed")) &&
      (r.state !== "verified" || r.findings.length === 0) && (r.trusted ? r.path.every(c => c.in_date) && (r.path[r.path.length-1].role === "trust-anchor" || r.path.length === 1) : !r.path.some(c => c.role === "trust-anchor"));
  }
  const displayDate = value => new Date(value).toLocaleDateString(undefined, {year:"numeric",month:"short",day:"numeric"});
  function render(r, example) {
    result.replaceChildren();
    if (example) result.append(element("p", "EXAMPLE · generated certificates · no website contacted", "chain-sample"));
    const banner = element("div", undefined, "chain-banner " + r.state);
    banner.append(element("span", r.state === "failed" ? "!" : r.state === "attention" ? "△" : "✓", "state-icon"));
    const heading = element("div");
    heading.append(element("h2", r.state === "failed" ? "This certificate needs a fix." : r.state === "attention" ? "The chain needs attention." : "The certificate chain checks out."));
    heading.append(element("p", r.hostname + " · " + (r.trusted ? "Path reaches a trusted root" : "Trusted path not established") + " · " + (r.hostname_matches ? "Domain matches" : "Domain does not match")));
    banner.append(heading); result.append(banner);
    const layout = element("div", undefined, "chain-layout"), left = element("div", undefined, "chain-column"), right = element("div", undefined, "chain-column");
    left.append(element("h3", "Your certificate chain"));
    const path = element("ol", undefined, "chain-path");
    r.path.forEach((c, i) => {
      const item = element("li");
      if (i > 0) item.append(element("div", "✓ Signature matches the issuer below", "chain-link"));
      const card = element("div", undefined, "chain-node"), meta = element("div", undefined, "node-type");
      meta.append(element("span", c.role === "leaf" ? "01 / Website certificate" : c.role === "trust-anchor" ? "Trust anchor" : c.role === "root" ? "Server-sent root" : "Intermediate certificate"));
      meta.append(element("span", c.role === "trust-anchor" ? "Trusted locally" : !c.in_date ? "Outside validity" : c.role === "root" ? "Path not verified" : "Server-sent", "chain-badge" + (c.role === "trust-anchor" ? " trusted" : !c.in_date || c.role === "root" ? " failed" : "")));
      card.append(meta, element("strong", c.subject), element("p", "Valid from " + displayDate(c.not_before)), element("p", "Expires " + displayDate(c.not_after)));
      if (c.role === "trust-anchor") card.append(element("p", c.sent ? "Also sent by the server; trust comes from the local root store." : "From the root store. The server does not need to send it."));
      else card.append(element("p", "Issued by " + c.issuer));
      item.append(card); path.append(item);
    });
    if (!r.trusted) {
      const item = element("li"); item.append(element("div", "! Full trust path not established", "chain-link failed"));
      const gap = element("div", undefined, "chain-node chain-gap"); gap.append(element("strong", "Validation stops here"), element("p", "An issuer may be missing or unsuitable, the CA may be untrusted, or another validation rule may fail. See the explanation alongside.")); item.append(gap); path.append(item);
    }
    left.append(path);
    const legend = element("div", undefined, "chain-legend"); legend.append(element("span","✓ Verified link"), element("span","△ Attention"), element("span","! Problem")); left.append(legend);
    right.append(element("h3", r.findings.length ? "What to check next" : "Everything connected"));
    const focused = r.findings.filter(f => f.code !== "unused" && !(f.code === "trust" && r.findings.some(other => ["issuer-not-linked","issuer-ambiguous"].includes(other.code))));
    const findings = focused.length ? focused : r.findings.length ? r.findings : [{title:"No chain problem found in this observation",detail:"The hostname matches and the current server-auth path verifies against this Rootwell server's roots.",action:"No chain repair is needed for this observation. Revocation, other endpoints and every browser's trust are outside this check."}];
    for (const f of findings) { const item = element("article", undefined, "chain-finding"); item.append(element("h4", (f.level === "failed" ? "! " : f.level === "attention" ? "△ " : "✓ ") + f.title), element("p",f.detail),element("p",f.action,"finding-action")); right.append(item); }
    layout.append(left,right); result.append(layout);
    const details = element("details",undefined,"chain-details"); details.append(element("summary","Technical details · server-sent order & fingerprints"));
    const dl = element("dl");
    for (const [k,v] of [["Observed",new Date(r.observed_at).toLocaleString()],["Connected IP",r.address],["Connection",r.tls_version + " · port 443"],["Trust source",r.trust_source],["Revocation","Not checked"]]) dl.append(element("dt",k),element("dd",v));
    if (r.trusted) dl.append(element("dt","Root SHA-256"),element("dd",r.path[r.path.length-1].fingerprint));
    details.append(dl,element("p","Certificates in the order the server sent them. The diagram above follows signature links; it may use a different order."));
    const sent = element("ol"); for (const c of r.presented) { const li = element("li",c.subject + " · issuer: " + c.issuer); li.append(element("p","Valid from " + c.not_before + " · expires " + c.not_after),element("code","SHA-256 " + c.fingerprint)); sent.append(li); } details.append(sent);
    if (r.findings.length) { details.append(element("h3","All observations")); for (const f of r.findings) details.append(element("p",f.title + ": " + f.detail + " " + f.action)); }
    result.append(details); result.hidden = false; result.scrollIntoView({block:"start"});
  }
  function reset(message = "") {
    epoch++; if (active) active.abort(); active = null;
    result.replaceChildren(); result.hidden = true; status.textContent = message;
    submit.disabled = form.dataset.readOnly === "true"; for (const b of buttons) b.disabled = false;
  }
  async function read(response) {
    if (!response.ok || !/^application\/json(?:;|$)/i.test(response.headers.get("Content-Type") || "") || !response.body) throw new Error("response");
    const reader = response.body.getReader(), decoder = new TextDecoder("utf-8", {fatal:true}); let size = 0, body = "";
    try { for (;;) { const {done,value} = await reader.read(); if (done) break; size += value.byteLength; if (size > 98304) throw new Error("size"); body += decoder.decode(value,{stream:true}); } body += decoder.decode(); return JSON.parse(body); }
    finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
  }
  async function run(example) {
    if (active) return;
    reset(); if (document.hidden) return;
    if (!example && (form.dataset.readOnly === "true" || !consent.checked)) { status.textContent = "Confirm this one website check first."; return; }
    const id = epoch, controller = new AbortController(); active = controller; submit.disabled = true; for (const b of buttons) b.disabled = true;
    const selectedTarget = target.value;
    if (!example) consent.checked = false;
    status.textContent = example ? "Loading a generated example…" : "Checking the website certificate from your Rootwell server…";
    const timer = setTimeout(() => { if (id === epoch) reset("Check timed out. No successful result is available. Wait 30 seconds before trying again."); }, 12000);
    try {
      const response = await fetch(example ? "/website-examples.json" : "/api/website-check", {
        method: example ? "GET" : "POST", credentials:"same-origin", cache:"no-store", redirect:"error", signal:controller.signal,
        ...(example ? {} : {headers:{"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify({target:selectedTarget,confirm:true})})
      });
      const body = await read(response), report = example ? body.synthetic === true && body.examples && body.examples[example] : body;
      if (!valid(report)) throw new Error("contract");
      if (!example && report.hostname !== new URL(selectedTarget.includes("://") ? selectedTarget : "https://"+selectedTarget).hostname.toLowerCase()) throw new Error("target");
      if (id !== epoch || controller.signal.aborted || document.hidden) return;
      render(report,!!example); status.textContent = example ? "Example only. Your website has not been checked." : "Check complete. This is one observation; the result has not been saved.";
    } catch {
      if (id === epoch && !document.hidden) { result.replaceChildren(); result.hidden = true; status.textContent = "No result available. Check your sign-in, the public HTTPS address and Linux server availability. Wait 30 seconds before trying again. No successful check is implied."; }
    } finally {
      clearTimeout(timer); if (id === epoch) { active = null; submit.disabled = form.dataset.readOnly === "true"; for (const b of buttons) b.disabled = false; }
    }
  }
  form.addEventListener("submit", event => { event.preventDefault(); void run(null); });
  buttons.forEach((b,i) => b.addEventListener("click", () => { void run(["valid","missing","wrong"][i]); }));
  target.addEventListener("input", () => { consent.checked = false; reset(); });
  consent.addEventListener("change", () => reset());
  document.addEventListener("visibilitychange", () => { if (document.hidden) { consent.checked = false; target.value = ""; reset(); } });
  addEventListener("pagehide", () => { consent.checked = false; target.value = ""; reset(); });
  reset(form.dataset.readOnly === "true" ? "Visual preview · live checks are disabled. Choose a generated example below." : "");
})();
