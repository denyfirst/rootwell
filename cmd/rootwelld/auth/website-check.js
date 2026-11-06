(() => {
  "use strict";
  const $ = id => document.getElementById(id);
  const form = $("website-form"), target = $("website-target"), consent = $("website-consent"), submit = $("website-submit"), status = $("website-status"), result = $("website-result");
  const compareEnabled = $("website-compare"), expectedFile = $("expected-certificate"), expectedPanel = $("website-expected"), expectedChoice = $("expected-choice"), choiceBox = $("expected-choice-box"), expectedStatus = $("expected-status");
  let active = null, epoch = 0;
  const buttons = [$("example-valid"), $("example-missing"), $("example-wrong"), $("example-compare")];
  const element = (tag, text, cls) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; };
  const text = (v, max) => typeof v === "string" && v.length <= max;
  const date = v => text(v, 40) && Number.isFinite(Date.parse(v));
  function certificate(c) {
    return c && typeof c.fingerprint === "string" && c.fingerprint.length===64 && /^[a-f0-9]{64}$/.test(c.fingerprint) && text(c.subject, 480) && text(c.issuer, 480) && date(c.not_before) && date(c.not_after) && ["leaf", "intermediate", "trust-anchor", "root"].includes(c.role) && typeof c.sent === "boolean" && Number.isInteger(c.position) && c.position >= 0 && c.position <= 10 && c.sent === (c.position > 0) && typeof c.in_date === "boolean";
  }
  function issuerChecks(r) {
    if (!Array.isArray(r.issuer_checks) || r.issuer_checks.length !== r.presented.length || new Set(r.issuer_checks.map(c => c?.child)).size !== r.issuer_checks.length) return false;
    return r.issuer_checks.every(c => c && r.presented.some(p => p.fingerprint === c.child) && typeof c.self_signed === "boolean" &&
      [c.verified,c.rejected].every(a => Array.isArray(a) && a.length <= 9 && new Set(a).size === a.length && a.every(fp => fp !== c.child && r.presented.some(p => p.fingerprint === fp))) && !c.verified.some(fp => c.rejected.includes(fp)));
  }
  function valid(r) {
    return r && r.schema_version === "rootwell.website-chain.v1" && text(r.hostname,253) && r.hostname.length > 0 && text(r.address,64) && ["TLS 1.2","TLS 1.3"].includes(r.tls_version) && date(r.observed_at) && ["verified","attention","failed"].includes(r.state) && typeof r.trusted === "boolean" && typeof r.hostname_matches === "boolean" && Array.isArray(r.path) && r.path.length >= 1 && r.path.length <= 11 && r.path.every(certificate) && r.path[0].role === "leaf" && Array.isArray(r.presented) && r.presented.length >= 1 && r.presented.length <= 10 && r.presented.every(certificate) && Array.isArray(r.findings) && r.findings.length <= 40 && r.findings.every(f => f && text(f.code,64) && ["failed","attention"].includes(f.level) && text(f.title,200) && text(f.detail,800) && text(f.action,800)) && text(r.trust_source,120) && r.revocation === "not-checked" &&
      (r.state === "failed" ? r.findings.some(f => f.level === "failed") : r.trusted && r.hostname_matches && !r.findings.some(f => f.level === "failed")) &&
      (r.state !== "verified" || r.findings.length === 0) && (r.trusted ? r.path.every(c => c.in_date) && (r.path[r.path.length-1].role === "trust-anchor" || r.path.length === 1) : !r.path.some(c => c.role === "trust-anchor")) && issuerChecks(r);
  }
  const displayDate = value => new Date(value).toLocaleDateString(undefined, {year:"numeric",month:"short",day:"numeric"});
  function render(r, example, comparison = null) {
    result.replaceChildren();
    if (example) result.append(element("p", "EXAMPLE · generated certificates · no website contacted", "chain-sample"));
    if (comparison) {
      const chainDiffers=comparison.nodes.some(n=>["wrong-issuer","missing","alternative"].includes(n.state));
      const box = element("section",undefined,"expected-result " + comparison.state + (r.state === "failed" ? " has-issue" : chainDiffers ? " has-difference" : ""));
      box.append(element("h2",comparison.state !== "match" ? "! The website serves a different certificate." : r.state === "failed" ? "! Your certificate matches, but the website check fails." : chainDiffers ? "△ Your certificate matches; the supplied chain differs." : "✓ The website serves your certificate."));
      box.append(element("p",comparison.state === "match" ? "The full SHA-256 certificate fingerprint matches your selected certificate. This identity match does not establish that the server chain is healthy; see the separate result below." : "The certificate fingerprint differs. Check the installed certificate, SNI, proxy or load-balancer node. A renewal can change the certificate even when its names or public key stay the same."));
      const ids = element("details"); ids.append(element("summary","Compared fingerprints"),element("p","Your selected certificate"),element("code",comparison.expected),element("p","Server-presented certificate"),element("code",comparison.served));box.append(ids);
      box.append(element("h3","Where your chain matches or differs"));
      if (comparison.ambiguousPath) box.append(element("p","Your file has more than one possible issuer path. Remaining CA certificates are listed separately; file order does not choose a trusted path."));
      const nodes=element("ol",undefined,"expected-nodes");
      for (const [index,node] of comparison.nodes.entries()) {
        const item=element("li",undefined,"expected-node " + node.state);
        const icon=node.state === "match" ? "✓" : ["different","wrong-issuer","missing"].includes(node.state) ? "!" : "△";
        item.append(element("strong",(index+1)+". "+(node.role === "website" ? "Website certificate" : node.role === "root" ? "Root certificate" : "Intermediate certificate")+" · "+node.subject),element("p",icon+" "+node.detail));
        const nodeIds=element("details");nodeIds.append(element("summary","Fingerprints"),element("code","Expected SHA-256 "+node.fingerprint));
        for (const fp of node.candidates) { const candidate=r.presented.find(c => c.fingerprint===fp)||r.path.find(c => c.fingerprint===fp);item.append(element("p","Observed issuer candidate"+(candidate?.position ? " #"+candidate.position : "")+": "+(candidate?.subject||"Certificate in verified path")));nodeIds.append(element("code","Observed SHA-256 "+fp)); }
        item.append(nodeIds);
        nodes.append(item);
      }
      box.append(nodes);
      if (comparison.authorities.length) {
        const authorities = element("details");authorities.append(element("summary","Other CA certificates in your file · presence only"));
        const list = element("ul");for (const c of comparison.authorities) list.append(element("li",c.subject + " — " + (c.presence === "server-sent" ? "sent by the server" : c.presence === "verified-path" ? "found in the independently verified path" : "not sent / not in this verified path")));
        authorities.append(element("p","This list does not verify the uploaded bundle. A missing root is normal; a different valid issuer chain can also be legitimate. Your file never fills a gap in the website check."),list);box.append(authorities);
      }
      result.append(box);
      result.append(element("h3","Independent website chain check"));
    }
    const banner = element("div", undefined, "chain-banner " + r.state);
    banner.append(element("span", r.state === "failed" ? "!" : r.state === "attention" ? "△" : "✓", "state-icon"));
    const heading = element("div");
    heading.append(element("h2", r.state === "failed" ? "This certificate needs a fix." : r.state === "attention" ? "The chain needs attention." : "The certificate chain checks out."));
    heading.append(element("p", r.hostname + " · " + (r.trusted ? "Path reaches a trusted root" : "Trusted path not established") + " · " + (r.hostname_matches ? "Domain matches" : "Domain does not match")));
    banner.append(heading); result.append(banner);
    const layout = element("div", undefined, "chain-layout"), left = element("div", undefined, "chain-column"), right = element("div", undefined, "chain-column");
    left.append(element("h3", "Your certificate chain"));
    const path = element("ol", undefined, "chain-path");let showedBrokenIssuer=false;
    r.path.forEach((c, i) => {
      const item = element("li");
      if (i > 0) item.append(element("div", "✓ Signature matches the issuer below", "chain-link"));
      const card = element("div", undefined, "chain-node"), meta = element("div", undefined, "node-type");
      meta.append(element("span", c.role === "leaf" ? "01 / Website certificate" : c.role === "trust-anchor" ? "Trust anchor" : c.role === "root" ? "Server-sent root" : "Intermediate certificate"));
      meta.append(element("span", c.role === "trust-anchor" ? "Trusted locally" : !c.in_date ? "Outside validity" : c.role === "root" ? "Path not verified" : "Server-sent", "chain-badge" + (c.role === "trust-anchor" ? " trusted" : !c.in_date || c.role === "root" ? " failed" : "")));
      card.append(meta, element("strong", c.subject), element("p", "Valid from " + displayDate(c.not_before)), element("p", "Expires " + displayDate(c.not_after)));
      if (c.role === "trust-anchor") card.append(element("p", c.sent ? "Also sent by the server; trust comes from the local root store." : "From the root store. The server does not need to send it."));
      else card.append(element("p", "Issued by " + c.issuer));
      item.append(card);
      const check=r.issuer_checks.find(k => k.child===c.fingerprint);
      if (!r.trusted && check && check.verified.length===0 && check.rejected.length) {
        for (const fp of check.rejected) {
          const candidate=r.presented.find(p => p.fingerprint===fp);
          item.append(element("div","! This issuer cannot verify the certificate above","chain-link failed"));
          const rejected=element("div",undefined,"chain-node chain-gap");rejected.append(element("strong","Server-sent certificate #"+candidate.position+": "+candidate.subject),element("p","This exact candidate cannot verify the certificate above it."),element("code","SHA-256 "+candidate.fingerprint));item.append(rejected);showedBrokenIssuer=true;
        }
      }
      path.append(item);
    });
    if (!r.trusted && !showedBrokenIssuer) {
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
  function clearExpected() {
    expectedFile.value = ""; expectedChoice.replaceChildren(); expectedChoice.value = ""; choiceBox.hidden = true; expectedStatus.textContent = "";
  }
  async function prepareExpected(current) {
    const files = Array.from(expectedFile.files || []), file = files[0];
    if (files.length !== 1 || !Number.isSafeInteger(file?.size) || file.size < 1 || file.size > 256*1024) throw new Error("expected-file");
    let engine;
    try { engine = await globalThis.rootwellInventoryEngineReady; if (!engine) throw new Error(); } catch { throw new Error("expected-engine"); }
    if (!current()) throw new Error("stale");
    let bytes;
    try {
      bytes = new Uint8Array(await file.arrayBuffer());
      if (!current() || expectedFile.files?.[0] !== file || bytes.length !== file.size) throw new Error("stale");
      const prepared = globalThis.rootwellWebsiteExpected.prepare(engine,bytes,expectedChoice.value);
      if (!prepared.leaf) {
        expectedChoice.replaceChildren(element("option","Choose a certificate…"));expectedChoice.children[0].value = "";
        for (const c of prepared.candidates) { const option = element("option",c.subject + " · " + c.fingerprint.slice(0,16));option.value = c.fingerprint;expectedChoice.append(option); }
        expectedChoice.value = "";choiceBox.hidden = false;throw new Error("expected-selection");
      }
      expectedStatus.textContent = "Your file was read locally. Certificate identity and website chain health will be shown separately.";
      return prepared;
    } finally { if (bytes instanceof Uint8Array) bytes.fill(0); }
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
      const current = () => id === epoch && !controller.signal.aborted && !document.hidden;
      let expected = null;
      if (!example && compareEnabled.checked) expected = await prepareExpected(current);
      if (!current()) return;
      const response = await fetch(example ? "/website-examples.json" : "/api/website-check", {
        method: example ? "GET" : "POST", credentials:"same-origin", cache:"no-store", redirect:"error", signal:controller.signal,
        ...(example ? {} : {headers:{"Content-Type":"application/json","X-Rootwell-Request":"1"},body:JSON.stringify({target:selectedTarget,confirm:true})})
      });
      const body = await read(response), report = example ? body.synthetic === true && body.examples && body.examples[example === "compare" ? "wrong" : example] : body;
      if (!valid(report)) throw new Error("contract");
      if (!example && report.hostname !== new URL(selectedTarget.includes("://") ? selectedTarget : "https://"+selectedTarget).hostname.toLowerCase()) throw new Error("target");
      if (example === "compare") {
        if (!text(body.expected_certificate_pem,256*1024)) throw new Error("expected-file");
        const engine = await globalThis.rootwellInventoryEngineReady;
        if (!current()) return;
        const bytes = new TextEncoder().encode(body.expected_certificate_pem);
        try { expected = globalThis.rootwellWebsiteExpected.prepare(engine,bytes); } finally { bytes.fill(0); }
      }
      const comparison = expected ? globalThis.rootwellWebsiteExpected.compare(expected,report) : null;
      if (id !== epoch || controller.signal.aborted || document.hidden) return;
      render(report,!!example,comparison); status.textContent = example ? "Example only. Your website has not been checked and your selected file was not used." : "Check complete. This is one observation; the result has not been saved.";
    } catch (error) {
      if (id === epoch && !document.hidden) {
        result.replaceChildren(); result.hidden = true;
        status.textContent = error?.message === "expected-selection" ? "Several site certificates are in this file. Choose the intended certificate, confirm and check again. No website was contacted." :
          error?.message === "expected-engine" ? "The local certificate engine is unavailable. Reload and try again. No website was contacted." :
          ["expected-file","expected-site-certificate"].includes(error?.message) ? "Choose a valid public site certificate or bundle (PEM/CRT/CER/DER, up to 256 KiB / 10 certificates). Private keys, PFX and CA-only files are not accepted. No website was contacted." :
          "No result available. Check your sign-in, the public HTTPS address and Linux server availability. Wait 30 seconds before trying again. No successful check is implied.";
      }
    } finally {
      clearTimeout(timer); if (id === epoch) { active = null; submit.disabled = form.dataset.readOnly === "true"; for (const b of buttons) b.disabled = false; }
    }
  }
  form.addEventListener("submit", event => { event.preventDefault(); void run(null); });
  buttons.forEach((b,i) => b.addEventListener("click", () => { void run(["valid","missing","wrong","compare"][i]); }));
  target.addEventListener("input", () => { consent.checked = false; reset(); });
  consent.addEventListener("change", () => reset());
  compareEnabled.addEventListener("change", () => { consent.checked = false; clearExpected(); expectedPanel.hidden = !compareEnabled.checked; reset(); });
  expectedFile.addEventListener("change", () => { expectedChoice.replaceChildren(); expectedChoice.value = ""; choiceBox.hidden = true; expectedStatus.textContent = ""; consent.checked = false; reset(); });
  expectedChoice.addEventListener("change", () => { consent.checked = false; reset(); });
  const leave = () => { consent.checked = false; target.value = ""; compareEnabled.checked = false; expectedPanel.hidden = true; clearExpected(); reset(); };
  document.addEventListener("visibilitychange", () => { if (document.hidden) leave(); });
  addEventListener("pagehide", leave);
  reset(form.dataset.readOnly === "true" ? "Visual preview · live checks are disabled. Choose a generated example below." : "");
})();
