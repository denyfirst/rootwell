// Pure public comparison helper: no DOM, network, storage or private-key API.
(() => {
  "use strict";
  const fingerprint = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/;
  const hash = /^[a-f0-9]{64}$/;
  const validFingerprint=value=>typeof value === "string" && value.length===95 && fingerprint.test(value);
  const validHash=value=>typeof value === "string" && value.length===64 && hash.test(value);
  const maxBytes = 256 * 1024;
  const normalize = value => value.replaceAll(":", "").toLowerCase();
  function prepare(engine, bytes, selected = "") {
    if (!(bytes instanceof Uint8Array) || bytes.length < 1 || bytes.length > maxBytes || typeof engine?.explore !== "function" || typeof engine?.analyze !== "function") throw new Error("expected-file");
    const raw = engine.explore(bytes);
    if (typeof raw !== "string" || raw.length > 1024 * 1024) throw new Error("expected-file");
    const parsed = JSON.parse(raw), r = parsed?.result;
    if (parsed.schema_version !== "rootwell.browser.explore.v1" || parsed.ok !== true || parsed.error !== null || !r || r.verification !== "not-performed" || r.trust_anchor !== "not-selected" || !Array.isArray(r.certificates) || r.count !== r.certificates.length || r.count < 1 || r.count > 10) throw new Error("expected-file");
    const certificates = r.certificates.map(c => {
      if (!c || !validFingerprint(c.sha256) || typeof c.is_ca !== "boolean" || typeof c.subject !== "string" || c.subject.length > 8192) throw new Error("expected-file");
      return Object.freeze({fingerprint:normalize(c.sha256), is_ca:c.is_ca, subject:c.subject.replace(/[\u0000-\u001f\u007f-\u009f\u2028-\u202e\u2066-\u2069]/gu,"?").slice(0,160)});
    });
    if (new Set(certificates.map(c => c.fingerprint)).size !== certificates.length) throw new Error("expected-file");
    const graphRaw = engine.analyze([bytes]);
    if (typeof graphRaw !== "string" || graphRaw.length > 65536) throw new Error("expected-file");
    const graph = JSON.parse(graphRaw);
    if (graph.schema_version !== "rootwell.browser.chain.v1" || graph.ok !== true || graph.error !== "" || graph.result?.verification !== "not-performed" || graph.result?.trust_anchor !== "not-selected" || !Array.isArray(graph.result.certificates) || graph.result.certificates.length !== certificates.length) throw new Error("expected-file");
    const linked = certificates.map((c,i) => {
      const g = graph.result.certificates[i];
      if (!g || !validFingerprint(g.sha256) || normalize(g.sha256) !== c.fingerprint || typeof g.self_signed !== "boolean" || (g.self_signed && !c.is_ca) || !Array.isArray(g.parents) || g.parents.length > 9 || new Set(g.parents).size !== g.parents.length || g.parents.some(p => !Number.isInteger(p) || p < 0 || p >= certificates.length || p === i || !certificates[p].is_ca)) throw new Error("expected-file");
      return Object.freeze({...c, self_signed:g.self_signed, parents:Object.freeze(g.parents.map(p => certificates[p].fingerprint))});
    });
    const candidates = certificates.filter(c => !c.is_ca);
    if (!candidates.length) throw new Error("expected-site-certificate");
    if (selected && (!validHash(selected) || !candidates.some(c => c.fingerprint === selected))) throw new Error("expected-selection");
    const leaf = selected || (candidates.length === 1 ? candidates[0].fingerprint : "");
    return Object.freeze({leaf, candidates:Object.freeze(candidates), certificates:Object.freeze(linked)});
  }
  function compare(expected, report) {
    if (!expected || !validHash(expected.leaf) || !Array.isArray(expected.certificates) || expected.certificates.length < 1 || expected.certificates.length > 10 || !expected.certificates.every(c=>c&&validHash(c.fingerprint)&&typeof c.is_ca==="boolean") || !expected.certificates.some(c => !c.is_ca && c.fingerprint === expected.leaf) || !Array.isArray(report?.presented) || report.presented.length < 1 || report.presented.length > 10 || report.presented[0].role !== "leaf" || report.presented[0].position !== 1 || report.presented.some(c => !validHash(c?.fingerprint))) throw new Error("expected-response");
    const served = report.presented[0].fingerprint;
    // Presence is informational, not a chain or trust verdict. Never add any
    // supplied certificate to the server observation or its trust path.
    const authorities = expected.certificates.filter(c => c.is_ca).map(c => Object.freeze({
      fingerprint:c.fingerprint, subject:c.subject,
      presence:report.presented.some(p => p.fingerprint === c.fingerprint) ? "server-sent" :
        report.trusted === true && report.path?.some(p => p.fingerprint === c.fingerprint) ? "verified-path" : "not-sent"
    }));
    if (!Array.isArray(report.issuer_checks) || report.issuer_checks.length !== report.presented.length) throw new Error("expected-response");
    const nodes=[],visited=new Set();let ambiguousPath=false;
    let next=expected.leaf;
    while (next && !visited.has(next) && nodes.length < 10) {
      visited.add(next);
      const c=expected.certificates.find(c => c.fingerprint === next);
      if (!c) throw new Error("expected-response");
      const actual=report.presented.find(p => p.fingerprint === next),child=nodes[nodes.length-1];
      const check=child?.actual ? report.issuer_checks.find(k => k.child === child.fingerprint) : null;
      const childPath=child ? report.path?.findIndex(p => p.fingerprint === child.fingerprint) : -1;
      const verifiedParent=report.trusted === true && childPath >= 0 ? report.path[childPath+1] : null;
      let state,detail;
      if (!c.is_ca) { state=actual && actual.position===1 ? "match" : "different";detail=state==="match"?"Exact website certificate match":"The endpoint serves another website certificate"; }
      else if (actual) { state="match";detail="This exact CA certificate is sent by the server"; }
      else if (report.trusted === true && report.path?.some(p => p.fingerprint === c.fingerprint && p.role === "trust-anchor")) { state="root-omitted";detail="This exact trust anchor is local; the server does not need to send it"; }
      else if (c.self_signed) { state="root-omitted";detail="Root not sent — this is normally correct"; }
      else if (check?.verified?.length || verifiedParent) { state="alternative";detail="Another issuer verifies the signature; a different valid chain may be in use"; }
      else if (check?.rejected?.length) { state="wrong-issuer";detail="The certificate sent as its issuer cannot verify the certificate above"; }
      else if (child?.actual) { state="missing";detail="This expected intermediate was not sent by the server"; }
      else { state="not-observed";detail="First identify the certificate above before comparing this part"; }
      nodes.push(Object.freeze({fingerprint:c.fingerprint,subject:c.subject,role:!c.is_ca?"website":c.self_signed?"root":"intermediate",state,detail,actual:!!actual && (c.is_ca || actual.position===1), candidates:Object.freeze(check?.verified?.length ? [...check.verified] : verifiedParent ? [verifiedParent.fingerprint] : check?.rejected ? [...check.rejected] : [])}));
      if (c.parents.length > 1) ambiguousPath=true;
      if (c.self_signed || c.parents.length !== 1) break;
      next=c.parents[0];
    }
    for (const c of expected.certificates.filter(c=>c.is_ca&&!visited.has(c.fingerprint))) {
      const actual=report.presented.some(p=>p.fingerprint===c.fingerprint),inPath=report.trusted===true&&report.path?.some(p=>p.fingerprint===c.fingerprint);
      nodes.push(Object.freeze({fingerprint:c.fingerprint,subject:c.subject,role:c.self_signed?"root":"intermediate",state:"additional",actual,
        detail:actual ? "Additional CA from your file: sent by the server, outside the unique expected path shown" : inPath ? "Additional CA from your file: found in the independently verified website path" : c.self_signed ? "Additional root not sent — normally expected; no unique signature path to it was established from your file" : "This additional CA from your file was not observed; it is outside the unique expected path shown",candidates:Object.freeze([])}));
    }
    return Object.freeze({state:expected.leaf === served ? "match" : "different", expected:expected.leaf, served, authorities:Object.freeze(authorities),nodes:Object.freeze(nodes),ambiguousPath});
  }
  Object.defineProperty(globalThis,"rootwellWebsiteExpected",{value:Object.freeze({prepare,compare,maxBytes})});
})();
