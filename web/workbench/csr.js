"use strict";
(function () {
  const get = id => document.getElementById(id);
  const encoder = new TextEncoder();
  const fingerprint = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/;
  const mode = get("csr-mode"), algorithm = get("csr-algorithm"), keyFile = get("csr-key-file"), openFile = get("csr-open-file"), certFile = get("csr-certificate");
  const password = get("csr-password"), confirm = get("csr-confirm"), inputPassword = get("csr-input-password");
  const createButton = get("csr-create-button"), openButton = get("csr-open-button"), matchButton = get("csr-match-button");
  const status = get("csr-status"), error = get("csr-error"), result = get("csr-result"), comparison = get("csr-comparison");
  let module = null, generation = 0, controller = null, busy = false, current = null;
  function clearSecrets() { password.value = confirm.value = inputPassword.value = ""; }
  function fail(message) { error.textContent = message; error.hidden = false; status.textContent = "No download was requested by this operation."; }
  function refusal(kind, selectedMode) {
    if (kind === "inspect") return "Choose a supported signed CSR, not a certificate or private key. Only DNS/IP requests are supported; unknown attributes or extensions are refused. If the check timed out, try opening the CSR again.";
    if (kind === "match") return "Choose one public site certificate, not a bundle or private key. Reopen the CSR if its file changed, then compare again. No trust result was produced.";
    if (kind === "convert") return "The CSR could not be exported safely. Open the signed CSR again, then choose PEM or DER. No new download was requested.";
    return selectedMode === "key" ? "The request could not be created. Check your current key password, supported key format, site names and optional details. If the check timed out, try again. No new download was requested." : "The request could not be created. Check your site names and optional details, or try again if key generation timed out. No new download was requested.";
  }
  function validFile(file, maximum) { return file && Number.isSafeInteger(file.size) && file.size > 0 && file.size <= maximum; }
  function first(field) { return field.files && field.files.length === 1 ? field.files[0] : null; }
  function buttons() {
    createButton.disabled = !module || busy || !["generate", "key"].includes(mode.value) || (mode.value === "key" && !validFile(first(keyFile), 64 << 10));
    openButton.disabled = !module || busy || !validFile(first(openFile), 64 << 10);
    matchButton.disabled = !module || busy || !current || !validFile(first(certFile), 1 << 20);
    for (const id of ["csr-download-pem", "csr-download-der"]) get(id).disabled = !module || busy || !current;
  }
  function cancel() {
    if (controller) { generation++; controller.abort(); status.textContent = "Choices changed or page left. Start the operation again."; }
  }
  function forget() { if (current && current.csr) current.csr.fill(0); current = null; result.hidden = true; comparison.hidden = true; }
  function change() { cancel(); generation++; clearSecrets(); forget(); error.hidden = true; status.textContent = ""; buttons(); }
  function updateMode() {
    get("csr-new-key").hidden = mode.value !== "generate";
    get("csr-existing-key").hidden = mode.value !== "key";
    createButton.textContent = mode.value === "key" ? "Create CSR using my key" : "Create key and CSR download";
  }
  async function read(file, maximum) {
    if (!validFile(file, maximum)) throw new Error("invalid file");
    const bytes = new Uint8Array(await file.slice(0, maximum + 1).arrayBuffer());
    if (bytes.length !== file.size || bytes.length > maximum) { bytes.fill(0); throw new Error("changed file"); }
    return bytes;
  }
  function validSummary(value) {
    return value && ["pem", "der"].includes(value.input_format) && typeof value.subject === "string" && value.subject.length <= 4096 &&
      ["RSA", "ECDSA", "Ed25519"].includes(value.algorithm) && Number.isSafeInteger(value.bits) && value.bits > 0 && value.bits <= 16384 &&
      typeof value.curve === "string" && value.curve.length <= 32 && typeof value.signature_algorithm === "string" && value.signature_algorithm.length <= 64 &&
      value.signature_checked === true && typeof value.request_fingerprint === "string" && fingerprint.test(value.request_fingerprint) &&
      typeof value.public_fingerprint === "string" && fingerprint.test(value.public_fingerprint) &&
      Array.isArray(value.dns_names) && value.dns_names.length <= 32 && value.dns_names.every(name => typeof name === "string" && name.length <= 253) &&
      Array.isArray(value.ip_addresses) && value.ip_addresses.length <= 8 && value.ip_addresses.every(name => typeof name === "string" && name.length <= 64);
  }
  function publicAnswer(answer) {
    if (typeof answer !== "string" || answer.length > 32768) throw new Error("invalid reply");
    const response = JSON.parse(answer);
    if (!response || response.schema_version !== "rootwell.browser.csr.v1" || response.ok !== true || response.error !== null || !response.result) throw new Error("invalid reply");
    return response.result;
  }
  function fileAnswer(answer, format, expected) {
    const value = answer && answer.result;
    if (!answer || answer.schema_version !== "rootwell.browser.csr.v1" || answer.ok !== true || answer.error !== null || !value || value.format !== format ||
        !(value.bytes instanceof Uint8Array) || !value.bytes.length || value.bytes.length > 256 << 10 ||
        !(value.csr instanceof Uint8Array) || !value.csr.length || value.csr.length > 64 << 10 ||
        typeof value.summary !== "string" || value.summary.length > 16384) throw new Error("invalid output");
    const summary = JSON.parse(value.summary);
    if (!validSummary(summary) || (expected && summary.request_fingerprint !== expected)) throw new Error("changed request");
    const pattern = format === "zip" ? /^rootwell-request-and-key-[0-9a-f]{32}\.zip$/ : new RegExp("^rootwell-request-[0-9a-f]{32}\\." + (format === "pem" ? "csr" : "der") + "$");
    if (!pattern.test(value.filename)) throw new Error("invalid name");
    const header = encoder.encode("-----BEGIN CERTIFICATE REQUEST-----\n");
    if (!header.every((byte, i) => value.csr[i] === byte) || (format === "pem" && !header.every((byte, i) => value.bytes[i] === byte)) ||
        (format === "der" && value.bytes[0] !== 0x30) || (format === "zip" && (value.bytes[0] !== 0x50 || value.bytes[1] !== 0x4b))) throw new Error("invalid encoding");
    return summary;
  }
  function show(source) {
    forget(); current = source;
    get("csr-summary").textContent = "Signed request · " + source.summary.algorithm + " " + source.summary.bits + " bits · " + (source.summary.subject || "empty subject");
    const names = get("csr-names"); names.replaceChildren();
    for (const name of [...source.summary.dns_names, ...source.summary.ip_addresses]) { const item = document.createElement("li"); item.textContent = name; names.append(item); }
    if (!names.children.length) { const item = document.createElement("li"); item.textContent = "No DNS/IP names requested. Modern TLS certificates normally need SAN names."; names.append(item); }
    get("csr-technical").textContent = "Signature checked: " + source.summary.signature_algorithm + "\nCSR SHA-256: " + source.fingerprint + "\nPublic-key SHA-256: " + source.summary.public_fingerprint;
    result.hidden = false;
  }
  function download(value) {
    const url = URL.createObjectURL(new Blob([value.bytes], { type: value.format === "zip" ? "application/zip" : value.format === "pem" ? "application/x-pem-file" : "application/octet-stream" }));
    try { const anchor = document.createElement("a"); anchor.href = url; anchor.download = value.filename; document.body.append(anchor); anchor.click(); anchor.remove(); }
    finally { setTimeout(() => URL.revokeObjectURL(url), 15000); }
  }
  function params() {
    const list = value => value.split(/[\n,]+/).map(name => name.trim()).filter(Boolean);
    return { dns_names: list(get("csr-dns").value), ip_addresses: list(get("csr-ips").value), common_name: "",
      organization: get("csr-organization").value, organizational_unit: get("csr-unit").value, country: get("csr-country").value,
      locality: get("csr-locality").value, province: get("csr-province").value };
  }
  async function operation(kind, format) {
    if (!module || busy) return;
    const request = generation, source = current, selectedKey = first(keyFile), selectedCSR = first(openFile), selectedCert = first(certFile);
    const selectedMode = mode.value;
    const keyPassword = inputPassword.value, nextPassword = password.value, confirmation = confirm.value;
    clearSecrets();
    let option = "", workerKind = kind, expectedFormat = format, input = new Uint8Array(), cert = new Uint8Array(), secret = new Uint8Array(), answer;
    if (kind === "create") {
      const values = params();
      if (!values.dns_names.length && !values.ip_addresses.length) { fail("Enter at least one site name, or an IP address in optional details."); return; }
      if (values.dns_names.length > 32 || values.ip_addresses.length > 8) { fail("Use at most 32 site names and 8 IP addresses."); return; }
      workerKind = selectedMode;
      if (selectedMode === "generate") {
        if (nextPassword !== confirmation || nextPassword.length < 20 || nextPassword.length > 128 || !/^[!-~]+$/.test(nextPassword)) { fail("Choose and confirm a fresh 20–128 character non-space ASCII key password."); return; }
        secret = encoder.encode(nextPassword); expectedFormat = "zip";
        option = JSON.stringify({ algorithm: algorithm.value, params: values, format: "" });
      } else if (selectedMode === "key" && validFile(selectedKey, 64 << 10)) {
        secret = encoder.encode(keyPassword); expectedFormat = get("csr-key-format").value;
        option = JSON.stringify({ algorithm: "", params: values, format: expectedFormat });
      } else { fail("Choose one supported private key no larger than 64 KiB."); return; }
    } else if (kind === "inspect") {
      if (!validFile(selectedCSR, 64 << 10)) { fail("Choose one CSR no larger than 64 KiB."); return; }
    } else {
      if (!source) return;
      option = source.fingerprint + (kind === "convert" ? ":" + format : "");
      if (kind === "match" && !validFile(selectedCert, 1 << 20)) { fail("Choose one returned public certificate no larger than 1 MiB."); return; }
    }
    if (secret.length > 256 || encoder.encode(option).length > 16384) { secret.fill(0); fail("The password or request fields exceed the supported limits."); return; }
    const active = new AbortController(); controller = active; busy = true; buttons(); error.hidden = true;
    if (kind === "match") comparison.hidden = true;
    status.textContent = kind === "create" ? "Creating and rechecking your signed request locally. Large RSA keys may take a while…" : "Checking locally…";
    try {
      if (kind === "create" && selectedMode === "key") input = await read(selectedKey, 64 << 10);
      else if (kind === "inspect") input = await read(selectedCSR, 64 << 10);
      else if (source && kind !== "create") input = source.file ? await read(source.file, 64 << 10) : source.csr.slice();
      if (kind === "match") cert = await read(selectedCert, 1 << 20);
      if (request !== generation) return;
      answer = await rootwellCSRWorker.run(module, workerKind, input, cert, secret, option, active.signal);
      if (request !== generation || (kind !== "create" && kind !== "inspect" && current !== source)) return;
      if (kind === "inspect") {
        const summary = publicAnswer(answer); if (!validSummary(summary)) throw new Error("invalid summary");
        show({ file: selectedCSR, fingerprint: summary.request_fingerprint, summary });
        status.textContent = "CSR signature checked locally. Nothing was uploaded or saved.";
      } else if (kind === "match") {
        const checked = publicAnswer(answer);
        const namesValid = values => Array.isArray(values) && values.length <= 256 && values.every(name => typeof name === "string" && name.length <= 260);
        if (typeof checked.key_match !== "boolean" || typeof checked.subject_changed !== "boolean" || typeof checked.certificate_is_ca !== "boolean" ||
            checked.trust_checked !== false || !namesValid(checked.missing_names) || !namesValid(checked.additional_names)) throw new Error("invalid comparison");
        get("csr-match-summary").textContent = checked.key_match ? (checked.missing_names.length ? "Same public key, but requested names are missing." : "Same public key. All requested names are present.") : "Different public key — do not pair this certificate with this request.";
        const differences = get("csr-match-differences"); differences.replaceChildren();
        for (const text of [...checked.missing_names.map(name => "Missing: " + name), ...checked.additional_names.map(name => "Additional: " + name),
          ...(checked.subject_changed ? ["Subject differs from the request (values or encoding may have changed)."] : []),
          ...(checked.certificate_is_ca ? ["This is a CA certificate, not a normal site certificate."] : [])]) { const item = document.createElement("li"); item.textContent = text; differences.append(item); }
        comparison.hidden = false; status.textContent = "Comparison complete. Certificate trust was not checked.";
      } else {
        const summary = fileAnswer(answer, expectedFormat, kind === "convert" ? source.fingerprint : "");
        download(answer.result);
        if (kind === "create") show({ csr: answer.result.csr.slice(), fingerprint: summary.request_fingerprint, summary });
        status.textContent = expectedFormat === "zip" ? "Download requested: ZIP with encrypted private key and signed public CSR. Save it and your password securely; send only the CSR to your CA." : "Public CSR download requested. Your private key was not included.";
      }
    } catch {
      if (request === generation) fail(refusal(kind, selectedMode));
    } finally {
      for (const bytes of [input, cert, secret, answer && answer.result && answer.result.bytes, answer && answer.result && answer.result.csr]) if (bytes instanceof Uint8Array) bytes.fill(0);
      clearSecrets(); if (controller === active) controller = null; busy = false; buttons();
    }
  }
  mode.addEventListener("change", () => { change(); updateMode(); });
  for (const id of ["csr-algorithm", "csr-key-format", "csr-key-file", "csr-open-file"]) get(id).addEventListener("change", change);
  for (const id of ["csr-dns", "csr-ips", "csr-organization", "csr-unit", "csr-country", "csr-locality", "csr-province"]) get(id).addEventListener("input", () => { cancel(); generation++; forget(); error.hidden = true; buttons(); });
  for (const field of [password, confirm, inputPassword]) field.addEventListener("input", cancel);
  certFile.addEventListener("change", () => { cancel(); generation++; comparison.hidden = true; error.hidden = true; buttons(); });
  createButton.addEventListener("click", () => operation("create")); openButton.addEventListener("click", () => operation("inspect"));
  matchButton.addEventListener("click", () => operation("match"));
  for (const format of ["pem", "der"]) get("csr-download-" + format).addEventListener("click", () => operation("convert", format));
  function boundary() { cancel(); clearSecrets(); }
  for (const id of ["inspect-tab", "convert-tab", "verify-tab", "request-tab"]) get(id).addEventListener("click", boundary);
  for (const name of ["blur", "pagehide", "hashchange"]) globalThis.addEventListener(name, boundary);
  document.addEventListener("visibilitychange", () => { if (document.hidden) boundary(); });
  updateMode(); buttons();
  rootwellWorkbenchReady.then(ready => {
    if (!(ready.module instanceof WebAssembly.Module) || !globalThis.rootwellCSRWorker || typeof rootwellCSRWorker.run !== "function") throw new Error("unavailable");
    module = ready.module; buttons();
  }).catch(() => { fail("Local request engine is unavailable."); });
})();
