"use strict";

(function () {
  const byID = id => document.getElementById(id);
  const encoder = new TextEncoder();
  const fingerprint = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/;
  const newPassword = value => value.length >= 20 && value.length <= 128 && /^[!-~]+$/.test(value);
  let module = null;
  let openGeneration = 0;
  let createGeneration = 0;
  let openController = null;
  let createController = null;
  let inspected = null;
  let openBusy = false;
  let createBusy = false;

  const openFile = byID("pfx-open-file");
  const openPassword = byID("pfx-open-password");
  const openButton = byID("pfx-open-button");
  const openError = byID("pfx-open-error");
  const openStatus = byID("pfx-open-status");
  const openResult = byID("pfx-open-result");
  const certChoice = byID("pfx-cert-choice");
  const certFormat = byID("pfx-cert-format");
  const keyPassword = byID("pfx-key-password");
  const keyConfirm = byID("pfx-key-confirm");
  const createCert = byID("pfx-create-cert");
  const createKey = byID("pfx-create-key");
  const createChain = byID("pfx-create-chain");
  const createPassword = byID("pfx-create-password");
  const createConfirm = byID("pfx-create-confirm");
  const createButton = byID("pfx-create-button");
  const createError = byID("pfx-create-error");
  const createStatus = byID("pfx-create-status");

  function fail(box, status, message) {
    box.textContent = message;
    box.hidden = false;
    status.textContent = "No download was requested.";
  }
  function validFile(file, maximum) {
    return file && Number.isSafeInteger(file.size) && file.size > 0 && file.size <= maximum;
  }
  async function read(file, maximum) {
    if (!validFile(file, maximum)) throw new Error("invalid file");
    const bytes = new Uint8Array(await file.slice(0, maximum + 1).arrayBuffer());
    if (bytes.length !== file.size || bytes.length > maximum) { bytes.fill(0); throw new Error("changed file"); }
    return bytes;
  }
  function validSummary(answer) {
    const certs = answer && answer.result && answer.result.certificates;
    return answer.schema_version === "rootwell.browser.pfx.v1" && answer.ok === true && answer.error === null &&
      Array.isArray(certs) && certs.length >= 1 && certs.length <= 16 &&
      certs.filter(cert => cert.matching_key === true).length === 1 &&
      certs.every(cert => cert && typeof cert.subject === "string" && cert.subject.length <= 4096 &&
        typeof cert.issuer === "string" && cert.issuer.length <= 4096 &&
        typeof cert.not_after === "string" && cert.not_after.length <= 64 &&
        typeof cert.fingerprint === "string" && fingerprint.test(cert.fingerprint) &&
        typeof cert.is_ca === "boolean" && typeof cert.matching_key === "boolean") &&
      new Set(certs.map(cert => cert.fingerprint)).size === certs.length;
  }
  function showSummary(certs) {
    const list = byID("pfx-certificates");
    list.replaceChildren();
    certChoice.replaceChildren();
    for (const cert of certs) {
      const item = document.createElement("li");
      const title = document.createElement("strong");
      title.textContent = cert.matching_key ? "Certificate matching the private key" : "Additional included certificate · not trusted";
      const details = document.createElement("p");
      details.textContent = cert.subject + " · issuer: " + cert.issuer + " · expires: " + cert.not_after +
        " · " + (cert.is_ca ? "CA certificate" : "non-CA certificate") + " · SHA-256 " + cert.fingerprint;
      item.append(title, details);
      list.append(item);
      const option = document.createElement("option");
      option.value = cert.fingerprint;
      option.textContent = (cert.matching_key ? "Matching certificate" : "Included certificate") + " · " + cert.fingerprint.slice(0, 17);
      certChoice.append(option);
    }
  }
  function requestDownload(output, filename, type) {
    const url = URL.createObjectURL(new Blob([output], { type }));
    try {
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
    } finally { setTimeout(() => URL.revokeObjectURL(url), 15000); }
  }

  function invalidateOpen() {
    openGeneration++;
    if (openController) openController.abort();
    inspected = null;
    openResult.hidden = true;
    openError.hidden = true;
    openStatus.textContent = "";
    openPassword.value = "";
    keyPassword.value = "";
    keyConfirm.value = "";
    const file = openFile.files && openFile.files[0];
    byID("pfx-open-file-state").textContent = validFile(file, 1 << 20) ? "One PFX selected · " + file.size + " bytes" : "Choose one PFX no larger than 1 MiB";
    openButton.disabled = !module || !validFile(file, 1 << 20) || openBusy;
  }
  openFile.addEventListener("change", invalidateOpen);
  function cancelOpen() { if (openController) { openGeneration++; openController.abort(); openStatus.textContent = "Choices changed. Start this operation again."; } }
  for (const field of [openPassword, certChoice, certFormat, keyPassword, keyConfirm]) field.addEventListener(field.tagName === "SELECT" ? "change" : "input", cancelOpen);

  rootwellWorkbenchReady.then(ready => {
    if (!(ready.module instanceof WebAssembly.Module) || !globalThis.rootwellPFXWorker || typeof rootwellPFXWorker.run !== "function") throw new Error("no PFX engine");
    module = ready.module;
    openButton.disabled = !validFile(openFile.files && openFile.files[0], 1 << 20);
    createButton.disabled = !(validFile(createCert.files && createCert.files[0], 1 << 20) && validFile(createKey.files && createKey.files[0], 64 << 10));
  }).catch(() => {
    fail(openError, openStatus, "Local PFX engine is unavailable.");
    fail(createError, createStatus, "Local PFX engine is unavailable.");
  });

  openButton.addEventListener("click", async () => {
    const file = openFile.files && openFile.files[0];
    if (!module || !validFile(file, 1 << 20) || openBusy) return;
    const generation = openGeneration;
    const controller = new AbortController();
    openController = controller;
    openBusy = true;
    openButton.disabled = true;
    openResult.hidden = true;
    inspected = null;
    openError.hidden = true;
    openStatus.textContent = "Opening locally in an isolated worker…";
    let bytes, password;
    try {
      bytes = await read(file, 1 << 20);
      if (generation !== openGeneration || file !== openFile.files[0]) return;
      password = encoder.encode(openPassword.value);
      openPassword.value = "";
      if (password.length < 1 || password.length > 128) throw new Error("invalid password");
      const answer = await rootwellPFXWorker.run(module, "inspect", [bytes, new Uint8Array(), new Uint8Array()], password, new Uint8Array(), "", controller.signal);
      if (generation !== openGeneration || file !== openFile.files[0]) return;
      const parsed = JSON.parse(answer);
      if (!validSummary(parsed)) throw new Error("invalid PFX");
      inspected = { file, fingerprints: parsed.result.certificates.map(cert => cert.fingerprint),
        matching: parsed.result.certificates.find(cert => cert.matching_key).fingerprint };
      showSummary(parsed.result.certificates);
      openResult.hidden = false;
      openStatus.textContent = "Opened locally. Nothing was uploaded or saved. Enter the PFX password again before a download.";
    } catch {
      if (generation === openGeneration) fail(openError, openStatus, "PFX/password is invalid or outside the supported modern profile, or processing timed out.");
    } finally {
      openPassword.value = "";
      if (bytes) bytes.fill(0);
      if (password) password.fill(0);
      if (openController === controller) openController = null;
      openBusy = false;
      openButton.disabled = !module || !validFile(openFile.files && openFile.files[0], 1 << 20);
    }
  });

  async function exportOpened(kind) {
    if (!module || !inspected || openBusy) return;
    const source = inspected;
    const generation = openGeneration;
    const selected = certChoice.value;
    const format = certFormat.value;
    const pfxPassword = openPassword.value;
    const next = keyPassword.value;
    const confirm = keyConfirm.value;
    openPassword.value = "";
    keyPassword.value = "";
    keyConfirm.value = "";
    if (!source.fingerprints.includes(selected) || !["pem", "der"].includes(format) ||
        !pfxPassword || pfxPassword.length > 128 ||
        (kind === "key" && (!newPassword(next) || next !== confirm || next === pfxPassword))) {
      fail(openError, openStatus, kind === "key" ? "Re-enter the PFX password and choose a different, confirmed 20–128 character non-space ASCII key password." : "Re-enter the PFX password and choose a certificate.");
      return;
    }
    const controller = new AbortController();
    openController = controller;
    openBusy = true;
    openButton.disabled = true;
    openError.hidden = true;
    openStatus.textContent = "Rechecking the PFX locally…";
    let bytes, password, outputPassword, output;
    try {
      bytes = await read(source.file, 1 << 20);
      if (generation !== openGeneration || source !== inspected) return;
      password = encoder.encode(pfxPassword);
      outputPassword = encoder.encode(kind === "key" ? next : "");
      const option = kind === "key" ? source.matching : selected + ":" + format;
      const answer = await rootwellPFXWorker.run(module, kind, [bytes, new Uint8Array(), new Uint8Array()], password, outputPassword, option, controller.signal);
      output = answer && answer.result && answer.result.bytes;
      if (generation !== openGeneration || source !== inspected) return;
      const expectedFormat = kind === "key" ? "encrypted-pkcs8-pem" : format;
      const expectedName = kind === "key" ? /^rootwell-encrypted-key-[0-9a-f]{16}-[0-9a-f]{32}\.pem$/ :
        new RegExp("^rootwell-certificate-[0-9a-f]{16}-[0-9a-f]{32}\\." + format + "$");
      if (!answer || answer.schema_version !== "rootwell.browser.pfx.v1" || answer.ok !== true || answer.error !== null ||
          !answer.result || answer.result.format !== expectedFormat || !expectedName.test(answer.result.filename) ||
          !(output instanceof Uint8Array) || output.length < 1 || output.length > 1 << 20) throw new Error("invalid response");
      if (expectedFormat !== "der") {
        const header = encoder.encode(kind === "key" ? "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" : "-----BEGIN CERTIFICATE-----\n");
        if (!header.every((byte, index) => output[index] === byte)) throw new Error("invalid output");
      }
      requestDownload(output, answer.result.filename, expectedFormat === "der" ? "application/octet-stream" : "application/x-pem-file");
      openStatus.textContent = "Download requested. Check the browser save location; this is not a Vault save.";
    } catch {
      if (generation === openGeneration) fail(openError, openStatus, "PFX export failed safely. Open the PFX again before retrying.");
      inspected = null;
      openResult.hidden = true;
    } finally {
      if (bytes) bytes.fill(0);
      if (password) password.fill(0);
      if (outputPassword) outputPassword.fill(0);
      if (output) output.fill(0);
      if (openController === controller) openController = null;
      openBusy = false;
      openButton.disabled = !module || !validFile(openFile.files && openFile.files[0], 1 << 20);
    }
  }
  byID("pfx-cert-download").addEventListener("click", () => exportOpened("certificate"));
  byID("pfx-key-download").addEventListener("click", () => exportOpened("key"));

  function invalidateCreate() {
    createGeneration++;
    if (createController) createController.abort();
    createPassword.value = "";
    createConfirm.value = "";
    createError.hidden = true;
    createStatus.textContent = "";
    createButton.disabled = !module || createBusy || !validFile(createCert.files && createCert.files[0], 1 << 20) ||
      !validFile(createKey.files && createKey.files[0], 64 << 10) ||
      !!(createChain.files && createChain.files.length && !validFile(createChain.files[0], 1 << 20));
  }
  for (const field of [createCert, createKey, createChain]) field.addEventListener("change", invalidateCreate);
  for (const field of [createPassword, createConfirm]) field.addEventListener("input", () => {
    if (createController) { createGeneration++; createController.abort(); createStatus.textContent = "Password changed. Start again."; }
  });
  createButton.addEventListener("click", async () => {
    const certificate = createCert.files && createCert.files[0];
    const key = createKey.files && createKey.files[0];
    const chain = createChain.files && createChain.files[0];
    if (!module || createBusy || !validFile(certificate, 1 << 20) || !validFile(key, 64 << 10) || (chain && !validFile(chain, 1 << 20))) return;
    const pfxPassword = createPassword.value;
    const confirmation = createConfirm.value;
    createPassword.value = "";
    createConfirm.value = "";
    if (!newPassword(pfxPassword) || pfxPassword !== confirmation) {
      fail(createError, createStatus, "Choose and confirm a new, random 20–128 character non-space ASCII PFX password.");
      return;
    }
    const generation = createGeneration;
    const controller = new AbortController();
    createController = controller;
    createBusy = true;
    createButton.disabled = true;
    createError.hidden = true;
    createStatus.textContent = "Checking certificate, key match and issuer order locally…";
    let certBytes, keyBytes, chainBytes, passwordBytes, output;
    try {
      certBytes = await read(certificate, 1 << 20);
      keyBytes = await read(key, 64 << 10);
      chainBytes = chain ? await read(chain, 1 << 20) : new Uint8Array();
      if (generation !== createGeneration || certificate !== createCert.files[0] || key !== createKey.files[0] || chain !== (createChain.files && createChain.files[0])) return;
      passwordBytes = encoder.encode(pfxPassword);
      const answer = await rootwellPFXWorker.run(module, "create", [certBytes, keyBytes, chainBytes], passwordBytes, new Uint8Array(), "", controller.signal);
      output = answer && answer.result && answer.result.bytes;
      if (generation !== createGeneration) return;
      if (!answer || answer.schema_version !== "rootwell.browser.pfx.v1" || answer.ok !== true || answer.error !== null ||
          !answer.result || answer.result.format !== "pfx" || !/^rootwell-bundle-[0-9a-f]{32}\.pfx$/.test(answer.result.filename) ||
          !(output instanceof Uint8Array) || output.length < 1 || output.length > 1 << 20 || output[0] !== 0x30) throw new Error("invalid response");
      requestDownload(output, answer.result.filename, "application/x-pkcs12");
      createStatus.textContent = "Password-protected PFX download requested. Store it securely; the browser may keep a copy in Downloads/backups.";
    } catch {
      if (generation === createGeneration) fail(createError, createStatus, "PFX creation refused: invalid/mismatched certificate or key, invalid issuer order, or local processing failure.");
    } finally {
      if (certBytes) certBytes.fill(0);
      if (keyBytes) keyBytes.fill(0);
      if (chainBytes) chainBytes.fill(0);
      if (passwordBytes) passwordBytes.fill(0);
      if (output) output.fill(0);
      if (createController === controller) createController = null;
      createBusy = false;
      createButton.disabled = !module || !validFile(createCert.files && createCert.files[0], 1 << 20) || !validFile(createKey.files && createKey.files[0], 64 << 10);
    }
  });
})();
