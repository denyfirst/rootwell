"use strict";

(function () {
  const fileInput = document.getElementById("private-convert-file");
  const fileState = document.getElementById("private-convert-file-state");
  const inspectButton = document.getElementById("private-convert-inspect");
  const errorBox = document.getElementById("private-convert-error");
  const resultBox = document.getElementById("private-convert-result");
  const summaryBox = document.getElementById("private-convert-summary");
  const passwordInput = document.getElementById("private-convert-password");
  const confirmInput = document.getElementById("private-convert-confirm");
  const downloadButton = document.getElementById("private-convert-download");
  const status = document.getElementById("private-convert-status");
  const encoder = new TextEncoder();
  const fingerprintPattern = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/;
  const formats = new Set(["pkcs8-pem", "pkcs8-der", "pkcs1-pem", "pkcs1-der", "sec1-pem", "sec1-der"]);
  let engine = null;
  let generation = 0;
  let selected = null;
  let inspected = null;
  let busy = false;

  function clearSecrets() {
    passwordInput.value = "";
    confirmInput.value = "";
  }

  function fail(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
    status.textContent = "No private key was downloaded.";
  }

  function validSummary(response) {
    const result = response && response.result;
    return response.schema_version === "rootwell.browser.private-convert.v1" && response.ok === true &&
      response.error === null && result && typeof result === "object" &&
      formats.has(result.input_format) && ["RSA", "ECDSA", "Ed25519"].includes(result.algorithm) &&
      Number.isSafeInteger(result.bits) && result.bits > 0 && result.bits <= 16384 &&
      typeof result.curve === "string" && result.curve.length <= 32 &&
      typeof result.public_fingerprint === "string" && fingerprintPattern.test(result.public_fingerprint);
  }

  function invalidate() {
    generation++;
    selected = null;
    inspected = null;
    resultBox.hidden = true;
    downloadButton.disabled = true;
    errorBox.hidden = true;
    status.textContent = "";
    clearSecrets();
    const files = fileInput.files;
    if (files && files.length === 1 && Number.isSafeInteger(files[0].size) && files[0].size > 0 && files[0].size <= 64 * 1024) {
      selected = files[0];
      fileState.textContent = "One private key selected · " + files[0].size + " bytes";
    } else {
      fileState.textContent = files && files.length ? "Choose one private key no larger than 64 KiB" : "No private key selected";
    }
    inspectButton.disabled = !engine || !selected || busy;
  }

  fileInput.addEventListener("change", invalidate);
  rootwellWorkbenchReady.then(function (ready) {
    if (typeof ready.privateInspect !== "function" || typeof ready.privateExportEncrypted !== "function") {
      fail("Local private-key engine is unavailable.");
      return;
    }
    engine = ready;
    inspectButton.disabled = !selected;
  }, function () { fail("Local private-key engine is unavailable."); });

  inspectButton.addEventListener("click", async function () {
    if (!engine || !selected || busy) return;
    const file = selected;
    const request = generation;
    busy = true;
    inspectButton.disabled = true;
    inspected = null;
    resultBox.hidden = true;
    errorBox.hidden = true;
    let bytes;
    try {
      bytes = new Uint8Array(await file.slice(0, 64 * 1024 + 1).arrayBuffer());
      if (request !== generation || file !== selected) return;
      if (bytes.byteLength !== file.size || bytes.byteLength === 0 || bytes.byteLength > 64 * 1024) throw new Error("invalid source");
      const answer = engine.privateInspect(bytes);
      if (typeof answer !== "string" || answer.length > 2048) throw new Error("invalid response");
      const response = JSON.parse(answer);
      if (!validSummary(response)) throw new Error("invalid key");
      inspected = Object.freeze({ file, fingerprint: response.result.public_fingerprint });
      summaryBox.textContent = response.result.algorithm + " · " + response.result.bits + " bits · " +
        response.result.input_format.toUpperCase() + (response.result.curve ? " · " + response.result.curve : "") +
        " · public-key SHA-256 " + response.result.public_fingerprint;
      status.textContent = "Format identified locally. The key has not been saved or uploaded.";
      resultBox.hidden = false;
      downloadButton.disabled = false;
    } catch {
      if (request === generation) fail("This private key is malformed, encrypted, unsupported, or too large. No key details were shown.");
    } finally {
      clearSecrets();
      if (bytes) bytes.fill(0);
      busy = false;
      inspectButton.disabled = !selected || !engine;
    }
  });

  downloadButton.addEventListener("click", async function () {
    if (!engine || !inspected || busy) return;
    const source = inspected;
    const request = generation;
    errorBox.hidden = true;
    busy = true;
    inspectButton.disabled = true;
    downloadButton.disabled = true;
    status.textContent = "Encrypting locally…";
    let bytes;
    let passwordBytes;
    let output;
    let url;
    try {
      bytes = new Uint8Array(await source.file.slice(0, 64 * 1024 + 1).arrayBuffer());
      if (request !== generation || inspected !== source) return;
      if (bytes.byteLength !== source.file.size || bytes.byteLength === 0 || bytes.byteLength > 64 * 1024) throw new Error("changed source");
      const password = passwordInput.value;
      const confirmation = confirmInput.value;
      clearSecrets();
      if (password !== confirmation || password.length < 20 || password.length > 128 || !/^[!-~]+$/.test(password)) {
        fail("Choose and confirm a new 20–128 character printable password. No key was downloaded.");
        return;
      }
      passwordBytes = encoder.encode(password);
      const response = engine.privateExportEncrypted(bytes, source.fingerprint, passwordBytes);
      if (response && response.result && response.result.bytes instanceof Uint8Array) output = response.result.bytes;
      if (!response || response.schema_version !== "rootwell.browser.private-convert.v1" || response.ok !== true || response.error !== null ||
          !response.result || !output || output.byteLength === 0 || output.byteLength > 96 * 1024 ||
          !/^rootwell-encrypted-key-[0-9a-f]{16}-[0-9a-f]{32}\.pem$/.test(response.result.filename)) {
        throw new Error("invalid export");
      }
      const header = encoder.encode("-----BEGIN ENCRYPTED PRIVATE KEY-----\n");
      if (output.length < header.length + 32 || !header.every(function (byte, index) { return output[index] === byte; })) {
        throw new Error("invalid encrypted output");
      }
      url = URL.createObjectURL(new Blob([output], { type: "application/x-pem-file" }));
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = response.result.filename;
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      status.textContent = "Encrypted-key download requested. Check the browser save location; this is not a Vault save.";
    } catch {
      if (request === generation) {
        inspected = null;
        resultBox.hidden = true;
        fail("Private-key conversion failed safely. No download was requested. Identify the key again before retrying.");
      }
    } finally {
      clearSecrets();
      if (bytes) bytes.fill(0);
      if (passwordBytes) passwordBytes.fill(0);
      if (output) output.fill(0);
      if (url) setTimeout(function () { URL.revokeObjectURL(url); }, 15000);
      busy = false;
      if (request === generation) downloadButton.disabled = !inspected;
      inspectButton.disabled = !selected || !engine;
    }
  });
})();
