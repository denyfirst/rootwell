"use strict";

(function () {
  const fileInput = document.getElementById("private-convert-file");
  const fileState = document.getElementById("private-convert-file-state");
  const inspectButton = document.getElementById("private-convert-inspect");
  const errorBox = document.getElementById("private-convert-error");
  const resultBox = document.getElementById("private-convert-result");
  const summaryBox = document.getElementById("private-convert-summary");
  const inputPasswordInput = document.getElementById("private-convert-input-password");
  const formatInput = document.getElementById("private-convert-format");
  const outputPasswords = document.getElementById("private-convert-output-passwords");
  const plaintextWarning = document.getElementById("private-convert-plaintext-warning");
  const plaintextConfirm = document.getElementById("private-convert-plaintext-confirm");
  const passwordInput = document.getElementById("private-convert-password");
  const confirmInput = document.getElementById("private-convert-confirm");
  const downloadButton = document.getElementById("private-convert-download");
  const status = document.getElementById("private-convert-status");
  const revealButton = document.getElementById("private-reveal-button");
  const revealConfirm = document.getElementById("private-reveal-confirm");
  const revealLabel = document.getElementById("private-reveal-confirm-label");
  const encoder = new TextEncoder();
  const fingerprintPattern = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/;
  const formats = new Set(["pkcs8-pem", "pkcs8-der", "pkcs1-pem", "pkcs1-der", "sec1-pem", "sec1-der", "encrypted-pkcs8-pem", "encrypted-pkcs8-der"]);
  const outputs = new Set(["encrypted-pkcs8-pem", "pkcs8-pem", "pkcs8-der", "pkcs1-pem", "pkcs1-der", "sec1-pem", "sec1-der"]);
  let engine = null;
  let generation = 0;
  let selected = null;
  let inspected = null;
  let busy = false;
  let activeController = null;
  const view = rootwellSecretView.create(document.getElementById("private-reveal-panel"),
    document.getElementById("private-reveal-content"), document.getElementById("private-reveal-hide"),
    function () { cancelPendingChoice(); clearSecrets(); revealConfirm.checked = false; },
    function () { status.textContent = "Private key hidden."; });

  function clearSecrets() {
    inputPasswordInput.value = "";
    passwordInput.value = "";
    confirmInput.value = "";
  }

  function updateFormat() {
    const plaintext = formatInput.value !== "encrypted-pkcs8-pem";
    outputPasswords.hidden = plaintext;
    plaintextWarning.hidden = !plaintext;
    plaintextConfirm.checked = false;
    passwordInput.value = "";
    confirmInput.value = "";
  }

  function cancelPendingChoice() {
    view.hide();
    if (!activeController) return;
    generation++;
    activeController.abort();
    status.textContent = "Choices changed. Start this operation again.";
  }

  formatInput.addEventListener("change", function () { cancelPendingChoice(); updateFormat(); });
  for (const field of [inputPasswordInput, passwordInput, confirmInput]) {
    field.addEventListener("input", cancelPendingChoice);
  }
  plaintextConfirm.addEventListener("change", cancelPendingChoice);
  revealConfirm.addEventListener("change", cancelPendingChoice);

  function fail(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
    status.textContent = "No private key was shown or downloaded.";
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
    view.hide();
    revealConfirm.checked = false;
    revealButton.disabled = true;
    if (activeController) activeController.abort();
    generation++;
    selected = null;
    inspected = null;
    resultBox.hidden = true;
    downloadButton.disabled = true;
    errorBox.hidden = true;
    status.textContent = "";
    clearSecrets();
    formatInput.value = "encrypted-pkcs8-pem";
    updateFormat();
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
    if (!(ready.module instanceof WebAssembly.Module) || !globalThis.rootwellPrivateWorker ||
        typeof globalThis.rootwellPrivateWorker.run !== "function") {
      fail("Local private-key engine is unavailable.");
      return;
    }
    engine = ready.module;
    inspectButton.disabled = !selected;
  }, function () { fail("Local private-key engine is unavailable."); });

  inspectButton.addEventListener("click", async function () {
    if (!engine || !selected || busy) return;
    view.hide();
    revealConfirm.checked = false;
    revealButton.disabled = true;
    const file = selected;
    const request = generation;
    busy = true;
    inspectButton.disabled = true;
    inspected = null;
    resultBox.hidden = true;
    errorBox.hidden = true;
    status.textContent = "Identifying this key locally…";
    let bytes;
    let currentPasswordBytes;
    const controller = new AbortController();
    activeController = controller;
    try {
      bytes = new Uint8Array(await file.slice(0, 64 * 1024 + 1).arrayBuffer());
      if (request !== generation || file !== selected) return;
      if (bytes.byteLength !== file.size || bytes.byteLength === 0 || bytes.byteLength > 64 * 1024) throw new Error("invalid source");
      currentPasswordBytes = encoder.encode(inputPasswordInput.value);
      if (currentPasswordBytes.length > 256) throw new Error("invalid password length");
      const answer = await rootwellPrivateWorker.run(engine, "inspect", bytes, currentPasswordBytes, "", "", new Uint8Array(0), controller.signal);
      if (request !== generation || file !== selected) return;
      if (typeof answer !== "string" || answer.length > 2048) throw new Error("invalid response");
      const response = JSON.parse(answer);
      if (response && response.error === "input-password-required") {
        fail("This key is encrypted. Enter its current password above, then identify it again.");
        return;
      }
      if (!validSummary(response)) throw new Error("invalid key");
      inspected = Object.freeze({ file, fingerprint: response.result.public_fingerprint, encrypted: response.result.input_format.startsWith("encrypted-") });
      revealLabel.hidden = inspected.encrypted;
      for (const option of formatInput.options) {
        option.disabled = option.value.startsWith("pkcs1-") && response.result.algorithm !== "RSA" ||
          option.value.startsWith("sec1-") && response.result.algorithm !== "ECDSA";
      }
      formatInput.value = "encrypted-pkcs8-pem";
      updateFormat();
      const inputLabel = response.result.input_format.startsWith("encrypted-") ?
        "Password-protected PKCS#8 · " + response.result.input_format.slice(-3).toUpperCase() :
        response.result.input_format.toUpperCase();
      summaryBox.textContent = response.result.algorithm + " · " + response.result.bits + " bits · " +
        inputLabel + (response.result.curve ? " · " + response.result.curve : "") +
        " · public-key SHA-256 " + response.result.public_fingerprint;
      status.textContent = "Format identified locally. The key has not been saved or uploaded." +
        (inspected.encrypted ? " Re-enter the current key password before viewing or downloading." : "");
      resultBox.hidden = false;
      downloadButton.disabled = false;
    } catch {
      if (request === generation) fail("This key/password is invalid or unsupported, or local processing failed or timed out. No key details were shown.");
    } finally {
      clearSecrets();
      if (bytes) bytes.fill(0);
      if (currentPasswordBytes) currentPasswordBytes.fill(0);
      if (activeController === controller) activeController = null;
      busy = false;
      revealButton.disabled = !inspected;
      inspectButton.disabled = !selected || !engine;
    }
  });

  downloadButton.addEventListener("click", async function () {
    if (!engine || !inspected || busy) return;
    view.hide();
    revealConfirm.checked = false;
    revealButton.disabled = true;
    const source = inspected;
    const request = generation;
    errorBox.hidden = true;
    busy = true;
    inspectButton.disabled = true;
    downloadButton.disabled = true;
    status.textContent = "Converting locally…";
    let bytes;
    let currentPasswordBytes;
    let passwordBytes;
    let output;
    let url;
    const controller = new AbortController();
    activeController = controller;
    try {
      bytes = new Uint8Array(await source.file.slice(0, 64 * 1024 + 1).arrayBuffer());
      if (request !== generation || inspected !== source) return;
      if (bytes.byteLength !== source.file.size || bytes.byteLength === 0 || bytes.byteLength > 64 * 1024) throw new Error("changed source");
      const format = formatInput.value;
      if (!outputs.has(format) || (format.startsWith("pkcs1-") && formatInput.selectedOptions[0].disabled) ||
          (format.startsWith("sec1-") && formatInput.selectedOptions[0].disabled)) throw new Error("invalid format");
      const currentPassword = inputPasswordInput.value;
      if (source.encrypted && !currentPassword) {
        fail("Enter the current key password again before downloading.");
        return;
      }
      if (!source.encrypted && currentPassword) {
        fail("This input key has no password. Leave the current-password field empty.");
        return;
      }
      currentPasswordBytes = encoder.encode(currentPassword);
      if (currentPasswordBytes.length > 256) throw new Error("invalid password length");
      const password = passwordInput.value;
      const confirmation = confirmInput.value;
      clearSecrets();
      if (format === "encrypted-pkcs8-pem" && (password !== confirmation || password.length < 20 || password.length > 128 || !/^[!-~]+$/.test(password))) {
        fail("Choose and confirm a new 20–128 character printable password. No key was downloaded.");
        return;
      }
      if (source.encrypted && format === "encrypted-pkcs8-pem" && password === currentPassword) {
        fail("Use a new output password, different from this key's current password. No key was downloaded.");
        return;
      }
      if (format !== "encrypted-pkcs8-pem" && (!plaintextConfirm.checked || password || confirmation)) {
        fail("Confirm that you want an unencrypted private-key download. No key was downloaded.");
        return;
      }
      passwordBytes = encoder.encode(format === "encrypted-pkcs8-pem" ? password : "");
      const response = await rootwellPrivateWorker.run(engine, "export", bytes, currentPasswordBytes,
        source.fingerprint, format, passwordBytes, controller.signal);
      if (response && response.result && response.result.bytes instanceof Uint8Array) output = response.result.bytes;
      if (request !== generation || inspected !== source) return;
      if (!response || response.schema_version !== "rootwell.browser.private-convert.v1" || response.ok !== true || response.error !== null ||
          !response.result || !output || output.byteLength === 0 || output.byteLength > 96 * 1024 || response.result.format !== format ||
          !new RegExp("^rootwell-" + (format === "encrypted-pkcs8-pem" ? "encrypted" : "plaintext") + "-key-[0-9a-f]{16}-[0-9a-f]{32}\\." + (format.endsWith("-der") ? "der" : "pem") + "$").test(response.result.filename)) {
        throw new Error("invalid export");
      }
      if (format.endsWith("-pem")) {
        const label = format === "encrypted-pkcs8-pem" ? "ENCRYPTED PRIVATE KEY" : format === "pkcs1-pem" ? "RSA PRIVATE KEY" : format === "sec1-pem" ? "EC PRIVATE KEY" : "PRIVATE KEY";
        const header = encoder.encode("-----BEGIN " + label + "-----\n");
        if (output.length < header.length + 32 || !header.every(function (byte, index) { return output[index] === byte; })) throw new Error("invalid output");
      }
      url = URL.createObjectURL(new Blob([output], { type: format.endsWith("-der") ? "application/octet-stream" : "application/x-pem-file" }));
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = response.result.filename;
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      status.textContent = (format === "encrypted-pkcs8-pem" ? "Encrypted" : "Unencrypted") + " private-key download requested. Check and protect the browser save location; this is not a Vault save.";
    } catch {
      if (request === generation) {
        inspected = null;
        resultBox.hidden = true;
        fail("Private-key conversion failed safely. No download was requested. Identify the key again before retrying.");
      }
    } finally {
      clearSecrets();
      if (bytes) bytes.fill(0);
      if (currentPasswordBytes) currentPasswordBytes.fill(0);
      if (passwordBytes) passwordBytes.fill(0);
      if (output) output.fill(0);
      if (activeController === controller) activeController = null;
      plaintextConfirm.checked = false;
      if (url) setTimeout(function () { URL.revokeObjectURL(url); }, 15000);
      busy = false;
      revealButton.disabled = !inspected;
      downloadButton.disabled = !inspected;
      inspectButton.disabled = !selected || !engine;
    }
  });

  revealButton.addEventListener("click", async function () {
    if (!engine || !inspected || busy) return;
    view.hide();
    const source = inspected;
    const request = generation;
    const currentPassword = inputPasswordInput.value;
    const consent = revealConfirm.checked === true;
    clearSecrets();
    revealConfirm.checked = false;
    if ((source.encrypted && !currentPassword) || (!source.encrypted && (currentPassword || !consent))) {
      fail(source.encrypted ? "Re-enter the current key password before viewing." : "This key has no password. Confirm that you want to show it on screen, and leave the current-password field empty.");
      return;
    }
    let bytes, password, output;
    const controller = new AbortController();
    activeController = controller;
    busy = true;
    inspectButton.disabled = downloadButton.disabled = revealButton.disabled = true;
    errorBox.hidden = true;
    status.textContent = "Rechecking the key locally before showing it…";
    try {
      password = encoder.encode(currentPassword);
      if (password.length > 256) throw new Error("invalid password");
      bytes = new Uint8Array(await source.file.slice(0, 64 * 1024 + 1).arrayBuffer());
      if (request !== generation || inspected !== source) return;
      if (!bytes.length || bytes.length !== source.file.size || bytes.length > 64 * 1024) throw new Error("changed file");
      const response = await rootwellPrivateWorker.run(engine, "export", bytes, password,
        source.fingerprint, "pkcs8-pem", new Uint8Array(), controller.signal);
      output = response && response.result && response.result.bytes;
      if (request !== generation || inspected !== source) return;
      if (!response || response.schema_version !== "rootwell.browser.private-convert.v1" || response.ok !== true || response.error !== null ||
          !response.result || response.result.format !== "pkcs8-pem" ||
          !/^rootwell-plaintext-key-[0-9a-f]{16}-[0-9a-f]{32}\.pem$/.test(response.result.filename)) throw new Error("invalid response");
      view.show(output);
      status.textContent = "Private key visible for 30 seconds. No download was requested.";
    } catch {
      view.hide();
      if (request === generation) fail("The key could not be shown safely. Check its password and identify it again if the file changed.");
    } finally {
      if (bytes) bytes.fill(0);
      if (password) password.fill(0);
      if (output instanceof Uint8Array) output.fill(0);
      clearSecrets();
      if (activeController === controller) activeController = null;
      busy = false;
      revealButton.disabled = downloadButton.disabled = !inspected;
      inspectButton.disabled = !selected || !engine;
    }
  });
})();
