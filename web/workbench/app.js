"use strict";

(function () {
  const tabs = Array.from(document.querySelectorAll("[data-tool]"));
  const panels = {
    inspect: document.getElementById("inspect-panel"),
    explore: document.getElementById("explore-panel"),
    verify: document.getElementById("verify-panel")
  };
  const pagePath = document.getElementById("page-path");
  const engineState = document.getElementById("engine-state");
  const inspectInput = document.getElementById("inspect-file");
  const inspectSelection = document.getElementById("inspect-file-state");
  const inspectStatus = document.getElementById("inspect-status");
  const inspectButton = document.getElementById("inspect-button");
  const inspectError = document.getElementById("inspect-error");
  const inspectResult = document.getElementById("inspect-result");
  const exploreInput = document.getElementById("explore-file");
  const exploreSelection = document.getElementById("explore-file-state");
  const exploreStatus = document.getElementById("explore-status");
  const exploreButton = document.getElementById("explore-button");
  const exploreError = document.getElementById("explore-error");
  const exploreResult = document.getElementById("explore-result");
  const exploreCertificates = document.getElementById("explore-certificates");
  const exportStatus = document.getElementById("export-status");
  const exportError = document.getElementById("export-error");
  const exportBundleButton = document.getElementById("export-bundle-button");
  const verifyHostname = document.getElementById("verify-hostname");
  const verifyTrustFile = document.getElementById("verify-trust-file");
  const verifyRootPin = document.getElementById("verify-root-pin");
  const verifyRootPinStatus = document.getElementById("verify-root-pin-status");
  const verifySimpleMode = document.getElementById("verify-simple-mode");
  const verifyAdvancedMode = document.getElementById("verify-advanced-mode");
  const verifySimpleInputs = document.getElementById("verify-simple-inputs");
  const verifyAdvancedInputs = document.getElementById("verify-advanced-inputs");
  const verifySourceFiles = document.getElementById("verify-source-files");
  const verifyLeafFile = document.getElementById("verify-leaf-file");
  const verifyIntermediatesFile = document.getElementById("verify-intermediates-file");
  const verifyTime = document.getElementById("verify-time");
  const verifyButton = document.getElementById("verify-button");
  const verifyStatus = document.getElementById("verify-status");
  const verifyError = document.getElementById("verify-error");
  const verifyResult = document.getElementById("verify-result");
  const verifyChain = document.getElementById("verify-chain");
  const verifyExportButton = document.getElementById("verify-export-button");
  const verifyExportStatus = document.getElementById("verify-export-status");
  const verifyExportError = document.getElementById("verify-export-error");

  let engine = null;
  let selectedInspectFile = null;
  let selectedExploreFiles = null;
  let inspecting = false;
  let exploring = false;
  let exporting = false;
  let verifying = false;
  let exportingVerified = false;
  let verifyGeneration = 0;
  let currentVerifySnapshot = null;
  let currentExploreEntries = null;
  const selectedBundleFingerprints = new Set();
  const pendingDownloadURLs = new Set();
  const maxExploreFiles = 8;
  const maxExploreCertificates = 64;
  const maxExploreMetadataBytes = 1 << 20;
  const metadataEncoder = new TextEncoder();
  const exportChoices = Object.freeze({
    "pem:pem": Object.freeze({ encoding: "pem", extension: "pem", label: "PEM text (.pem)" }),
    "pem:crt": Object.freeze({ encoding: "pem", extension: "crt", label: "PEM text (.crt)" }),
    "pem:cer": Object.freeze({ encoding: "pem", extension: "cer", label: "PEM text (.cer)" }),
    "der:der": Object.freeze({ encoding: "der", extension: "der", label: "DER binary (.der)" }),
    "der:crt": Object.freeze({ encoding: "der", extension: "crt", label: "DER binary (.crt)" }),
    "der:cer": Object.freeze({ encoding: "der", extension: "cer", label: "DER binary (.cer)" })
  });

  function selectTool(name) {
    tabs.forEach(function (tab) {
      const selected = tab.dataset.tool === name;
      tab.setAttribute("aria-selected", selected ? "true" : "false");
    });
    Object.keys(panels).forEach(function (panelName) {
      panels[panelName].hidden = panelName !== name;
    });
    pagePath.textContent = name === "verify" ? "Verify" : name === "explore" ? "Explore" : "Inspect";
  }

  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      selectTool(tab.dataset.tool);
    });
  });

  function formatSize(size) {
    if (size < 1024) return size + " B";
    if (size < 1024 * 1024) return (size / 1024).toFixed(1) + " KiB";
    return (size / (1024 * 1024)).toFixed(1) + " MiB";
  }

  function displayFileName(file) {
    const name = typeof file.name === "string" && file.name ? file.name : "unnamed file";
    const characters = Array.from(name.replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g, "�"));
    return characters.length > 120 ? characters.slice(0, 120).join("") + "…" : characters.join("");
  }

  function selectedFileLabel(file, index) {
    return "File " + (index + 1) + " (" + displayFileName(file) + ")";
  }

  function updateInspectControls() {
    inspectButton.disabled = inspecting || engine === null || selectedInspectFile === null;
  }

  function updateExploreControls() {
    exploreButton.disabled = exploring || exporting || engine === null || selectedExploreFiles === null;
    exportBundleButton.disabled = exploring || exporting || engine === null || currentExploreEntries === null || selectedBundleFingerprints.size === 0;
    exploreCertificates.querySelectorAll("button, select, input").forEach(function (control) {
      control.disabled = exploring || exporting;
    });
  }

  function updateVerifyControls() {
    const trust = verifyTrustFile.files && verifyTrustFile.files.length === 1;
    const hostname = verifyHostname.value && verifyHostname.value.trim();
    const sources = verifySourceFiles.files && verifySourceFiles.files.length >= 1 && verifySourceFiles.files.length <= maxExploreFiles;
    const leaf = verifyLeafFile.files && verifyLeafFile.files.length === 1;
    verifyButton.disabled = verifying || exportingVerified || !engine || !trust || !hostname || !(verifySimpleMode.checked ? sources : leaf);
    verifyExportButton.disabled = verifying || exportingVerified || !engine || currentVerifySnapshot === null;
  }

  function invalidateVerify() {
    verifyGeneration++;
    currentVerifySnapshot = null;
    verifyResult.hidden = true;
    verifyChain.replaceChildren();
    verifyError.hidden = true;
    verifyExportError.hidden = true;
    verifyExportStatus.textContent = "";
    updateVerifyControls();
  }

  for (const input of [verifyHostname, verifyRootPin, verifyTrustFile, verifySourceFiles, verifyLeafFile, verifyIntermediatesFile, verifyTime]) {
    input.addEventListener(input === verifyHostname || input === verifyRootPin || input === verifyTime ? "input" : "change", invalidateVerify);
  }
  for (const mode of [verifySimpleMode, verifyAdvancedMode]) {
    mode.addEventListener("change", function () {
      verifySimpleInputs.hidden = !verifySimpleMode.checked;
      verifyAdvancedInputs.hidden = !verifyAdvancedMode.checked;
      invalidateVerify();
    });
  }

  function setInspectFile(file) {
    selectedInspectFile = file;
    inspectResult.hidden = true;
    inspectError.hidden = true;
    inspectSelection.textContent = file ? file.name + " · " + formatSize(file.size) : "No file selected";
    if (file && engine) {
      inspectStatus.textContent = "Ready for local inspection";
    }
    updateInspectControls();
  }

  inspectInput.addEventListener("change", function () {
    const file = inspectInput.files && inspectInput.files.length === 1 ? inspectInput.files[0] : null;
    setInspectFile(file);
  });

  function setExploreFiles(files) {
    selectedExploreFiles = null;
    currentExploreEntries = null;
    selectedBundleFingerprints.clear();
    exploreResult.hidden = true;
    exploreCertificates.replaceChildren();
    exploreError.hidden = true;
    exportError.hidden = true;
    if (files.length > maxExploreFiles) {
      exploreSelection.textContent = "Choose at most 8 public certificate files";
      exploreStatus.textContent = "Too many files selected";
    } else if (files.length === 0) {
      exploreSelection.textContent = "No files selected";
      exploreStatus.textContent = "Choose public certificate files to explore";
    } else {
      let totalBytes = 0;
      for (const file of files) {
        if (!Number.isSafeInteger(file.size) || file.size < 0) {
          exploreSelection.textContent = "The selected file size is invalid";
          exploreStatus.textContent = "Choose public certificate files to explore";
          updateExploreControls();
          return;
        }
        totalBytes += file.size;
      }
      if (totalBytes > (engine ? engine.maxBytes : 16 * 1024 * 1024)) {
        exploreSelection.textContent = "Selected files exceed the 16 MiB combined limit";
        exploreStatus.textContent = "Selected files exceed the combined limit";
      } else {
        selectedExploreFiles = Object.freeze(files.slice());
        exploreSelection.textContent = files.length === 1 ? displayFileName(files[0]) + " · " + formatSize(totalBytes) :
          files.length + " files · " + formatSize(totalBytes) + " total";
        if (engine) exploreStatus.textContent = "Ready for local exploration";
      }
    }
    updateExploreControls();
  }

  exploreInput.addEventListener("change", function () {
    setExploreFiles(exploreInput.files ? Array.from(exploreInput.files) : []);
  });

  document.querySelectorAll("[data-drop-target]").forEach(function (zone) {
    ["dragenter", "dragover"].forEach(function (eventName) {
      zone.addEventListener(eventName, function (event) {
        event.preventDefault();
        zone.classList.add("is-dragging");
      });
    });
    ["dragleave", "drop"].forEach(function (eventName) {
      zone.addEventListener(eventName, function (event) {
        event.preventDefault();
        zone.classList.remove("is-dragging");
      });
    });
    zone.addEventListener("drop", function (event) {
      const isExplore = zone.dataset.dropTarget === "explore-file";
      if (isExplore) {
        setExploreFiles(event.dataTransfer ? Array.from(event.dataTransfer.files) : []);
        return;
      }
      if (!event.dataTransfer || event.dataTransfer.files.length !== 1) {
        setInspectFile(null);
        inspectSelection.textContent = "Choose exactly one file";
        return;
      }
      setInspectFile(event.dataTransfer.files[0]);
    });
  });

  document.querySelectorAll("[data-show-sample]").forEach(function (button) {
    button.addEventListener("click", function () {
      const result = document.getElementById(button.dataset.showSample);
      const opening = result.hidden;
      result.hidden = !opening;
      button.textContent = opening ? "Hide sample result" : "Show sample result";
      if (opening) result.scrollIntoView({ block: "nearest" });
    });
  });

  function engineUnavailable() {
    engineState.textContent = "Unavailable · build assets required";
    inspectStatus.textContent = "Local inspection engine is unavailable";
    exploreStatus.textContent = "Local exploration engine is unavailable";
    verifyStatus.textContent = "Local verification engine is unavailable";
    engine = null;
    updateInspectControls();
    updateExploreControls();
    updateVerifyControls();
  }

  if (!globalThis.rootwellWorkbenchReady || typeof globalThis.rootwellWorkbenchReady.then !== "function") {
    engineUnavailable();
  } else {
    globalThis.rootwellWorkbenchReady.then(function (readyEngine) {
      if (!readyEngine || typeof readyEngine.inspect !== "function" || typeof readyEngine.explore !== "function" ||
          typeof readyEngine.exportPublic !== "function" || typeof readyEngine.analyze !== "function" ||
          typeof readyEngine.exportBundle !== "function" ||
          typeof readyEngine.verifySimple !== "function" || typeof readyEngine.verifyExplicit !== "function" ||
          typeof readyEngine.exportVerifiedSimple !== "function" || typeof readyEngine.exportVerifiedExplicit !== "function" ||
          !Number.isSafeInteger(readyEngine.maxBytes) || readyEngine.maxBytes <= 0) {
        engineUnavailable();
        return;
      }
      engine = readyEngine;
      engineState.textContent = "Ready · Go WebAssembly";
      inspectStatus.textContent = selectedInspectFile ? "Ready for local inspection" : "Choose one certificate to inspect";
      exploreStatus.textContent = selectedExploreFiles ? "Ready for local exploration" : "Choose public certificate files to explore";
      updateInspectControls();
      updateExploreControls();
      updateVerifyControls();
    }, engineUnavailable);
  }

  function validStringArray(value) {
    return Array.isArray(value) && value.every(function (item) { return typeof item === "string"; });
  }

  function validInspection(documentValue) {
    if (!documentValue || documentValue.schema_version !== "rootwell.inspect.x509.v1" ||
        documentValue.object_type !== "x509-certificate" ||
        typeof documentValue.encoding !== "string" ||
        typeof documentValue.subject !== "string" ||
        typeof documentValue.issuer !== "string" ||
        typeof documentValue.serial !== "string" ||
        !documentValue.validity || typeof documentValue.validity.not_before !== "string" ||
        typeof documentValue.validity.not_after !== "string" ||
        !documentValue.time_window || typeof documentValue.time_window.status !== "string" ||
        typeof documentValue.time_window.evaluated_at !== "string" ||
        !documentValue.public_key || typeof documentValue.public_key.algorithm !== "string" ||
        !Number.isSafeInteger(documentValue.public_key.bits) ||
        typeof documentValue.public_key.curve !== "string" ||
        typeof documentValue.signature_algorithm !== "string" ||
        typeof documentValue.signature_algorithm !== "string" ||
        typeof documentValue.subject_key_id !== "string" ||
        typeof documentValue.authority_key_id !== "string" ||
        !documentValue.basic_constraints || typeof documentValue.basic_constraints.present !== "boolean" ||
        typeof documentValue.basic_constraints.is_ca !== "boolean" ||
        !documentValue.subject_alternative_names || !documentValue.fingerprints ||
        typeof documentValue.fingerprints.sha256 !== "string") {
      return false;
    }
    const timeWindow = documentValue.time_window;
    const allowedStatuses = ["within-validity-window", "not-yet-valid", "expired", "invalid-range"];
    const relativeValues = [timeWindow.seconds_until_start, timeWindow.seconds_until_expiry, timeWindow.seconds_since_expiry];
    if (!allowedStatuses.includes(timeWindow.status) ||
        !relativeValues.every(function (value) { return value === null || (Number.isSafeInteger(value) && value >= 0); }) ||
        !(documentValue.basic_constraints.max_path_length === null ||
          (Number.isSafeInteger(documentValue.basic_constraints.max_path_length) && documentValue.basic_constraints.max_path_length >= 0))) {
      return false;
    }
    const expectedRelativeIndex = {
      "not-yet-valid": 0,
      "within-validity-window": 1,
      "expired": 2
    }[timeWindow.status];
    if (timeWindow.status === "invalid-range") {
      if (relativeValues.some(function (value) { return value !== null; })) return false;
    } else if (relativeValues.some(function (value, index) {
      return index === expectedRelativeIndex ? value === null : value !== null;
    })) {
      return false;
    }
    return validStringArray(documentValue.key_usage) &&
      validStringArray(documentValue.extended_key_usage) &&
      validStringArray(documentValue.unknown_extended_key_usage) &&
      validStringArray(documentValue.critical_extensions) &&
      validStringArray(documentValue.unhandled_critical_extensions) &&
      validStringArray(documentValue.subject_alternative_names.dns) &&
      validStringArray(documentValue.subject_alternative_names.email) &&
      validStringArray(documentValue.subject_alternative_names.ip) &&
      validStringArray(documentValue.subject_alternative_names.uri);
  }

  function text(id, value) {
    document.getElementById(id).textContent = value;
  }

  function list(values) {
    return values.length ? values.join("\n") : "None";
  }

  function publicKeyLabel(publicKey) {
    const details = [];
    if (publicKey.curve) details.push(publicKey.curve);
    if (publicKey.bits > 0) details.push(publicKey.bits + " bit");
    return publicKey.algorithm + (details.length ? " · " + details.join(" · ") : "");
  }

  function timeWindowLabel(timeWindow) {
    if (timeWindow.status === "within-validity-window" && Number.isSafeInteger(timeWindow.seconds_until_expiry)) {
      return Math.floor(timeWindow.seconds_until_expiry / 86400) + " whole days remain";
    }
    if (timeWindow.status === "not-yet-valid" && Number.isSafeInteger(timeWindow.seconds_until_start)) {
      return "Starts in " + Math.floor(timeWindow.seconds_until_start / 86400) + " whole days";
    }
    if (timeWindow.status === "expired" && Number.isSafeInteger(timeWindow.seconds_since_expiry)) {
      return "Expired " + Math.floor(timeWindow.seconds_since_expiry / 86400) + " whole days ago";
    }
    return "Invalid validity range";
  }

  function basicConstraintsLabel(constraints) {
    if (!constraints.present) return "Not present";
    let value = constraints.is_ca ? "CA certificate" : "End-entity certificate";
    if (Number.isSafeInteger(constraints.max_path_length)) value += " · path length " + constraints.max_path_length;
    return value;
  }

  function renderInspection(result) {
    text("inspect-result-subject", result.subject || "Subject not present");
    text("inspect-result-fingerprint", "SHA256 " + result.fingerprints.sha256);
    text("inspect-result-encoding", result.encoding.toUpperCase());
    text("inspect-result-public-key", publicKeyLabel(result.public_key));
    text("inspect-result-signature", "Signature: " + result.signature_algorithm);
    text("inspect-result-relative-time", timeWindowLabel(result.time_window));
    text("inspect-result-not-after", result.validity.not_after);
    text("inspect-detail-subject", result.subject || "Not present");
    text("inspect-detail-issuer", result.issuer || "Not present");
    text("inspect-detail-serial", result.serial || "Not present");
    text("inspect-detail-not-before", result.validity.not_before);
    text("inspect-detail-not-after", result.validity.not_after);
    text("inspect-detail-dns", list(result.subject_alternative_names.dns));
    text("inspect-detail-other-names", list(
      result.subject_alternative_names.email.map(function (value) { return "Email: " + value; })
        .concat(result.subject_alternative_names.ip.map(function (value) { return "IP: " + value; }))
        .concat(result.subject_alternative_names.uri.map(function (value) { return "URI: " + value; }))
    ));
    text("inspect-detail-key-usage", list(result.key_usage));
    text("inspect-detail-extended-usage", list(result.extended_key_usage.concat(result.unknown_extended_key_usage)));
    text("inspect-detail-basic-constraints", basicConstraintsLabel(result.basic_constraints));

    const status = document.getElementById("inspect-result-status");
    status.className = "stamp";
    if (result.time_window.status === "within-validity-window") status.classList.add("stamp-good");
    else status.classList.add("stamp-warn");
    status.textContent = result.time_window.status.replaceAll("-", " ");
    inspectResult.hidden = false;
    inspectResult.scrollIntoView({ block: "nearest" });
  }

  function showFailure(message) {
    inspectResult.hidden = true;
    inspectError.textContent = message;
    inspectError.hidden = false;
  }

  const failureMessages = Object.freeze({
    "empty-input": "Choose one non-empty certificate.",
    "input-too-large": "The certificate exceeds the 16 MiB limit.",
    "unsupported-encoding": "Only one PEM or DER X.509 certificate is supported.",
    "trailing-data": "Choose exactly one complete certificate with no trailing data.",
    "metadata-limit": "The certificate metadata exceeds the inspection limit.",
    "invalid-certificate": "The file is not a valid X.509 certificate.",
    "invalid-browser-request": "The browser bridge rejected the request.",
    "internal-failure": "Inspection could not be completed safely."
  });

  inspectButton.addEventListener("click", async function () {
    if (!engine || !selectedInspectFile || inspecting) return;
    if (selectedInspectFile.size > engine.maxBytes) {
      showFailure("The certificate exceeds the 16 MiB limit.");
      return;
    }

    inspecting = true;
    inspectError.hidden = true;
    inspectResult.hidden = true;
    inspectStatus.textContent = "Inspecting locally · no certificate upload";
    updateInspectControls();

    let bytes = null;
    try {
      const buffer = await selectedInspectFile.arrayBuffer();
      bytes = new Uint8Array(buffer);
      if (bytes.byteLength !== selectedInspectFile.size || bytes.byteLength > engine.maxBytes) {
        showFailure("The selected file changed or exceeds the inspection limit.");
        return;
      }
      const rawResponse = engine.inspect(bytes);
      if (typeof rawResponse !== "string" || rawResponse.length > 4 * 1024 * 1024) {
        showFailure("The local inspection engine returned an invalid response.");
        return;
      }
      const response = JSON.parse(rawResponse);
      if (!response || response.schema_version !== "rootwell.browser.inspect.v1" || typeof response.ok !== "boolean") {
        showFailure("The local inspection engine returned an invalid response.");
        return;
      }
      if (!response.ok) {
        const failure = response.error;
        const fixedMessage = failure && typeof failure.code === "string" && Object.hasOwn(failureMessages, failure.code) ? failureMessages[failure.code] : null;
        if (response.result !== null || !fixedMessage || failure.message !== fixedMessage) {
          showFailure("Inspection failed safely.");
          return;
        }
        showFailure(fixedMessage);
        return;
      }
      if (response.error !== null || !validInspection(response.result)) {
        showFailure("The local inspection engine returned an invalid response.");
        return;
      }
      renderInspection(response.result);
    } catch {
      showFailure("Inspection failed safely. The selected file was not uploaded.");
    } finally {
      if (bytes) bytes.fill(0);
      inspecting = false;
      inspectStatus.textContent = "Local inspection finished · no certificate upload";
      updateInspectControls();
    }
  });

  const exploreFailureMessages = Object.freeze({
    "empty-input": "Choose one non-empty public certificate file.",
    "input-too-large": "The file exceeds the 16 MiB limit.",
    "certificate-count-limit": "The bundle exceeds 64 certificates.",
    "duplicate-certificate": "The bundle contains a duplicate certificate.",
    "metadata-limit": "Certificate metadata exceeds the display limit.",
    "unsupported-public-bundle": "Only public PEM certificate blocks or one DER certificate are supported.",
    "invalid-certificate": "The file contains an invalid X.509 certificate.",
    "invalid-browser-request": "The browser bridge rejected the request.",
    "internal-failure": "Bundle exploration could not be completed safely."
  });

  function validExploreCertificate(certificate) {
    return certificate && (certificate.encoding === "pem" || certificate.encoding === "der") &&
      typeof certificate.subject === "string" && typeof certificate.issuer === "string" &&
      typeof certificate.is_ca === "boolean" && typeof certificate.not_after === "string" &&
      /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(certificate.sha256);
  }

  function validExploreResult(result) {
    return result && Number.isSafeInteger(result.count) && result.count >= 1 && result.count <= 64 &&
      result.verification === "not-performed" && result.trust_anchor === "not-selected" &&
      Array.isArray(result.certificates) && result.certificates.length === result.count &&
      result.certificates.every(validExploreCertificate);
  }

  function validChainResult(response, entries) {
    if (!response || response.schema_version !== "rootwell.browser.chain.v1" || response.ok !== true ||
        response.error !== "" || !response.result || response.result.verification !== "not-performed" ||
        response.result.trust_anchor !== "not-selected" || !Array.isArray(response.result.certificates) ||
        response.result.certificates.length !== entries.length) return false;
    return response.result.certificates.every(function (certificate, index) {
      return certificate && certificate.sha256 === entries[index].certificate.sha256 &&
        typeof certificate.self_signed === "boolean" && Array.isArray(certificate.parents) &&
        certificate.parents.every(function (parent, position) {
          return Number.isSafeInteger(parent) && parent >= 0 && parent < entries.length && parent !== index &&
            (position === 0 || parent > certificate.parents[position - 1]);
        });
    });
  }

  function bundleDetail(listElement, label, value) {
    const row = document.createElement("div");
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = label;
    description.textContent = value;
    row.append(term, description);
    listElement.append(row);
  }

  function exportAction(file, fingerprint, index) {
    const controls = document.createElement("div");
    controls.className = "bundle-actions";
    const choice = document.createElement("select");
    choice.setAttribute("aria-label", "Encoding and file extension for certificate " + (index + 1));
    for (const [value, option] of Object.entries(exportChoices)) {
      const element = document.createElement("option");
      element.value = value;
      element.textContent = option.label;
      choice.append(element);
    }
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Download certificate";
    button.setAttribute("aria-label", "Download certificate " + (index + 1) + " using the selected encoding and extension");
    button.addEventListener("click", function () {
      if (!Object.hasOwn(exportChoices, choice.value)) {
        showExportFailure("Choose a supported encoding and file extension.");
        return;
      }
      const selected = exportChoices[choice.value];
      void exportCertificate(file, fingerprint, selected.encoding, selected.extension);
    });
    controls.append(choice, button);
    return controls;
  }

  function renderExplore(entries, chain) {
    const cards = entries.map(function (entry, index) {
      const certificate = entry.certificate;
      const item = document.createElement("li");
      const heading = document.createElement("div");
      heading.className = "bundle-card-head";
      const number = document.createElement("span");
      number.textContent = String(index + 1).padStart(2, "0");
      const title = document.createElement("strong");
      title.textContent = certificate.subject || "Subject not present";
      heading.append(number, title);
      const details = document.createElement("dl");
      bundleDetail(details, "Source file", displayFileName(entry.file));
      bundleDetail(details, "Issuer", certificate.issuer || "Not present");
      bundleDetail(details, "CA flag", certificate.is_ca ? "Yes · not automatically trusted" : "No");
      bundleDetail(details, "Expires", certificate.not_after);
      bundleDetail(details, "Encoding", certificate.encoding.toUpperCase());
      bundleDetail(details, "SHA-256", certificate.sha256);
      const relation = chain.certificates[index];
      const issuerHint = relation.parents.length === 0 ?
        (relation.self_signed ? "Self-signed CA candidate · not automatically trusted" : "No matching issuer in these files") :
        relation.parents.map(function (parent) { return "certificate #" + (parent + 1); }).join(", ") +
          " · issuer signature matches, not a trust verdict";
      bundleDetail(details, "Possible issuer", issuerHint);
      const selection = document.createElement("label");
      selection.className = "bundle-select";
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.setAttribute("aria-label", "Include certificate " + (index + 1) + " in public PEM bundle");
      checkbox.addEventListener("change", function () {
        if (currentExploreEntries !== entries) return;
        if (checkbox.checked) selectedBundleFingerprints.add(certificate.sha256);
        else selectedBundleFingerprints.delete(certificate.sha256);
        updateExploreControls();
      });
      const selectionText = document.createElement("span");
      selectionText.textContent = "Include in public PEM bundle";
      selection.append(checkbox, selectionText);
      item.append(heading, details, selection, exportAction(entry.file, certificate.sha256, index));
      return item;
    });
    exploreCertificates.replaceChildren(...cards);
    currentExploreEntries = entries;
    selectedBundleFingerprints.clear();
    updateExploreControls();
    exportError.hidden = true;
    exportStatus.textContent = "Choose the certificate encoding and filename extension, then download. A .crt or .cer name can contain PEM or DER; Rootwell does not write directly to disk.";
    text("explore-result-count", entries.length + (entries.length === 1 ? " certificate found" : " certificates found"));
    exploreResult.hidden = false;
    exploreResult.scrollIntoView({ block: "nearest" });
  }

  function showExploreFailure(message) {
    currentExploreEntries = null;
    selectedBundleFingerprints.clear();
    exploreResult.hidden = true;
    exploreCertificates.replaceChildren();
    exploreError.textContent = message;
    exploreError.hidden = false;
    updateExploreControls();
  }

  const exportFailureMessages = Object.freeze({
    "invalid-browser-request": "The local export request was rejected.",
    "input-too-large": "The file exceeds the 16 MiB limit.",
    "invalid-public-source": "The selected file is no longer a valid public certificate bundle. Explore it again.",
    "certificate-not-found": "The selected certificate was not found in this file. Explore it again.",
    "internal-failure": "The local certificate export could not be completed safely."
  });

  function showExportFailure(message) {
    exportStatus.textContent = "No download was requested.";
    exportError.textContent = message;
    exportError.hidden = false;
  }

  function validateExportResponse(response, fingerprint, format) {
    if (!response || response.schema_version !== "rootwell.browser.export.v1" || typeof response.ok !== "boolean") return null;
    if (!response.ok) {
      if (response.result !== null || typeof response.error !== "string" || !Object.hasOwn(exportFailureMessages, response.error)) return null;
      return exportFailureMessages[response.error];
    }
    const result = response.result;
    const fingerprintPrefix = fingerprint.replaceAll(":", "").slice(0, 16).toLowerCase();
    const expectedName = new RegExp("^rootwell-public-" + fingerprintPrefix + "-[0-9a-f]{32}\\." + format + "$");
    if (response.error !== null || !result || result.encoding !== format || result.fingerprint !== fingerprint ||
        typeof result.filename !== "string" || !expectedName.test(result.filename) ||
        !(result.bytes instanceof Uint8Array) || result.bytes.byteLength === 0 || result.bytes.byteLength > engine.maxBytes) return null;
    return result;
  }

  const bundleExportFailureMessages = Object.freeze({
    "invalid-browser-request": "Choose public certificates from the current Explore result.",
    "invalid-public-source": "A selected source is no longer a valid public certificate collection. Explore again.",
    "changed-public-source": "The selected files changed since Explore. Explore again before downloading.",
    "input-too-large": "The public bundle would exceed the 16 MiB limit.",
    "internal-failure": "The local bundle export could not be completed safely."
  });

  function validateBundleExportResponse(response, selected) {
    if (!response || response.schema_version !== "rootwell.browser.bundle-export.v1" || typeof response.ok !== "boolean") return null;
    if (!response.ok) {
      if (response.result !== null || !Object.hasOwn(bundleExportFailureMessages, response.error)) return null;
      return bundleExportFailureMessages[response.error];
    }
    const result = response.result;
    if (response.error !== null || !result || !Array.isArray(result.fingerprints) ||
        result.fingerprints.length !== selected.length ||
        !result.fingerprints.every(function (fingerprint, index) { return fingerprint === selected[index]; }) ||
        typeof result.filename !== "string" || !/^rootwell-public-bundle-[0-9a-f]{32}\.pem$/.test(result.filename) ||
        !(result.bytes instanceof Uint8Array) || result.bytes.byteLength === 0 || result.bytes.byteLength > engine.maxBytes) return null;
    return result;
  }

  function requestBrowserDownload(bytes, filename) {
    const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.rel = "noopener";
    try {
      document.body.append(anchor);
      anchor.click();
      pendingDownloadURLs.add(url);
      if (pendingDownloadURLs.size > 4) {
        const oldest = pendingDownloadURLs.values().next().value;
        pendingDownloadURLs.delete(oldest);
        URL.revokeObjectURL(oldest);
      }
      setTimeout(function () {
        if (pendingDownloadURLs.delete(url)) URL.revokeObjectURL(url);
      }, 30000);
    } catch (error) {
      URL.revokeObjectURL(url);
      throw error;
    } finally {
      anchor.remove();
    }
  }

  async function exportCertificate(file, fingerprint, format, extension) {
    if (!engine || !selectedExploreFiles || !selectedExploreFiles.includes(file) || exporting || exploring) return;
    if (!Object.hasOwn(exportChoices, format + ":" + extension)) {
      showExportFailure("Choose a supported encoding and file extension.");
      return;
    }
    const files = selectedExploreFiles;
    if (file.size > engine.maxBytes) {
      showExportFailure(exportFailureMessages["input-too-large"]);
      return;
    }
    exporting = true;
    exportError.hidden = true;
    exportStatus.textContent = "Preparing this public certificate locally…";
    updateExploreControls();
    let input = null;
    let output = null;
    try {
      input = new Uint8Array(await file.arrayBuffer());
      if (selectedExploreFiles !== files) return;
      if (input.byteLength !== file.size || input.byteLength > engine.maxBytes) {
        showExportFailure("The selected file changed or exceeds the export limit.");
        return;
      }
      const response = engine.exportPublic(input, fingerprint, format);
      const validated = validateExportResponse(response, fingerprint, format);
      if (typeof validated === "string") {
        showExportFailure(validated);
        return;
      }
      if (!validated) {
        showExportFailure("The local export engine returned an invalid response.");
        return;
      }
      output = validated.bytes;
      const reparsed = JSON.parse(engine.explore(output));
      if (!reparsed.ok || !validExploreResult(reparsed.result) || reparsed.result.count !== 1 ||
          reparsed.result.certificates[0].sha256 !== fingerprint || reparsed.result.certificates[0].encoding !== format) {
        showExportFailure("The exported certificate did not match the selected card.");
        return;
      }
      const downloadName = validated.filename.slice(0, -format.length) + extension;
      requestBrowserDownload(output, downloadName);
      exportStatus.textContent = "Browser download requested. Check the browser's save location; Rootwell did not write to disk.";
    } catch {
      if (selectedExploreFiles === files) showExportFailure("Certificate export failed safely. No upload was made.");
    } finally {
      if (input) input.fill(0);
      if (output) output.fill(0);
      exporting = false;
      updateExploreControls();
    }
  }

  exportBundleButton.addEventListener("click", function () { void exportPublicBundle(); });

  async function exportPublicBundle() {
    if (!engine || !selectedExploreFiles || !currentExploreEntries || selectedBundleFingerprints.size === 0 || exporting || exploring) return;
    const files = selectedExploreFiles;
    const entries = currentExploreEntries;
    const expected = entries.map(function (entry) { return entry.certificate.sha256; });
    const selected = expected.filter(function (fingerprint) { return selectedBundleFingerprints.has(fingerprint); });
    if (selected.length === 0) return;
    exporting = true;
    exportError.hidden = true;
    exportStatus.textContent = "Preparing the selected public PEM bundle locally…";
    updateExploreControls();
    const inputs = [];
    let output = null;
    try {
      let remainingBytes = engine.maxBytes;
      for (const file of files) {
        if (selectedExploreFiles !== files || currentExploreEntries !== entries) return;
        if (file.size > remainingBytes) {
          showExportFailure("The selected files changed or exceed the combined limit.");
          return;
        }
        const bytes = new Uint8Array(await file.arrayBuffer());
        inputs.push(bytes);
        if (bytes.byteLength !== file.size || bytes.byteLength > remainingBytes) {
          showExportFailure("The selected files changed or exceed the combined limit.");
          return;
        }
        remainingBytes -= bytes.byteLength;
      }
      if (selectedExploreFiles !== files || currentExploreEntries !== entries) return;
      const validated = validateBundleExportResponse(engine.exportBundle(inputs, expected, selected), selected);
      if (typeof validated === "string") {
        showExportFailure(validated);
        return;
      }
      if (!validated) {
        showExportFailure("The local bundle export engine returned an invalid response.");
        return;
      }
      output = validated.bytes;
      const reparsed = JSON.parse(engine.explore(output));
      if (!reparsed.ok || !validExploreResult(reparsed.result) || reparsed.result.count !== selected.length ||
          !reparsed.result.certificates.every(function (certificate, index) {
            return certificate.sha256 === selected[index] && certificate.encoding === "pem";
          })) {
        showExportFailure("The exported public bundle did not match the selected certificates.");
        return;
      }
      if (selectedExploreFiles !== files || currentExploreEntries !== entries) return;
      requestBrowserDownload(output, validated.filename);
      exportStatus.textContent = "Browser download requested for the public PEM bundle. Rootwell did not write to disk or verify a chain.";
    } catch {
      if (selectedExploreFiles === files) showExportFailure("Public bundle export failed safely. No upload was made.");
    } finally {
      for (const bytes of inputs) bytes.fill(0);
      if (output) output.fill(0);
      exporting = false;
      updateExploreControls();
    }
  }

  const verifyFailureMessages = Object.freeze({
    "invalid-browser-request": "Choose valid public files, a hostname, and a separate trust file.",
    "input-too-large": "The selected verification files exceed the 16 MiB combined limit.",
    "invalid-time": "Enter an RFC 3339 evaluation time, for example 2026-09-25T09:00:00Z.",
    "invalid-hostname": "Enter a valid ASCII TLS server hostname without a wildcard.",
    "invalid-root-pin": "Enter the complete root SHA-256 fingerprint: 64 hex digits or 32 colon-separated bytes.",
    "root-pin-mismatch": "The verified path ends at a different root than the expected fingerprint. No verified result was produced.",
    "invalid-public-source": "One of the CA files is not a strict public certificate or bundle.",
    "duplicate-certificate": "A certificate appears more than once in the CA files or verification bundles.",
    "missing-leaf": "No end-entity certificate was found in the CA files.",
    "ambiguous-leaf": "More than one end-entity certificate was found. Use Advanced to choose the leaf.",
    "invalid-leaf": "The selected leaf is not one complete public end-entity certificate.",
    "invalid-trust-bundle": "The separately selected trust file must contain self-signed CA certificates in PEM form.",
    "invalid-intermediates": "The intermediate file must contain non-self-signed CA certificates in PEM form.",
    "disallowed-algorithm": "A certificate in the path uses a disallowed signature or public key.",
    "hostname-mismatch": "The certificate does not match the requested hostname.",
    "unknown-authority": "No path reaches the separately selected trust anchor.",
    "expired": "A certificate in the path has expired at the evaluation time.",
    "not-yet-valid": "A certificate in the path is not yet valid at the evaluation time.",
    "incompatible-usage": "The path is not valid for TLS server use.",
    "unhandled-critical-extension": "A certificate has an unsupported critical extension.",
    "constraint-failure": "The certificate path violates CA or name constraints.",
    "verification-failed": "TLS verification failed under the current policy.",
    "internal-failure": "Local verification could not be completed safely."
  });

  function validVerifyResponse(response, hostname, pin) {
    if (!response || response.schema_version !== "rootwell.browser.verify.v1" || typeof response.ok !== "boolean") return false;
    if (!response.ok) return response.result === null && response.error && typeof response.error.code === "string" &&
      Object.hasOwn(verifyFailureMessages, response.error.code);
    const result = response.result;
    return response.error === null && result && result.profile === "tls-server" && result.verification === "passed" &&
      result.hostname === hostname && typeof result.evaluated_at === "string" &&
      result.trust_source === "explicit-file" && result.revocation === "not-checked" && result.network === "disabled" &&
      result.root_pin === (pin ? "matched" : "not-provided") &&
      Number.isSafeInteger(result.ignored_source_roots) && result.ignored_source_roots >= 0 && result.ignored_source_roots <= 64 &&
      Array.isArray(result.chain) && result.chain.length >= 1 && result.chain.length <= 64 &&
      result.chain.every(function (certificate) {
        return certificate && typeof certificate.Subject === "string" && typeof certificate.Issuer === "string" &&
          /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(certificate.SHA256Fingerprint);
      }) && (!pin || (/^(?:[0-9A-Fa-f]{2}:){31}[0-9A-Fa-f]{2}$|^[0-9A-Fa-f]{64}$/.test(pin) &&
        result.chain.at(-1).SHA256Fingerprint.replaceAll(":", "") === pin.replaceAll(":", "").toUpperCase()));
  }

  const verifiedExportFailureMessages = Object.freeze({
    "invalid-browser-request": "The verification inputs are no longer valid. Verify again before exporting.",
    "not-verified": "The current files did not pass verification. Verify again before exporting.",
    "changed-verification": "The verified chain changed. Review and verify the files again before exporting.",
    "invalid-public-source": "A public source changed or is invalid. Verify again before exporting.",
    "input-too-large": "The selected files or PEM output exceed the export limits.",
    "internal-failure": "The local verified export could not be completed safely."
  });

  function validateVerifiedExportResponse(response, snapshot) {
    if (!response || response.schema_version !== "rootwell.browser.verified-export.v1" || typeof response.ok !== "boolean") return null;
    if (!response.ok) {
      if (response.result !== null || !Object.hasOwn(verifiedExportFailureMessages, response.error)) return null;
      return verifiedExportFailureMessages[response.error];
    }
    const result = response.result;
    const selected = snapshot.chain.slice(0, -1);
    if (response.error !== null || !result || result.hostname !== snapshot.hostname ||
        result.evaluated_at !== snapshot.evaluatedAt || result.trust_source !== "explicit-file" ||
        result.root_included !== false || !Array.isArray(result.fingerprints) ||
        result.fingerprints.length !== selected.length ||
        !result.fingerprints.every(function (fingerprint, index) { return fingerprint === selected[index]; }) ||
        typeof result.filename !== "string" || !/^rootwell-verified-fullchain-[0-9a-f]{32}\.pem$/.test(result.filename) ||
        !(result.bytes instanceof Uint8Array) || result.bytes.byteLength === 0 || result.bytes.byteLength > 4 * 1024 * 1024) return null;
    return result;
  }

  function refuseVerifiedExport(message) {
    showVerifyFailure(message);
    verifyExportError.textContent = message;
    verifyExportError.hidden = false;
  }

  function showVerifyFailure(message) {
    currentVerifySnapshot = null;
    verifyResult.hidden = true;
    verifyChain.replaceChildren();
    verifyExportError.hidden = true;
    verifyExportStatus.textContent = "";
    verifyError.textContent = message;
    verifyError.hidden = false;
    verifyStatus.textContent = "Local verification did not pass · no certificate upload";
    updateVerifyControls();
  }

  function renderVerify(result) {
    text("verify-result-hostname", result.hostname);
    text("verify-result-time", "Evaluated at " + result.evaluated_at + " · explicit trust file");
    text("verify-ignored-roots", result.ignored_source_roots > 0 ?
      result.ignored_source_roots + " self-signed CA certificate(s) in the CA files were ignored as trust sources." :
      "Trust came only from the separately selected file.");
    verifyRootPinStatus.textContent = result.root_pin === "matched" ?
      "The verified path's root matches the expected full SHA-256 fingerprint you supplied. Its source must still be independently trusted." :
      "No root fingerprint pin was supplied. The chain is valid against your selected root file, but Rootwell has not confirmed that root's identity.";
    const cards = result.chain.map(function (certificate, index) {
      const item = document.createElement("li");
      const role = document.createElement("span");
      role.textContent = index === 0 ? "Leaf" : index === result.chain.length - 1 ? "Trust anchor" : "Intermediate";
      const content = document.createElement("div");
      const subject = document.createElement("strong");
      subject.textContent = certificate.Subject;
      const detail = document.createElement("small");
      detail.textContent = "SHA-256 " + certificate.SHA256Fingerprint;
      content.append(subject, detail);
      item.append(role, content);
      return item;
    });
    verifyChain.replaceChildren(...cards);
    verifyError.hidden = true;
    verifyResult.hidden = false;
    verifyStatus.textContent = "Verified locally against the explicit trust file · no certificate upload";
    verifyResult.scrollIntoView({ block: "nearest" });
  }

  verifyButton.addEventListener("click", async function () {
    if (!engine || verifying || verifyButton.disabled) return;
    const generation = verifyGeneration;
    const simple = verifySimpleMode.checked;
    const hostname = verifyHostname.value.trim();
    const rootPin = verifyRootPin.value;
    const trustFile = verifyTrustFile.files[0];
    const sourceFiles = simple ? Array.from(verifySourceFiles.files) :
      [verifyLeafFile.files[0], verifyIntermediatesFile.files && verifyIntermediatesFile.files.length === 1 ? verifyIntermediatesFile.files[0] : null];
    const timeValue = !simple && verifyTime.value.trim() ? verifyTime.value.trim() : new Date().toISOString();
    const actualFiles = sourceFiles.filter(Boolean);
    if (!trustFile || !hostname || actualFiles.length < 1 || actualFiles.length > maxExploreFiles ||
        [...actualFiles, trustFile].some(function (file) { return !Number.isSafeInteger(file.size) || file.size <= 0; }) ||
        [...actualFiles, trustFile].reduce(function (sum, file) { return sum + file.size; }, 0) > engine.maxBytes) {
      showVerifyFailure("Choose public files within the 16 MiB combined limit and a separate trust file.");
      return;
    }
    verifying = true;
    currentVerifySnapshot = null;
    verifyResult.hidden = true;
    verifyError.hidden = true;
    verifyExportError.hidden = true;
    verifyExportStatus.textContent = "";
    verifyStatus.textContent = "Verifying locally · no certificate upload";
    updateVerifyControls();
    const buffers = [];
    try {
      for (const file of [...actualFiles, trustFile]) {
        const bytes = new Uint8Array(await file.arrayBuffer());
        buffers.push(bytes);
        if (generation !== verifyGeneration) return;
        if (bytes.byteLength !== file.size) {
          showVerifyFailure("A selected file changed while being read. Choose it again.");
          return;
        }
      }
      const trust = buffers[buffers.length - 1];
      const raw = simple ? engine.verifySimple(buffers.slice(0, -1), trust, hostname, timeValue, rootPin) :
        engine.verifyExplicit(buffers[0], sourceFiles[1] ? buffers[1] : new Uint8Array(0), trust, hostname, timeValue, rootPin);
      if (typeof raw !== "string" || raw.length > 1 << 20) {
        showVerifyFailure("The local verification engine returned an invalid response.");
        return;
      }
      const response = JSON.parse(raw);
      if (!validVerifyResponse(response, hostname, rootPin)) {
        showVerifyFailure("The local verification engine returned an invalid response.");
        return;
      }
      if (generation !== verifyGeneration) return;
      if (!response.ok) {
        showVerifyFailure(verifyFailureMessages[response.error.code]);
        return;
      }
      currentVerifySnapshot = Object.freeze({
        simple, hostname, timeValue, sourceFiles: Object.freeze(sourceFiles.slice()), trustFile,
        evaluatedAt: response.result.evaluated_at,
        chain: Object.freeze(response.result.chain.map(function (member) { return member.SHA256Fingerprint; }))
      });
      renderVerify(response.result);
    } catch {
      if (generation === verifyGeneration) showVerifyFailure("Verification failed safely. No certificate upload was made.");
    } finally {
      for (const bytes of buffers) bytes.fill(0);
      verifying = false;
      updateVerifyControls();
    }
  });

  verifyExportButton.addEventListener("click", exportVerifiedFullchain);

  async function exportVerifiedFullchain() {
    if (!engine || !currentVerifySnapshot || verifying || exportingVerified) return;
    const snapshot = currentVerifySnapshot;
    const generation = verifyGeneration;
    const files = snapshot.sourceFiles.filter(Boolean);
    const selectedFiles = [...files, snapshot.trustFile];
    if (selectedFiles.some(function (file) { return !Number.isSafeInteger(file.size) || file.size <= 0; }) ||
        selectedFiles.reduce(function (total, file) { return total + file.size; }, 0) > engine.maxBytes) {
      refuseVerifiedExport("The selected files changed or exceed the combined limit. Verify again.");
      return;
    }
    exportingVerified = true;
    verifyExportError.hidden = true;
    verifyExportStatus.textContent = "Re-verifying the public chain locally before download…";
    updateVerifyControls();
    const buffers = [];
    let output = null;
    try {
      let remaining = engine.maxBytes;
      for (const file of selectedFiles) {
        const bytes = new Uint8Array(await file.arrayBuffer());
        buffers.push(bytes);
        if (generation !== verifyGeneration || snapshot !== currentVerifySnapshot) return;
        if (bytes.byteLength !== file.size || bytes.byteLength > remaining) {
          refuseVerifiedExport("A selected file changed while being read. Verify again.");
          return;
        }
        remaining -= bytes.byteLength;
      }
      const trust = buffers[buffers.length - 1];
      const response = snapshot.simple ?
        engine.exportVerifiedSimple(buffers.slice(0, -1), trust, snapshot.hostname, snapshot.timeValue, snapshot.chain) :
        engine.exportVerifiedExplicit(buffers[0], snapshot.sourceFiles[1] ? buffers[1] : new Uint8Array(0),
          trust, snapshot.hostname, snapshot.timeValue, snapshot.chain);
      const validated = validateVerifiedExportResponse(response, snapshot);
      if (typeof validated === "string") {
        refuseVerifiedExport(validated);
        return;
      }
      if (!validated) {
        refuseVerifiedExport("The local verified export returned an invalid response. Verify again.");
        return;
      }
      output = validated.bytes;
      const reparsed = JSON.parse(engine.explore(output));
      const selected = snapshot.chain.slice(0, -1);
      if (!reparsed.ok || !validExploreResult(reparsed.result) || reparsed.result.count !== selected.length ||
          !reparsed.result.certificates.every(function (certificate, index) {
            return certificate.sha256 === selected[index] && certificate.encoding === "pem";
          })) {
        refuseVerifiedExport("The exported PEM did not match the verified chain. Verify again.");
        return;
      }
      if (generation !== verifyGeneration || snapshot !== currentVerifySnapshot) return;
      requestBrowserDownload(output, validated.filename);
      verifyExportStatus.textContent = "Browser download requested for the verified public server chain. The trust root and private key were not included.";
    } catch {
      if (generation === verifyGeneration && snapshot === currentVerifySnapshot) {
        refuseVerifiedExport("Verified fullchain export failed safely. Verify again before downloading.");
      }
    } finally {
      for (const bytes of buffers) bytes.fill(0);
      if (output) output.fill(0);
      exportingVerified = false;
      updateVerifyControls();
    }
  }

  exploreButton.addEventListener("click", async function () {
    if (!engine || !selectedExploreFiles || exploring || exporting) return;
    const files = selectedExploreFiles;
    if (files.length < 1 || files.length > maxExploreFiles ||
        files.reduce(function (total, file) { return total + file.size; }, 0) > engine.maxBytes) {
      showExploreFailure(exploreFailureMessages["input-too-large"]);
      return;
    }

    exploring = true;
    exploreError.hidden = true;
    exploreResult.hidden = true;
    exploreCertificates.replaceChildren();
    exploreStatus.textContent = "Exploring locally · no certificate upload";
    updateExploreControls();

    try {
      const entries = [];
      const fingerprints = new Map();
      let metadataBytes = 0;
      let remainingBytes = engine.maxBytes;
      for (const [fileIndex, file] of files.entries()) {
        if (selectedExploreFiles !== files) return;
        if (file.size > remainingBytes) {
          showExploreFailure("The selected files changed or exceed the combined limit.");
          return;
        }
        let bytes = null;
        try {
          bytes = new Uint8Array(await file.arrayBuffer());
          if (selectedExploreFiles !== files) return;
          if (bytes.byteLength !== file.size || bytes.byteLength > remainingBytes) {
            showExploreFailure("The selected files changed or exceed the combined limit.");
            return;
          }
          remainingBytes -= bytes.byteLength;
          const rawResponse = engine.explore(bytes);
          if (typeof rawResponse !== "string" || rawResponse.length > 4 * 1024 * 1024) {
            showExploreFailure("The local exploration engine returned an invalid response.");
            return;
          }
          const response = JSON.parse(rawResponse);
          if (!response || response.schema_version !== "rootwell.browser.explore.v1" || typeof response.ok !== "boolean") {
            showExploreFailure("The local exploration engine returned an invalid response.");
            return;
          }
          if (!response.ok) {
            const failure = response.error;
            const fixedMessage = failure && typeof failure.code === "string" && Object.hasOwn(exploreFailureMessages, failure.code) ? exploreFailureMessages[failure.code] : null;
            if (response.result !== null || !fixedMessage || failure.message !== fixedMessage) {
              showExploreFailure("Exploration failed safely.");
              return;
            }
            showExploreFailure(failure.code === "duplicate-certificate" ?
              selectedFileLabel(file, fileIndex) + " contains a duplicate certificate. No results were shown; remove one copy and try again." :
              fixedMessage);
            return;
          }
          if (response.error !== null || !validExploreResult(response.result)) {
            showExploreFailure("The local exploration engine returned an invalid response.");
            return;
          }
          for (const certificate of response.result.certificates) {
            const previous = fingerprints.get(certificate.sha256);
            if (previous) {
              showExploreFailure("Duplicate certificate (SHA-256 " + certificate.sha256 + ") in " +
                selectedFileLabel(previous.file, previous.index) + " and " + selectedFileLabel(file, fileIndex) +
                ". No results were shown; remove one copy and try again.");
              return;
            }
            if (entries.length === maxExploreCertificates) {
              showExploreFailure(exploreFailureMessages["certificate-count-limit"]);
              return;
            }
            metadataBytes += metadataEncoder.encode(certificate.subject).byteLength +
              metadataEncoder.encode(certificate.issuer).byteLength;
            if (metadataBytes > maxExploreMetadataBytes) {
              showExploreFailure(exploreFailureMessages["metadata-limit"]);
              return;
            }
            fingerprints.set(certificate.sha256, { file: file, index: fileIndex });
            entries.push({ certificate: certificate, file: file });
          }
        } finally {
          if (bytes) bytes.fill(0);
        }
      }
      const analysisInputs = [];
      try {
        for (const file of files) {
          if (selectedExploreFiles !== files) return;
          const bytes = new Uint8Array(await file.arrayBuffer());
          analysisInputs.push(bytes);
          if (bytes.byteLength !== file.size) {
            showExploreFailure("The selected files changed during analysis.");
            return;
          }
        }
        if (selectedExploreFiles !== files) return;
        const analysisText = engine.analyze(analysisInputs);
        if (typeof analysisText !== "string" || analysisText.length > 64 * 1024) {
          showExploreFailure("Local chain analysis failed safely.");
          return;
        }
        const analysis = JSON.parse(analysisText);
        if (!validChainResult(analysis, entries)) {
          showExploreFailure("Local chain analysis failed safely or the selected files changed.");
          return;
        }
        if (selectedExploreFiles === files) renderExplore(entries, analysis.result);
      } finally {
        for (const bytes of analysisInputs) bytes.fill(0);
      }
    } catch {
      if (selectedExploreFiles === files) showExploreFailure("Exploration failed safely. The selected files were not uploaded.");
    } finally {
      exploring = false;
      if (selectedExploreFiles === files) exploreStatus.textContent = "Local exploration finished · no certificate upload";
      updateExploreControls();
    }
  });
})();
