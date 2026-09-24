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

  let engine = null;
  let selectedInspectFile = null;
  let selectedExploreFile = null;
  let inspecting = false;
  let exploring = false;
  let exporting = false;
  const pendingDownloadURLs = new Set();

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

  function updateInspectControls() {
    inspectButton.disabled = inspecting || engine === null || selectedInspectFile === null;
  }

  function updateExploreControls() {
    exploreButton.disabled = exploring || exporting || engine === null || selectedExploreFile === null;
    exploreCertificates.querySelectorAll("button").forEach(function (button) {
      button.disabled = exploring || exporting;
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

  function setExploreFile(file) {
    selectedExploreFile = file;
    exploreResult.hidden = true;
    exploreCertificates.replaceChildren();
    exploreError.hidden = true;
    exportError.hidden = true;
    exploreSelection.textContent = file ? file.name + " · " + formatSize(file.size) : "No file selected";
    if (file && engine) exploreStatus.textContent = "Ready for local exploration";
    updateExploreControls();
  }

  exploreInput.addEventListener("change", function () {
    const file = exploreInput.files && exploreInput.files.length === 1 ? exploreInput.files[0] : null;
    setExploreFile(file);
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
      const selectFile = isExplore ? setExploreFile : setInspectFile;
      const selection = isExplore ? exploreSelection : inspectSelection;
      if (!event.dataTransfer || event.dataTransfer.files.length !== 1) {
        selectFile(null);
        selection.textContent = "Choose exactly one file";
        return;
      }
      selectFile(event.dataTransfer.files[0]);
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
    engine = null;
    updateInspectControls();
    updateExploreControls();
  }

  if (!globalThis.rootwellWorkbenchReady || typeof globalThis.rootwellWorkbenchReady.then !== "function") {
    engineUnavailable();
  } else {
    globalThis.rootwellWorkbenchReady.then(function (readyEngine) {
      if (!readyEngine || typeof readyEngine.inspect !== "function" || typeof readyEngine.explore !== "function" ||
          typeof readyEngine.exportPublic !== "function" ||
          !Number.isSafeInteger(readyEngine.maxBytes) || readyEngine.maxBytes <= 0) {
        engineUnavailable();
        return;
      }
      engine = readyEngine;
      engineState.textContent = "Ready · Go WebAssembly";
      inspectStatus.textContent = selectedInspectFile ? "Ready for local inspection" : "Choose one certificate to inspect";
      exploreStatus.textContent = selectedExploreFile ? "Ready for local exploration" : "Choose one public bundle to explore";
      updateInspectControls();
      updateExploreControls();
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

  function bundleDetail(listElement, label, value) {
    const row = document.createElement("div");
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = label;
    description.textContent = value;
    row.append(term, description);
    listElement.append(row);
  }

  function exportAction(label, fingerprint, format, index) {
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = label;
    button.setAttribute("aria-label", "Download certificate " + (index + 1) + " as " + format.toUpperCase());
    button.addEventListener("click", function () { void exportCertificate(fingerprint, format); });
    return button;
  }

  function renderExplore(result) {
    const cards = result.certificates.map(function (certificate, index) {
      const item = document.createElement("li");
      const heading = document.createElement("div");
      heading.className = "bundle-card-head";
      const number = document.createElement("span");
      number.textContent = String(index + 1).padStart(2, "0");
      const title = document.createElement("strong");
      title.textContent = certificate.subject || "Subject not present";
      heading.append(number, title);
      const details = document.createElement("dl");
      bundleDetail(details, "Issuer", certificate.issuer || "Not present");
      bundleDetail(details, "CA flag", certificate.is_ca ? "Yes · not automatically trusted" : "No");
      bundleDetail(details, "Expires", certificate.not_after);
      bundleDetail(details, "Encoding", certificate.encoding.toUpperCase());
      bundleDetail(details, "SHA-256", certificate.sha256);
      const actions = document.createElement("div");
      actions.className = "bundle-actions";
      actions.append(
        exportAction("Download PEM", certificate.sha256, "pem", index),
        exportAction("Download DER", certificate.sha256, "der", index)
      );
      item.append(heading, details, actions);
      return item;
    });
    exploreCertificates.replaceChildren(...cards);
    exportError.hidden = true;
    exportStatus.textContent = "Choose PEM or DER on a certificate card to request a browser download. Rootwell does not write directly to disk.";
    text("explore-result-count", result.count + (result.count === 1 ? " certificate found" : " certificates found"));
    exploreResult.hidden = false;
    exploreResult.scrollIntoView({ block: "nearest" });
  }

  function showExploreFailure(message) {
    exploreResult.hidden = true;
    exploreCertificates.replaceChildren();
    exploreError.textContent = message;
    exploreError.hidden = false;
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

  async function exportCertificate(fingerprint, format) {
    if (!engine || !selectedExploreFile || exporting || exploring) return;
    const file = selectedExploreFile;
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
      if (selectedExploreFile !== file) return;
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
      requestBrowserDownload(output, validated.filename);
      exportStatus.textContent = "Browser download requested. Check the browser's save location; Rootwell did not write to disk.";
    } catch {
      if (selectedExploreFile === file) showExportFailure("Certificate export failed safely. No upload was made.");
    } finally {
      if (input) input.fill(0);
      if (output) output.fill(0);
      exporting = false;
      updateExploreControls();
    }
  }

  exploreButton.addEventListener("click", async function () {
    if (!engine || !selectedExploreFile || exploring || exporting) return;
    const file = selectedExploreFile;
    if (file.size > engine.maxBytes) {
      showExploreFailure(exploreFailureMessages["input-too-large"]);
      return;
    }

    exploring = true;
    exploreError.hidden = true;
    exploreResult.hidden = true;
    exploreCertificates.replaceChildren();
    exploreStatus.textContent = "Exploring locally · no certificate upload";
    updateExploreControls();

    let bytes = null;
    try {
      const buffer = await file.arrayBuffer();
      bytes = new Uint8Array(buffer);
      if (selectedExploreFile !== file) return;
      if (bytes.byteLength !== file.size || bytes.byteLength > engine.maxBytes) {
        showExploreFailure("The selected file changed or exceeds the exploration limit.");
        return;
      }
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
        showExploreFailure(fixedMessage);
        return;
      }
      if (response.error !== null || !validExploreResult(response.result)) {
        showExploreFailure("The local exploration engine returned an invalid response.");
        return;
      }
      renderExplore(response.result);
    } catch {
      if (selectedExploreFile === file) showExploreFailure("Exploration failed safely. The selected file was not uploaded.");
    } finally {
      if (bytes) bytes.fill(0);
      exploring = false;
      if (selectedExploreFile === file) exploreStatus.textContent = "Local exploration finished · no certificate upload";
      updateExploreControls();
    }
  });
})();
