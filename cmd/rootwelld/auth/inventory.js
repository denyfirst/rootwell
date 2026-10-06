"use strict";

(function () {
  const form = document.getElementById("inventory-form");
  const fileInput = document.getElementById("certificate-file");
  const ownerInput = document.getElementById("owner");
  const locationInput = document.getElementById("location");
  const saveButton = document.getElementById("save-button");
  const saveStatus = document.getElementById("save-status");
  const previewButton = document.getElementById("preview-button");
  const importPreview = document.getElementById("import-preview");
  const previewSummary = document.getElementById("preview-summary");
  const previewRecords = document.getElementById("preview-records");
  const refreshButton = document.getElementById("refresh-button");
  const listStatus = document.getElementById("list-status");
  const counts = document.getElementById("counts");
  const list = document.getElementById("records");
  const clockAsOf = document.getElementById("clock-as-of");
  const expiryFilter = document.getElementById("expiry-filter");
  const inventorySearch = document.getElementById("inventory-search");
  const monitorSummary = document.getElementById("monitor-summary");
  const warningDays = document.getElementById("warning-days");
  const autoRefresh = document.getElementById("auto-refresh");
  const locationPanel = document.getElementById("location-panel");
  const locationForm = document.getElementById("location-form");
  const locationTarget = document.getElementById("location-target");
  const newLocation = document.getElementById("new-location");
  const locationButton = document.getElementById("location-button");
  const locationCancel = document.getElementById("location-cancel");
  const locationStatus = document.getElementById("location-status");
  const ownerPanel = document.getElementById("owner-panel");
  const ownerForm = document.getElementById("owner-form");
  const ownerTarget = document.getElementById("owner-target");
  const newOwner = document.getElementById("new-owner");
  const ownerButton = document.getElementById("owner-button");
  const ownerCancel = document.getElementById("owner-cancel");
  const ownerStatus = document.getElementById("owner-status");
  const locationManagePanel = document.getElementById("location-manage-panel");
  const locationManageForm = document.getElementById("location-manage-form");
  const locationManageTarget = document.getElementById("location-manage-target");
  const oldLocation = document.getElementById("old-location");
  const replacementLocation = document.getElementById("replacement-location");
  const renameLocationButton = document.getElementById("rename-location-button");
  const removeLocationButton = document.getElementById("remove-location-button");
  const confirmRemove = document.getElementById("confirm-remove");
  const locationManageCancel = document.getElementById("location-manage-cancel");
  const locationManageStatus = document.getElementById("location-manage-status");
  const deletePanel = document.getElementById("delete-panel");
  const deleteForm = document.getElementById("delete-form");
  const deleteTarget = document.getElementById("delete-target");
  const deleteFingerprint = document.getElementById("delete-fingerprint");
  const confirmDelete = document.getElementById("confirm-delete");
  const deleteButton = document.getElementById("delete-button");
  const deleteCancel = document.getElementById("delete-cancel");
  const deleteStatus = document.getElementById("delete-status");
  const encoder = new TextEncoder();
  let loadSerial = 0;
  let saving = false;
  let associating = false;
  let editingOwner = false;
  let changingLocation = false;
  let deleting = false;
  let selectedFingerprint = null;
  let selectedOwnerFingerprint = null;
  let selectedManageFingerprint = null;
  let selectedDeleteFingerprint = null;
  let selectedManageLocations = [];
  let originalOwner = null;
  let displayedGeneration = 0;
  let loadedRecords = [];
  let checkedAt = null;
  let receivedAt = null;
  let receivedWall = null;
  let refreshController = null;
  let timer = null;
  let refreshing = false;
  let automaticPaused = false;
  let importSerial = 0;
  let importFiles = null;
  let importEntries = null;
  let previewing = false;
  let saveController = null;

  function duplicateSaved() {
    return importEntries?.some(entry => loadedRecords.some(record => record.fingerprint === entry.sha256));
  }
  function sameImportFiles(files) {
    const selected = Array.from(fileInput.files || []);
    return files.length === selected.length && files.every((file, index) => file === selected[index]);
  }
  function updateImportControls() {
    const busy = saving || associating || editingOwner || changingLocation || deleting;
    saveButton.disabled = busy || previewing || document.hidden || !displayedGeneration || snapshotAge() >= 120000 ||
      !importEntries || duplicateSaved() || form.dataset?.readOnly === "true";
    previewButton.disabled = busy || previewing || document.hidden;
    fileInput.disabled = saving;
  }
  function clearImportPreview(clearFiles = false) {
    ++importSerial;
    importFiles = importEntries = null;
    previewing = false;
    importPreview.hidden = true;
    previewRecords.replaceChildren();
    previewSummary.textContent = "";
    if (clearFiles) fileInput.value = "";
    updateImportControls();
  }
  fileInput.addEventListener("change", () => { clearImportPreview(); saveStatus.textContent = "Preview these files before saving. Nothing has been uploaded."; });
  previewButton.addEventListener("click", async function () {
    if (saving || associating || editingOwner || changingLocation || deleting || previewing || document.hidden) return;
    clearImportPreview();
    const serial = importSerial;
    const files = Array.from(fileInput.files || []);
    importFiles = files;
    previewing = true;
    updateImportControls();
    saveStatus.textContent = "Reading public files locally — no upload…";
    const current = () => serial === importSerial && !document.hidden && sameImportFiles(files);
    const deadline = setTimeout(() => {
      if (current()) { clearImportPreview(); saveStatus.textContent = "Local preview timed out. Select and preview again; nothing was uploaded."; }
    }, 20000);
    try {
      const entries = await globalThis.rootwellInventoryImport.preview(files, current);
      if (!current()) return;
      importEntries = entries;
      importPreview.hidden = false;
      let duplicates = 0;
      for (const entry of entries) {
        const item = document.createElement("li");
        const title = document.createElement("strong");
        title.textContent = entry.subject || "Public certificate";
        item.appendChild(title);
        const saved = loadedRecords.some(record => record.fingerprint === entry.sha256);
        if (saved) duplicates++;
        const note = document.createElement("small");
        note.textContent = entry.source + " · Expires: " + entry.not_after.slice(0, 10) + (saved ? " · Already saved — duplicate" : " · New certificate");
        item.appendChild(note);
        previewRecords.appendChild(item);
      }
      previewSummary.textContent = entries.length + " public certificate(s) found.";
      saveStatus.textContent = duplicates ? duplicates + " certificate(s) are already saved. Remove their copies from this batch and preview again. Nothing was saved or skipped." :
        form.dataset?.readOnly === "true" ? "Local preview complete. This read-only demo cannot save certificates." :
        "Ready to save all " + entries.length + " certificate(s). Owner/server notes below apply to every certificate in this batch.";
    } catch (error) {
      if (current()) { clearImportPreview(); saveStatus.textContent = error instanceof Error ? error.message : "Local preview failed. Nothing was uploaded."; }
    } finally {
      clearTimeout(deadline);
      if (current()) { previewing = false; updateImportControls(); }
    }
  });

  function validLabel(value) {
    return encoder.encode(value).length <= 128 && value.trim() === value &&
      !/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u.test(value);
  }

  function base64(bytes) {
    const parts = [];
    for (let offset = 0; offset < bytes.length; offset += 8192) {
      parts.push(String.fromCharCode.apply(null, bytes.subarray(offset, offset + 8192)));
    }
    return btoa(parts.join(""));
  }

  function safeDate(value) {
    if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value)) return null;
    const ms = Date.parse(value);
    return Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 19) + "Z" === value ? ms : null;
  }

  function expiryState(record, now) {
    const start = safeDate(record.not_before);
    const end = safeDate(record.not_after);
    if (start === null || end === null || start >= end) return { name: "Check certificate dates", group: "invalid" };
    const daysLeft = Math.ceil((end - now) / 86400000);
    if (now >= end) return { name: "Expired", group: "expired", daysLeft: Math.trunc((end - now) / 86400000) };
    if (now < start) return { name: "Not yet valid", group: "future", daysLeft };
    const days = (end - now) / 86400000;
    const name = days < 1 ? "Less than 1 day left" : daysLeft + " days left";
    if (days <= 30) return { name, group: "soon", daysLeft };
    if (days <= 90) return { name, group: "medium", daysLeft };
    return { name, group: "later", daysLeft };
  }

  function reminder(record) {
    return ["invalid", "expired", "future"].includes(record.expiry.status || record.expiry.group) ||
      (record.expiry.days_left ?? record.expiry.daysLeft) <= Number(warningDays.value);
  }

  function snapshotAge() {
    if (receivedAt === null || receivedWall === null) return Infinity;
    const elapsed = performance.now() - receivedAt;
    const wall = Date.now() - receivedWall;
    return !Number.isFinite(elapsed) || !Number.isFinite(wall) || elapsed < 0 || wall < 0 ? Infinity : Math.max(elapsed, wall);
  }

  function updateMonitor() {
    if (checkedAt === null || !displayedGeneration || document.hidden) return;
    if (snapshotAge() >= 120000) {
      monitorSummary.textContent = "This list is out of date. Refresh before using its expiry reminders.";
      monitorSummary.className = "monitor-summary stale";
      return;
    }
    const attention = loadedRecords.filter(reminder).length;
    monitorSummary.textContent = attention ? attention + " certificate(s) need attention. Plan replacement with the owner or issuer." :
      "No expiry reminders within " + warningDays.value + " days. This is not a certificate trust check.";
    monitorSummary.className = attention ? "monitor-summary" : "monitor-summary clear";
  }

  function addText(parent, tag, value, className) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = value;
    parent.appendChild(node);
  }

  function render(data) {
    if (!data || !Number.isSafeInteger(data.generation) || data.generation < 1 ||
        !Array.isArray(data.records) || data.records.length > 500 || data.verification !== "not-performed" ||
        !data.monitoring || data.monitoring.clock_source !== "server-clock" ||
        data.monitoring.refresh_after_seconds !== 60 || safeDate(data.monitoring.checked_at) === null) {
      throw new Error("Inventory response was not recognized");
    }
    const records = data.records.slice();
    const serverNow = safeDate(data.monitoring.checked_at);
    const fingerprints = new Set();
    for (const record of records) {
      if (!record || typeof record.fingerprint !== "string" || record.fingerprint.length > 128 ||
          typeof record.subject !== "string" || typeof record.issuer !== "string" ||
          typeof record.not_before !== "string" || typeof record.not_after !== "string" ||
          typeof record.owner !== "string" || typeof record.location !== "string" ||
          !Array.isArray(record.locations) || record.locations.length > 32 ||
          (record.imported_at !== undefined && (typeof record.imported_at !== "string" || safeDate(record.imported_at) === null)) ||
          !Array.isArray(record.dns_names) || record.dns_names.length > 128 ||
          record.dns_names.some(value => typeof value !== "string") ||
          !Number.isSafeInteger(record.import_generation) || record.import_generation < 2 || record.import_generation > data.generation) {
        throw new Error("Inventory record was not recognized");
      }
      if (fingerprints.has(record.fingerprint) || record.locations.some(value => typeof value !== "string" || !value || !validLabel(value)) ||
          new Set(record.locations).size !== record.locations.length ||
          (record.locations.length ? record.locations[0] !== record.location : record.location !== "")) {
        throw new Error("Inventory locations were not recognized");
      }
      fingerprints.add(record.fingerprint);
      const expected = expiryState(record, serverNow);
      if (!record.expiry || record.expiry.status !== expected.group ||
          record.expiry.days_left !== expected.daysLeft ||
          (record.expiry.days_left !== undefined && !Number.isSafeInteger(record.expiry.days_left))) {
        throw new Error("Expiry response was not recognized; refresh before acting");
      }
    }
    checkedAt = serverNow;
    receivedAt = performance.now();
    receivedWall = Date.now();
    loadedRecords = records;
    displayedGeneration = data.generation;
    selectedFingerprint = null;
    selectedOwnerFingerprint = null;
    selectedManageFingerprint = null;
    selectedDeleteFingerprint = null;
    selectedManageLocations = [];
    originalOwner = null;
    locationPanel.hidden = true;
    ownerPanel.hidden = true;
    locationManagePanel.hidden = true;
    deletePanel.hidden = true;
    locationStatus.textContent = "";
    ownerStatus.textContent = "";
    locationManageStatus.textContent = "";
    draw();
    void globalThis.rootwellInventoryLifecycle?.refreshActivity();
  }

  function draw() {
    if (!displayedGeneration) return;
    const now = checkedAt;
    const differs = Math.abs(Date.now() - now) > 300000;
    clockAsOf.textContent = "Checked at " + new Date(now).toISOString() + " · Rootwell server clock." +
      (differs ? " Your device and server times differ by over 5 minutes; check both clocks." : "") +
      " This list is a page snapshot; background status is shown below; no automatic renewal or live server check.";
    const records = loadedRecords.map(record => ({ ...record, expiry: expiryState(record, now) }));
    const rank = { invalid: 0, expired: 1, soon: 2, medium: 3, future: 4, later: 5 };
    records.sort((a, b) => rank[a.expiry.group] - rank[b.expiry.group] ||
      (safeDate(a.not_after) ?? Number.NEGATIVE_INFINITY) - (safeDate(b.not_after) ?? Number.NEGATIVE_INFINITY) ||
      a.fingerprint.localeCompare(b.fingerprint));
    list.replaceChildren();
    counts.replaceChildren();
    const filter = expiryFilter.value || "all";
    const query = inventorySearch.value.trim().toLocaleLowerCase();
    let shown = 0;
    for (const record of records) {
      if (filter !== "all" && filter !== record.expiry.group &&
          !(filter === "attention" && reminder(record)) &&
          !(filter === "missing-owner" && !record.owner) &&
          !(filter === "missing-location" && !record.locations.length)) continue;
      if (query && ![record.subject, record.fingerprint, record.owner, ...record.locations]
        .some(value => value.toLocaleLowerCase().includes(query))) continue;
      shown++;
      const item = document.createElement("li");
      addText(item, "strong", record.subject || "Subject not provided");
      addText(item, "span", record.expiry.name, "state " + record.expiry.group);
      addText(item, "small", "Expires: " + record.not_after.slice(0, 10));
      addText(item, "small", "Owner: " + (record.owner || "Not noted") + " · Server: " +
        (record.locations.length ? record.locations.join(" · ") : "Not noted"));
      const details = document.createElement("details");
      details.className = "record-details";
      addText(details, "summary", "Details and manage");
      const guidance = {
        invalid: "Next: check the imported certificate dates and server clock; this is not a trust verdict.",
        expired: "Next: identify the owner and deployment, then arrange replacement outside Rootwell; this record is not renewed automatically.",
        soon: "Next: confirm the actual deployment and arrange renewal with its issuer before expiry.",
        medium: "Next: plan renewal with the owner and confirm the real deployment.",
        future: "Next: check the server clock and certificate validity start before deployment.",
        later: "Next: keep ownership and location notes current; deployment is not verified."
      };
      addText(item, "small", guidance[record.expiry.group], "next-action");
      const openForm = document.createElement("form");
      openForm.method = "post";
      openForm.action = "/workbench";
      openForm.className = "workbench-actions";
      for (const [name, value] of [["fingerprint", record.fingerprint], ["expected_generation", String(displayedGeneration)]]) {
        const field = document.createElement("input");
        field.type = "hidden";
        field.name = name;
        field.value = value;
        openForm.appendChild(field);
      }
      for (const [tool, label] of [["inspect", "Inspect"], ["verify", "Verify"]]) {
        const button = document.createElement("button");
        button.type = "submit";
        button.name = "tool";
        button.value = tool;
        button.textContent = label;
        button.className = "secondary";
        openForm.appendChild(button);
      }
      const snapshotGeneration = displayedGeneration;
      openForm.addEventListener("submit", function (event) {
        if (saving || associating || editingOwner || changingLocation || deleting ||
            displayedGeneration !== snapshotGeneration || document.hidden) {
          event.preventDefault();
          listStatus.textContent = "Finish the pending change, then refresh before opening a saved certificate.";
        }
      });
      item.appendChild(openForm);
      const compareButton = document.createElement("button");
      compareButton.type = "button";
      compareButton.className = "secondary";
      compareButton.textContent = "Compare replacement";
      compareButton.addEventListener("click", () => {
        if (!saving && !associating && !editingOwner && !changingLocation && !deleting &&
            !document.hidden && displayedGeneration === snapshotGeneration && snapshotAge() < 120000) {
          void globalThis.rootwellInventoryLifecycle?.open(record, snapshotGeneration);
        }
      });
      item.appendChild(compareButton);
      if (record.imported_at) addText(details,"small","Saved at (server clock): " + record.imported_at);
      addText(details, "small", "The listed servers are your notes; deployment has not been checked.");
      addText(details, "small", "SHA-256: " + record.fingerprint);
      const addButton = document.createElement("button");
      addButton.type = "button";
      addButton.className = "secondary";
      addButton.textContent = "Add server note";
      addButton.disabled = record.locations.length >= 32;
      addButton.addEventListener("click", function () {
        if (saving || associating || editingOwner || changingLocation || deleting || !displayedGeneration) return;
        selectedFingerprint = record.fingerprint;
        selectedOwnerFingerprint = null;
        selectedManageFingerprint = null;
        selectedDeleteFingerprint = null;
        ownerPanel.hidden = true;
        locationManagePanel.hidden = true;
        deletePanel.hidden = true;
        locationTarget.textContent = "Certificate: " + (record.subject || record.fingerprint) + " · SHA-256: " + record.fingerprint;
        newLocation.value = "";
        locationStatus.textContent = "";
        locationPanel.hidden = false;
      });
      details.appendChild(addButton);
      const editOwnerButton = document.createElement("button");
      editOwnerButton.type = "button";
      editOwnerButton.className = "secondary";
      editOwnerButton.textContent = "Change owner";
      editOwnerButton.addEventListener("click", function () {
        if (saving || associating || editingOwner || changingLocation || deleting || !displayedGeneration) return;
        selectedOwnerFingerprint = record.fingerprint;
        originalOwner = record.owner;
        selectedFingerprint = null;
        selectedManageFingerprint = null;
        selectedDeleteFingerprint = null;
        locationPanel.hidden = true;
        locationManagePanel.hidden = true;
        deletePanel.hidden = true;
        ownerTarget.textContent = "Certificate: " + (record.subject || record.fingerprint) + " · SHA-256: " + record.fingerprint +
          " · Current owner: " + (record.owner || "Unknown");
        newOwner.value = record.owner;
        ownerStatus.textContent = "";
        ownerPanel.hidden = false;
      });
      details.appendChild(editOwnerButton);
      const manageLocationButton = document.createElement("button");
      manageLocationButton.type = "button";
      manageLocationButton.className = "secondary";
      manageLocationButton.textContent = "Change server notes";
      manageLocationButton.disabled = record.locations.length === 0;
      manageLocationButton.addEventListener("click", function () {
        if (saving || associating || editingOwner || changingLocation || deleting || !displayedGeneration || !record.locations.length) return;
        selectedManageFingerprint = record.fingerprint;
        selectedManageLocations = record.locations.slice();
        selectedFingerprint = null;
        selectedOwnerFingerprint = null;
        selectedDeleteFingerprint = null;
        locationPanel.hidden = true;
        ownerPanel.hidden = true;
        deletePanel.hidden = true;
        locationManageTarget.textContent = "Certificate: " + (record.subject || record.fingerprint) + " · SHA-256: " + record.fingerprint;
        oldLocation.replaceChildren();
        for (const label of selectedManageLocations) {
          const option = document.createElement("option");
          option.value = label;
          option.textContent = label;
          oldLocation.appendChild(option);
        }
        oldLocation.value = selectedManageLocations[0];
        replacementLocation.value = "";
        confirmRemove.checked = false;
        locationManageStatus.textContent = "";
        locationManagePanel.hidden = false;
      });
      details.appendChild(manageLocationButton);
      const deleteRecordButton = document.createElement("button");
      deleteRecordButton.type = "button";
      deleteRecordButton.className = "secondary";
      deleteRecordButton.textContent = "Remove from saved list";
      deleteRecordButton.addEventListener("click", function () {
        if (saving || associating || editingOwner || changingLocation || deleting || !displayedGeneration) return;
        selectedDeleteFingerprint = record.fingerprint;
        selectedFingerprint = null;
        selectedOwnerFingerprint = null;
        selectedManageFingerprint = null;
        locationPanel.hidden = true;
        ownerPanel.hidden = true;
        locationManagePanel.hidden = true;
        deleteTarget.textContent = "Certificate: " + (record.subject || "Subject not provided") + " · SHA-256: " + record.fingerprint;
        deleteFingerprint.value = "";
        confirmDelete.checked = false;
        deleteStatus.textContent = "";
        deletePanel.hidden = false;
      });
      details.appendChild(deleteRecordButton);
      item.appendChild(details);
      list.appendChild(item);
    }
    addText(counts, "span", "Total: " + records.length);
    addText(counts, "span", "Needs attention: " + loadedRecords.filter(reminder).length);
    const unknownOwners = records.filter(record => !record.owner).length;
    const unknownLocations = records.filter(record => !record.locations.length).length;
    addText(counts, "span", "No owner note: " + unknownOwners);
    addText(counts, "span", "No server note: " + unknownLocations);
    listStatus.textContent = records.length ? shown + " of " + records.length + " saved public certificate(s) shown" :
      "No certificates saved yet. This is not a trust store.";
    updateMonitor();
  }

  async function refresh() {
    if (refreshing || document.hidden) return false;
    refreshing = true;
    globalThis.rootwellInventoryLifecycle?.invalidate();
    clearImportPreview();
    automaticPaused = false;
    const serial = ++loadSerial;
    const controller = new AbortController();
    refreshController = controller;
    const deadline = setTimeout(() => controller.abort(), 10000);
    refreshButton.disabled = true;
    displayedGeneration = 0;
    loadedRecords = [];
    checkedAt = null;
    receivedAt = null;
    receivedWall = null;
    list.replaceChildren();
    counts.replaceChildren();
    monitorSummary.textContent = "Checking saved certificate dates…";
    clockAsOf.textContent = "";
    selectedFingerprint = null;
    selectedOwnerFingerprint = null;
    selectedManageFingerprint = null;
    selectedDeleteFingerprint = null;
    selectedManageLocations = [];
    originalOwner = null;
    locationPanel.hidden = true;
    ownerPanel.hidden = true;
    locationManagePanel.hidden = true;
    deletePanel.hidden = true;
    listStatus.textContent = "Reading encrypted inventory…";
    try {
      const response = await fetch("/api/inventory", { method: "GET", credentials: "same-origin", cache: "no-store",
        headers: { "X-Rootwell-Request": "1" }, signal: controller.signal });
      if (serial !== loadSerial) return;
      if (!response.ok) {
        const messages = {
          401: "Sign in again to see saved certificates.",
          403: "Finish setup or reopen this page from your Rootwell installation.",
          409: "Inventory is not initialized or the installation changed. Check setup before retrying.",
          501: "Saved inventory requires the supported Linux installation; native Windows storage is not enabled.",
          503: "Encrypted inventory is unavailable. Check storage and server time before retrying."
        };
        throw new Error(messages[response.status] || "Inventory could not be opened; refresh before acting.");
      }
      const data = await readBoundedJSON(response, controller.signal);
      if (serial !== loadSerial || controller.signal.aborted || document.hidden) return false;
      render(data);
      return true;
    } catch (error) {
      if (serial !== loadSerial) return;
      displayedGeneration = 0;
      loadedRecords = [];
      checkedAt = null;
      list.replaceChildren();
      counts.replaceChildren();
      clockAsOf.textContent = "";
      automaticPaused = true;
      monitorSummary.textContent = "Expiry reminders unavailable. Sign in if needed, then refresh. No current result is shown.";
      monitorSummary.className = "monitor-summary stale";
      listStatus.textContent = error instanceof Error ? error.message : "Inventory could not be opened";
      return false;
    } finally {
      clearTimeout(deadline);
      controller.abort();
      if (serial === loadSerial) {
        refreshButton.disabled = false;
        refreshing = false;
        refreshController = null;
        updateImportControls();
      }
    }
  }

  async function readBoundedJSON(response, signal) {
    const reader = response.body?.getReader();
    if (!reader) throw new Error("Inventory response unavailable");
    const chunks = [];
    let size = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (signal.aborted) throw new Error("Inventory refresh timed out");
        if (done) break;
        size += value.byteLength;
        if (size > 4 * 1024 * 1024) throw new Error("Inventory response exceeds the page limit");
        chunks.push(value);
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
      try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
      catch { throw new Error("Inventory response was not recognized"); }
    } finally {
      await reader.cancel().catch(() => {});
      reader.releaseLock();
    }
  }

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    if (saving || associating || editingOwner || changingLocation || deleting || previewing || document.hidden || form.dataset?.readOnly === "true") return;
    const files = importFiles;
    const entries = importEntries;
    const owner = ownerInput.value;
    const location = locationInput.value;
    if (!files || !entries || !displayedGeneration || snapshotAge() >= 120000 || duplicateSaved()) {
      saveStatus.textContent = "Refresh saved certificates if needed, then preview a batch without duplicates before saving.";
      return;
    }
    if (!validLabel(owner) || !validLabel(location)) {
      saveStatus.textContent = "Owner and location must be short, plain-text labels (up to 128 bytes).";
      return;
    }
    saving = true;
    updateImportControls();
    const serial = importSerial;
    const generation = displayedGeneration;
    const current = () => serial === importSerial && !document.hidden && sameImportFiles(files) && displayedGeneration === generation;
    const controller = new AbortController();
    saveController = controller;
    let posted = false;
    let confirmed = false;
    const deadline = setTimeout(() => {
      controller.abort();
      clearImportPreview();
      saveStatus.textContent = posted ? "Save timed out and may have completed. Refresh before another import." : "Local recheck timed out; nothing was uploaded. Preview again.";
    }, 20000);
    saveStatus.textContent = "Rechecking the exact preview before sending public certificates to this Rootwell…";
    try {
      const expected = entries.map(entry => entry.sha256);
      const bytes = await globalThis.rootwellInventoryImport.prepare(files, expected, () => current() && !controller.signal.aborted);
      let certificate;
      try { certificate = base64(bytes); } finally { bytes.fill(0); }
      if (!current() || controller.signal.aborted || snapshotAge() >= 120000 || duplicateSaved()) return;
      posted = true;
      const response = await fetch("/api/inventory", { method: "POST", credentials: "same-origin", cache: "no-store",
        headers: { "Content-Type": "application/json", "X-Rootwell-Request": "1" },
        body: JSON.stringify({ certificate, owner, location }), signal: controller.signal });
      if (!response.ok) throw new Error("Save was not confirmed. The batch may now conflict with saved records; refresh and preview again before retrying.");
      const result = await readBoundedJSON(response, controller.signal);
      if (!current() || controller.signal.aborted) return;
      if (!result || !Array.isArray(result.records) || result.records.length !== expected.length || result.verification !== "not-performed" ||
          !result.records.every((record, index) => record.fingerprint === expected[index])) {
        throw new Error("Save outcome could not be confirmed; refresh before retrying.");
      }
      saveStatus.textContent = result.records.length + " public certificate(s) saved. Make a new full inventory snapshot; backup is not automatic.";
      confirmed = true;
      clearImportPreview(true);
      await refresh();
    } catch (error) {
      if (current()) saveStatus.textContent = posted ? "Save outcome could not be confirmed; it may have completed. Refresh and preview again before retrying." :
        error instanceof Error ? error.message : "Local recheck failed; nothing was uploaded.";
    } finally {
      clearTimeout(deadline);
      controller.abort();
      saveController = null;
      saving = false;
      if (!current() && posted && !confirmed) saveStatus.textContent = "Save may have completed before the view changed. Refresh before another import.";
      updateImportControls();
    }
  });

  locationForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    if (associating || saving || editingOwner || changingLocation || deleting || !selectedFingerprint || !displayedGeneration) return;
    const location = newLocation.value;
    if (!location || !validLabel(location)) {
      locationStatus.textContent = "Enter one short, plain-text location (up to 128 bytes).";
      return;
    }
    const fingerprint = selectedFingerprint;
    const expectedGeneration = displayedGeneration;
    associating = true;
    locationButton.disabled = true;
    saveButton.disabled = true;
    refreshButton.disabled = true;
    locationStatus.textContent = "Saving your manual location note…";
    try {
      const response = await fetch("/api/inventory/locations", { method: "POST", credentials: "same-origin", cache: "no-store",
        headers: { "Content-Type": "application/json", "X-Rootwell-Request": "1" },
        body: JSON.stringify({ fingerprint, location, expected_generation: expectedGeneration }) });
      if (!response.ok) {
        const message = (await response.text()).trim().slice(0, 240);
        throw new Error(message || "Location was not saved; refresh before retrying.");
      }
      const result = await response.json();
      if (!result || result.verification !== "not-performed" || result.generation !== expectedGeneration + 1 ||
          !Array.isArray(result.records) || result.records.length !== 1 ||
          result.records[0].fingerprint !== fingerprint || !Array.isArray(result.records[0].locations) ||
          !result.records[0].locations.includes(location)) {
        throw new Error("Save outcome could not be confirmed; refresh before retrying.");
      }
      const loaded = await refresh();
      listStatus.textContent = loaded ? "Manual location saved. Make a new full snapshot; backup is not automatic." :
        "Location may have been saved, but inventory could not be reloaded. Refresh before another change.";
    } catch (error) {
      locationStatus.textContent = error instanceof Error ? error.message : "Location was not saved; refresh before retrying.";
    } finally {
      associating = false;
      locationButton.disabled = false;
      updateImportControls();
      refreshButton.disabled = false;
    }
  });

  locationCancel.addEventListener("click", function () {
    if (associating) return;
    selectedFingerprint = null;
    locationPanel.hidden = true;
  });

  ownerForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    if (editingOwner || saving || associating || changingLocation || deleting || !selectedOwnerFingerprint || !displayedGeneration) return;
    const owner = newOwner.value;
    if (!validLabel(owner)) {
      ownerStatus.textContent = "Enter a plain-text owner note of up to 128 bytes, or leave it blank.";
      return;
    }
    if (owner === originalOwner) {
      ownerStatus.textContent = "Owner is unchanged.";
      return;
    }
    const fingerprint = selectedOwnerFingerprint;
    const expectedGeneration = displayedGeneration;
    editingOwner = true;
    ownerButton.disabled = true;
    saveButton.disabled = true;
    refreshButton.disabled = true;
    ownerStatus.textContent = "Saving your manual owner note…";
    try {
      const response = await fetch("/api/inventory/owner", { method: "POST", credentials: "same-origin", cache: "no-store",
        headers: { "Content-Type": "application/json", "X-Rootwell-Request": "1" },
        body: JSON.stringify({ fingerprint, owner, expected_generation: expectedGeneration }) });
      if (!response.ok) {
        const message = (await response.text()).trim().slice(0, 240);
        throw new Error(message || "Owner was not saved; refresh before retrying.");
      }
      const result = await response.json();
      if (!result || result.verification !== "not-performed" || result.generation !== expectedGeneration + 1 ||
          !Array.isArray(result.records) || result.records.length !== 1 ||
          result.records[0].fingerprint !== fingerprint || result.records[0].owner !== owner) {
        throw new Error("Save outcome could not be confirmed; refresh before retrying.");
      }
      const loaded = await refresh();
      listStatus.textContent = loaded ? "Manual owner note saved. Make a new full snapshot; backup is not automatic." :
        "Owner may have been saved, but inventory could not be reloaded. Refresh before another change.";
    } catch (error) {
      ownerStatus.textContent = error instanceof Error ? error.message : "Owner was not saved; refresh before retrying.";
    } finally {
      editingOwner = false;
      ownerButton.disabled = false;
      updateImportControls();
      refreshButton.disabled = false;
    }
  });

  ownerCancel.addEventListener("click", function () {
    if (editingOwner) return;
    selectedOwnerFingerprint = null;
    originalOwner = null;
    ownerPanel.hidden = true;
  });

  async function changeLocation(action) {
    if (changingLocation || saving || associating || editingOwner || deleting || !selectedManageFingerprint || !displayedGeneration) return;
    const old = oldLocation.value;
    const index = selectedManageLocations.indexOf(old);
    if (index < 0) {
      locationManageStatus.textContent = "Select a listed location; refresh if it changed.";
      return;
    }
    const replacement = replacementLocation.value;
    if (action === "rename" && (!replacement || !validLabel(replacement) || replacement === old || selectedManageLocations.includes(replacement))) {
      locationManageStatus.textContent = "Enter a different, unused plain-text name of up to 128 bytes.";
      return;
    }
    if (action === "remove" && !confirmRemove.checked) {
      locationManageStatus.textContent = "Confirm that only the inventory note will be removed.";
      return;
    }
    const fingerprint = selectedManageFingerprint;
    const expectedGeneration = displayedGeneration;
    const expectedLocations = selectedManageLocations.slice();
    if (action === "rename") expectedLocations[index] = replacement;
    else expectedLocations.splice(index, 1);
    const body = { fingerprint, old_location: old, action, expected_generation: expectedGeneration };
    if (action === "rename") body.new_location = replacement;
    changingLocation = true;
    renameLocationButton.disabled = true;
    removeLocationButton.disabled = true;
    saveButton.disabled = true;
    refreshButton.disabled = true;
    locationManageStatus.textContent = action === "rename" ? "Renaming your manual note…" : "Removing your manual note…";
    try {
      const response = await fetch("/api/inventory/locations/change", { method: "POST", credentials: "same-origin", cache: "no-store",
        headers: { "Content-Type": "application/json", "X-Rootwell-Request": "1" }, body: JSON.stringify(body) });
      if (!response.ok) {
        const message = (await response.text()).trim().slice(0, 240);
        throw new Error(message || "Location change was not confirmed; refresh before retrying.");
      }
      const result = await response.json();
      const record = result?.records?.[0];
      if (!result || result.verification !== "not-performed" || result.generation !== expectedGeneration + 1 ||
          !Array.isArray(result.records) || result.records.length !== 1 || !record || record.fingerprint !== fingerprint ||
          !Array.isArray(record.locations) || record.locations.length !== expectedLocations.length ||
          record.locations.some((label, position) => label !== expectedLocations[position]) ||
          record.location !== (expectedLocations[0] || "")) {
        throw new Error("Location change outcome could not be confirmed; refresh before retrying.");
      }
      const loaded = await refresh();
      listStatus.textContent = loaded ? "Manual location note changed. Make a new full snapshot; backup is not automatic." :
        "Location may have changed, but inventory could not be reloaded. Refresh before another change.";
    } catch (error) {
      locationManageStatus.textContent = error instanceof Error ? error.message : "Location change was not confirmed; refresh before retrying.";
    } finally {
      changingLocation = false;
      renameLocationButton.disabled = false;
      removeLocationButton.disabled = false;
      updateImportControls();
      refreshButton.disabled = false;
    }
  }

  locationManageForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    await changeLocation("rename");
  });
  removeLocationButton.addEventListener("click", async function () {
    await changeLocation("remove");
  });
  locationManageCancel.addEventListener("click", function () {
    if (changingLocation) return;
    selectedManageFingerprint = null;
    selectedManageLocations = [];
    locationManagePanel.hidden = true;
  });

  refreshButton.addEventListener("click", refresh);
  function changeView() {
    if (!displayedGeneration || saving || associating || editingOwner || changingLocation || deleting) return;
    selectedFingerprint = null;
    selectedOwnerFingerprint = null;
    selectedManageFingerprint = null;
    selectedDeleteFingerprint = null;
    selectedManageLocations = [];
    originalOwner = null;
    locationPanel.hidden = true;
    ownerPanel.hidden = true;
    locationManagePanel.hidden = true;
    deletePanel.hidden = true;
    draw();
  }
  expiryFilter.addEventListener("change", changeView);
  inventorySearch.addEventListener("input", changeView);
  warningDays.addEventListener("change", function () {
    if (!["7", "14", "30", "90"].includes(warningDays.value)) warningDays.value = "30";
    changeView();
  });

  function tick() {
    clearTimeout(timer);
    if (document.hidden) return;
    updateMonitor();
    updateImportControls();
    const editing = saving || previewing || importFiles !== null || associating || editingOwner || changingLocation || deleting ||
      !locationPanel.hidden || !ownerPanel.hidden || !locationManagePanel.hidden || !deletePanel.hidden ||
      document.querySelector(".record-details[open]") !== null;
    if (autoRefresh.checked && !automaticPaused && !refreshing && !editing && !globalThis.rootwellInventoryLifecycle?.isOpen() && snapshotAge() >= 60000) {
      void refresh();
    }
    timer = setTimeout(tick, 15000);
  }
  function suspend() {
    globalThis.rootwellInventoryLifecycle?.invalidate();
    if (saving) saveStatus.textContent = "Save may have completed before the view changed. Refresh before another import.";
    saveController?.abort();
    clearImportPreview(true);
    clearTimeout(timer);
    ++loadSerial;
    refreshController?.abort();
    refreshController = null;
    refreshing = false;
    refreshButton.disabled = false;
    displayedGeneration = 0;
    loadedRecords = [];
    checkedAt = null;
    receivedAt = null;
    receivedWall = null;
    selectedFingerprint = selectedOwnerFingerprint = selectedManageFingerprint = selectedDeleteFingerprint = null;
    selectedManageLocations = [];
    originalOwner = null;
    list.replaceChildren();
    counts.replaceChildren();
    clockAsOf.textContent = "";
    locationPanel.hidden = ownerPanel.hidden = locationManagePanel.hidden = deletePanel.hidden = true;
    for (const target of [locationTarget, ownerTarget, locationManageTarget, deleteTarget, locationStatus, ownerStatus, locationManageStatus, deleteStatus]) target.textContent = "";
    for (const input of [newLocation, newOwner, replacementLocation, deleteFingerprint, ownerInput, locationInput, inventorySearch, fileInput]) input.value = "";
    oldLocation.replaceChildren();
    confirmRemove.checked = confirmDelete.checked = false;
    monitorSummary.textContent = "Monitoring paused while this page is hidden. Refresh on return.";
    updateImportControls();
  }
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) suspend();
    else { if (!saving && !associating && !editingOwner && !changingLocation && !deleting) void refresh(); tick(); }
  });
  window.addEventListener("pagehide", suspend);
  window.addEventListener("pageshow", function (event) {
    if (event.persisted && !document.hidden) { void refresh(); tick(); }
  });
  deleteForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    if (deleting || saving || associating || editingOwner || changingLocation || !selectedDeleteFingerprint || !displayedGeneration) return;
    const fingerprint = selectedDeleteFingerprint;
    const typed = deleteFingerprint.value;
    if (typed !== fingerprint || !confirmDelete.checked) {
      deleteStatus.textContent = "Type the exact full fingerprint and confirm the backup warning before deleting.";
      return;
    }
    const expectedGeneration = displayedGeneration;
    deleting = true;
    displayedGeneration = 0;
    deleteButton.disabled = true;
    saveButton.disabled = true;
    refreshButton.disabled = true;
    deleteStatus.textContent = "Removing this record from the current encrypted inventory…";
    try {
      const response = await fetch("/api/inventory/delete", { method: "POST", credentials: "same-origin", cache: "no-store",
        headers: { "Content-Type": "application/json", "X-Rootwell-Request": "1" },
        body: JSON.stringify({ fingerprint, typed_fingerprint: typed, confirmation: "delete-public-record", expected_generation: expectedGeneration }) });
      if (!response.ok) {
        const message = (await response.text()).trim().slice(0, 240);
        throw new Error(message || "Deletion was not confirmed; refresh before retrying.");
      }
      const result = await response.json();
      if (!result || result.deleted !== true || result.fingerprint !== fingerprint || result.generation !== expectedGeneration + 1 ||
          result.verification !== "not-performed") {
        throw new Error("Deletion outcome could not be confirmed; refresh before retrying.");
      }
      const loaded = await refresh();
      if (!loaded || displayedGeneration !== result.generation || loadedRecords.some(record => record.fingerprint === fingerprint)) {
        displayedGeneration = 0;
        listStatus.textContent = "Deletion may have happened, but the current inventory could not be confirmed. Refresh before another change.";
        return;
      }
      listStatus.textContent = "Record removed from the current inventory. Older snapshots may still contain it; make a new full snapshot.";
    } catch (error) {
      deleteStatus.textContent = error instanceof Error ? error.message : "Deletion was not confirmed; refresh before retrying.";
    } finally {
      deleting = false;
      deleteButton.disabled = false;
      updateImportControls();
      refreshButton.disabled = false;
    }
  });
  deleteCancel.addEventListener("click", function () {
    if (deleting) return;
    selectedDeleteFingerprint = null;
    deletePanel.hidden = true;
  });
  refresh();
  tick();
}());
