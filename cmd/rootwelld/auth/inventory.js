"use strict";

(function () {
  const form = document.getElementById("inventory-form");
  const fileInput = document.getElementById("certificate-file");
  const ownerInput = document.getElementById("owner");
  const locationInput = document.getElementById("location");
  const saveButton = document.getElementById("save-button");
  const saveStatus = document.getElementById("save-status");
  const refreshButton = document.getElementById("refresh-button");
  const listStatus = document.getElementById("list-status");
  const counts = document.getElementById("counts");
  const list = document.getElementById("records");
  const locationPanel = document.getElementById("location-panel");
  const locationForm = document.getElementById("location-form");
  const locationTarget = document.getElementById("location-target");
  const newLocation = document.getElementById("new-location");
  const locationButton = document.getElementById("location-button");
  const locationCancel = document.getElementById("location-cancel");
  const locationStatus = document.getElementById("location-status");
  const encoder = new TextEncoder();
  let loadSerial = 0;
  let saving = false;
  let associating = false;
  let selectedFingerprint = null;
  let displayedGeneration = 0;

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
    if (start === null || end === null || start > end) return { name: "Invalid date range", group: "invalid" };
    if (now < start) return { name: "Not yet valid", group: "future" };
    if (now > end) return { name: "Expired", group: "expired" };
    const days = (end - now) / 86400000;
    if (days <= 30) return { name: "Expires within 30 days", group: "soon" };
    if (days <= 90) return { name: "Expires in 31–90 days", group: "medium" };
    return { name: "More than 90 days left", group: "later" };
  }

  function addText(parent, tag, value, className) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = value;
    parent.appendChild(node);
  }

  function render(data) {
    if (!data || !Number.isSafeInteger(data.generation) || data.generation < 1 ||
        !Array.isArray(data.records) || data.records.length > 500 || data.verification !== "not-performed") {
      throw new Error("Inventory response was not recognized");
    }
    const now = Date.now();
    const records = data.records.slice();
    const fingerprints = new Set();
    for (const record of records) {
      if (!record || typeof record.fingerprint !== "string" || record.fingerprint.length > 128 ||
          typeof record.subject !== "string" || typeof record.issuer !== "string" ||
          typeof record.owner !== "string" || typeof record.location !== "string" ||
          !Array.isArray(record.locations) || record.locations.length > 32 ||
          (record.imported_at !== undefined && (typeof record.imported_at !== "string" || safeDate(record.imported_at) === null)) ||
          !Array.isArray(record.dns_names) || record.dns_names.length > 128 ||
          !Number.isSafeInteger(record.import_generation) || record.import_generation < 2 || record.import_generation > data.generation) {
        throw new Error("Inventory record was not recognized");
      }
      if (fingerprints.has(record.fingerprint) || record.locations.some(value => typeof value !== "string" || !value || !validLabel(value)) ||
          new Set(record.locations).size !== record.locations.length ||
          (record.locations.length ? record.locations[0] !== record.location : record.location !== "")) {
        throw new Error("Inventory locations were not recognized");
      }
      fingerprints.add(record.fingerprint);
      record.expiry = expiryState(record, now);
    }
    displayedGeneration = data.generation;
    selectedFingerprint = null;
    locationPanel.hidden = true;
    locationStatus.textContent = "";
    records.sort((a, b) => (safeDate(a.not_after) ?? Number.NEGATIVE_INFINITY) - (safeDate(b.not_after) ?? Number.NEGATIVE_INFINITY));
    list.replaceChildren();
    counts.replaceChildren();
    const totals = { expired: 0, soon: 0, medium: 0, later: 0, future: 0, invalid: 0 };
    for (const record of records) {
      totals[record.expiry.group]++;
      const item = document.createElement("li");
      addText(item, "strong", record.subject || "Subject not provided");
      addText(item, "span", record.expiry.name, "state " + record.expiry.group);
      addText(item, "small", "Expires: " + record.not_after + " · Import batch " + record.import_generation);
      if (record.imported_at) addText(item,"small","Saved at (server clock): " + record.imported_at);
      addText(item, "small", "Owner: " + (record.owner || "Unknown") + " · Manually listed locations: " +
        (record.locations.length ? record.locations.join(" · ") : "Unknown"));
      addText(item, "small", "Deployment at these locations has not been checked.");
      addText(item, "small", "SHA-256: " + record.fingerprint);
      const addButton = document.createElement("button");
      addButton.type = "button";
      addButton.className = "secondary";
      addButton.textContent = "Add another location";
      addButton.disabled = record.locations.length >= 32;
      addButton.addEventListener("click", function () {
        if (saving || associating || !displayedGeneration) return;
        selectedFingerprint = record.fingerprint;
        locationTarget.textContent = "Certificate: " + (record.subject || record.fingerprint) + " · SHA-256: " + record.fingerprint;
        newLocation.value = "";
        locationStatus.textContent = "";
        locationPanel.hidden = false;
      });
      item.appendChild(addButton);
      list.appendChild(item);
    }
    for (const [name, value] of Object.entries(totals)) {
      if (value) addText(counts, "span", name + ": " + value);
    }
    listStatus.textContent = records.length ? records.length + " saved public certificate(s) · inventory generation " + data.generation :
      "No certificates saved yet. This is not a trust store.";
  }

  async function refresh() {
    const serial = ++loadSerial;
    refreshButton.disabled = true;
    displayedGeneration = 0;
    selectedFingerprint = null;
    locationPanel.hidden = true;
    listStatus.textContent = "Reading encrypted inventory…";
    try {
      const response = await fetch("/api/inventory", { method: "GET", credentials: "same-origin", cache: "no-store",
        headers: { "X-Rootwell-Request": "1" } });
      if (serial !== loadSerial) return;
      if (!response.ok) {
        const message = (await response.text()).trim().slice(0, 240);
        throw new Error(message || "Inventory could not be opened");
      }
      render(await response.json());
      return true;
    } catch (error) {
      if (serial !== loadSerial) return;
      list.replaceChildren();
      counts.replaceChildren();
      listStatus.textContent = error instanceof Error ? error.message : "Inventory could not be opened";
      return false;
    } finally {
      if (serial === loadSerial) refreshButton.disabled = false;
    }
  }

  form.addEventListener("submit", async function (event) {
    event.preventDefault();
    if (saving || associating) return;
    const file = fileInput.files && fileInput.files[0];
    const owner = ownerInput.value;
    const location = locationInput.value;
    if (!file || file.size < 1 || file.size > (16 << 20)) {
      saveStatus.textContent = "Choose one public certificate file up to 16 MiB.";
      return;
    }
    if (!validLabel(owner) || !validLabel(location)) {
      saveStatus.textContent = "Owner and location must be short, plain-text labels (up to 128 bytes).";
      return;
    }
    saving = true;
    saveButton.disabled = true;
    saveStatus.textContent = "Reading the selected file, then sending it only to this Rootwell server…";
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      if (bytes.length !== file.size) throw new Error("File changed while being read; choose it again.");
      let certificate;
      try { certificate = base64(bytes); } finally { bytes.fill(0); }
      const response = await fetch("/api/inventory", { method: "POST", credentials: "same-origin", cache: "no-store",
        headers: { "Content-Type": "application/json", "X-Rootwell-Request": "1" },
        body: JSON.stringify({ certificate, owner, location }) });
      if (!response.ok) {
        const message = (await response.text()).trim().slice(0, 240);
        throw new Error(message || "Public certificate was not saved");
      }
      const result = await response.json();
      if (!result || !Array.isArray(result.records) || result.records.length < 1 || result.verification !== "not-performed") {
        throw new Error("Save outcome could not be confirmed; refresh before retrying.");
      }
      saveStatus.textContent = result.records.length + " public certificate(s) saved. Make a new full inventory snapshot; backup is not automatic.";
      fileInput.value = "";
      await refresh();
    } catch (error) {
      saveStatus.textContent = error instanceof Error ? error.message : "Save outcome could not be confirmed; refresh before retrying.";
    } finally {
      saving = false;
      saveButton.disabled = false;
    }
  });

  locationForm.addEventListener("submit", async function (event) {
    event.preventDefault();
    if (associating || saving || !selectedFingerprint || !displayedGeneration) return;
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
      saveButton.disabled = false;
      refreshButton.disabled = false;
    }
  });

  locationCancel.addEventListener("click", function () {
    if (associating) return;
    selectedFingerprint = null;
    locationPanel.hidden = true;
  });

  refreshButton.addEventListener("click", refresh);
  refresh();
}());
