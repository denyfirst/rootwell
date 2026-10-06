"use strict";

// Public-only processing, with no DOM, network, storage or download capability.
(function () {
  const maxBytes = 16 * 1024 * 1024;
  const fingerprint = /^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$/;
  const encoder = new TextEncoder();
  function label(file, index) {
    const name = typeof file.name === "string" ? file.name.replace(/[\u0000-\u001f\u007f-\u009f\u2028-\u202e\u2066-\u2069]/gu, "?").slice(0, 120) : "public file";
    return "File " + (index + 1) + " (" + name + ")";
  }
  function explore(engine, bytes, source) {
    const raw = engine.explore(bytes);
    if (typeof raw !== "string" || raw.length > 4 * 1024 * 1024) throw new Error("Local certificate response was not recognized.");
    const response = JSON.parse(raw);
    if (!response || response.schema_version !== "rootwell.browser.explore.v1") throw new Error("Local certificate response was not recognized.");
    if (response.ok === false && response.result === null) {
      const code = response.error?.code;
      if (code === "duplicate-certificate") throw new Error(source + " contains a duplicate certificate. Remove the extra copy; nothing was saved.");
      if (code === "certificate-count-limit") throw new Error(source + " exceeds 64 certificates. Split this batch; nothing was saved.");
      throw new Error(source + " is not a supported public certificate file. Use a valid PEM certificate bundle or one DER certificate, not a private key or PFX. Nothing was saved.");
    }
    const result = response.result;
    if (response.ok !== true || response.error !== null || !result || result.verification !== "not-performed" ||
        result.trust_anchor !== "not-selected" || !Array.isArray(result.certificates) ||
        result.count < 1 || result.count > 64 || result.count !== result.certificates.length ||
        !result.certificates.every(cert => cert && fingerprint.test(cert.sha256) && typeof cert.subject === "string" &&
          typeof cert.issuer === "string" && typeof cert.is_ca === "boolean" && ["pem", "der"].includes(cert.encoding) &&
          typeof cert.not_before === "string" && typeof cert.not_after === "string" &&
          Number.isFinite(Date.parse(cert.not_before)) && Number.isFinite(Date.parse(cert.not_after)))) {
      throw new Error("Local certificate response was not recognized.");
    }
    return result.certificates;
  }
  async function read(files, current, operation) {
    if (!Array.isArray(files) || files.length < 1 || files.length > 8 ||
        files.some(file => !file || !Number.isSafeInteger(file.size) || file.size < 1) ||
        files.reduce((sum, file) => sum + file.size, 0) > maxBytes) {
      throw new Error("Choose 1–8 public files, up to 16 MiB combined. Nothing was saved.");
    }
    const inputs = [];
    try {
      const engine = await globalThis.rootwellInventoryEngineReady;
      if (!current()) throw new Error("Selection changed. Preview again.");
      for (const file of files) {
        if (!current()) throw new Error("Selection changed. Preview again.");
        const bytes = new Uint8Array(await file.arrayBuffer());
        inputs.push(bytes);
        if (!current() || bytes.length !== file.size) throw new Error("Selected files changed. Preview again; nothing was saved.");
      }
      return operation(engine, inputs);
    } finally { for (const bytes of inputs) bytes.fill(0); }
  }
  async function preview(files, current) {
    return read(files, current, (engine, inputs) => {
      const entries = [];
      const seen = new Map();
      let metadataBytes = 0;
      for (const [index, bytes] of inputs.entries()) {
        const source = label(files[index], index);
        for (const cert of explore(engine, bytes, source)) {
          if (seen.has(cert.sha256)) throw new Error("Duplicate certificate in " + seen.get(cert.sha256) + " and " + source + ". Remove one copy; nothing was saved.");
          if (entries.length === 64) throw new Error("This batch exceeds 64 certificates. Split it; nothing was saved.");
          metadataBytes += encoder.encode(cert.subject).length + encoder.encode(cert.issuer).length;
          if (metadataBytes > 512 * 1024) throw new Error("Certificate metadata exceeds the display limit.");
          // Inventory's per-object limit is narrower than the public parser.
          const exported = engine.exportPublic(bytes, cert.sha256, "der");
          const der = exported?.result?.bytes;
          try {
            if (exported?.schema_version !== "rootwell.browser.export.v1" || exported.ok !== true || exported.error !== null || exported.result.encoding !== "der" ||
                !(der instanceof Uint8Array) || der.length < 1 || der.length > 64 * 1024 || exported.result.fingerprint !== cert.sha256) {
              throw new Error(source + " cannot be prepared for inventory (maximum 64 KiB per certificate). Nothing was saved.");
            }
            const check = explore(engine, der, source);
            if (check.length !== 1 || check[0].sha256 !== cert.sha256 || check[0].encoding !== "der") throw new Error("Public certificate identity could not be confirmed.");
          } finally { if (der instanceof Uint8Array) der.fill(0); }
          seen.set(cert.sha256, source);
          entries.push(Object.freeze({ ...cert, source }));
        }
      }
      return Object.freeze(entries);
    });
  }
  async function prepare(files, expected, current) {
    if (!Array.isArray(expected) || !expected.length || expected.length > 64 || expected.some(value => !fingerprint.test(value))) {
      throw new Error("Preview the files before saving.");
    }
    return read(files, current, (engine, inputs) => {
      const output = engine.exportBundle(inputs, expected, expected);
      const bytes = output?.result?.bytes;
      try {
        if (output?.schema_version !== "rootwell.browser.bundle-export.v1" || output.ok !== true || output.error !== null ||
            !(bytes instanceof Uint8Array) || bytes.length < 1 || bytes.length > maxBytes ||
            !Array.isArray(output.result.fingerprints) || output.result.fingerprints.length !== expected.length ||
            !output.result.fingerprints.every((value, index) => value === expected[index])) throw new Error("Selected files changed. Preview again; nothing was saved.");
        const certificates = explore(engine, bytes, "Prepared public bundle");
        if (certificates.length !== expected.length || !certificates.every((cert, index) => cert.sha256 === expected[index] && cert.encoding === "pem")) {
          throw new Error("Prepared certificates did not match the preview. Nothing was saved.");
        }
        return bytes.slice();
      } finally { if (bytes instanceof Uint8Array) bytes.fill(0); }
    });
  }
  Object.defineProperty(globalThis, "rootwellInventoryImport", { value: Object.freeze({ preview, prepare }) });
}());
