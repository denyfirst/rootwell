"use strict";

(async function () {
  const result = document.getElementById("result");
  let der;
  let password;
  let exported;
  let stage = "engine";
  try {
    const engine = await rootwellWorkbenchReady;
    stage = "generate";
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    stage = "inspect";
    const inspected = JSON.parse(await rootwellPrivateWorker.run(engine.module, "inspect", der,
      new Uint8Array(), "", "", new Uint8Array(), new AbortController().signal));
    if (!inspected.ok || inspected.result.algorithm !== "ECDSA" || inspected.result.input_format !== "pkcs8-der") {
      throw new Error("synthetic inspection failed");
    }
    password = new TextEncoder().encode("synthetic-browser-password-12345");
    stage = "export";
    const response = await rootwellPrivateWorker.run(engine.module, "export", der, new Uint8Array(),
      inspected.result.public_fingerprint, "encrypted-pkcs8-pem", password, new AbortController().signal);
    exported = response.result && response.result.bytes;
    if (!response.ok || !(exported instanceof Uint8Array) || exported.length < 100 ||
        !new TextDecoder().decode(exported.subarray(0, 37)).startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
      throw new Error("synthetic export failed");
    }
    stage = "encrypted-import";
    const reopened = JSON.parse(await rootwellPrivateWorker.run(engine.module, "inspect", exported,
      password, "", "", new Uint8Array(), new AbortController().signal));
    if (!reopened.ok || reopened.result.input_format !== "encrypted-pkcs8-pem" ||
        reopened.result.public_fingerprint !== inspected.result.public_fingerprint) {
      throw new Error("synthetic encrypted import failed");
    }
    result.textContent = "PASS: browser worker inspected, encrypted, and reopened a generated synthetic key without a download.";
  } catch {
    result.textContent = "FAIL: browser worker could not complete the synthetic key test at " + stage + ".";
  } finally {
    if (der) der.fill(0);
    if (password) password.fill(0);
    if (exported) exported.fill(0);
  }
})();
