"use strict";

// This worker receives secrets only after its runtime is ready. It cannot
// read files or access the DOM; the response CSP denies network connections.
importScripts("wasm_exec.js");

let initialized = false;
let ready = false;
let used = false;

function refuse() {
  self.postMessage({ type: "failure" });
  self.close();
}

self.rootwellWasmReady = function () {
  if (typeof self.rootwellPrivateInspect !== "function" || typeof self.rootwellPrivateExport !== "function") {
    refuse();
    return;
  }
  ready = true;
  self.postMessage({ type: "ready" });
};

self.onmessage = function (event) {
  const request = event.data;
  if (!initialized) {
    initialized = true;
    if (!request || request.type !== "init" || !(request.module instanceof WebAssembly.Module)) {
      refuse();
      return;
    }
    try {
      const go = new Go();
      WebAssembly.instantiate(request.module, go.importObject).then(function (instance) {
        return go.run(instance);
      }).then(refuse, refuse);
    } catch {
      refuse();
    }
    return;
  }
  if (!ready || used || !request || request.type !== "operate") {
    refuse();
    return;
  }
  used = true;
  let input;
  let currentPassword;
  let outputPassword;
  let output;
  try {
    if (!(request.input instanceof ArrayBuffer) || !(request.currentPassword instanceof ArrayBuffer) ||
        !(request.outputPassword instanceof ArrayBuffer)) throw new Error("invalid request");
    input = new Uint8Array(request.input);
    currentPassword = new Uint8Array(request.currentPassword);
    outputPassword = new Uint8Array(request.outputPassword);
    if (input.length < 1 || input.length > 64 * 1024 || currentPassword.length > 256 || outputPassword.length > 256) {
      throw new Error("invalid request");
    }
    if (request.operation === "inspect" && outputPassword.length === 0) {
      const answer = self.rootwellPrivateInspect(input, currentPassword);
      if (typeof answer !== "string" || answer.length > 2048) throw new Error("invalid response");
      self.postMessage({ type: "result", operation: "inspect", answer });
    } else if (request.operation === "export" && typeof request.fingerprint === "string" &&
               typeof request.format === "string" && request.fingerprint.length === 95 && request.format.length <= 32) {
      const answer = self.rootwellPrivateExport(input, request.fingerprint, currentPassword, request.format, outputPassword);
      if (answer && answer.result && answer.result.bytes instanceof Uint8Array) output = answer.result.bytes;
      if (!answer || answer.schema_version !== "rootwell.browser.private-convert.v1" ||
          !answer.ok || !answer.result || !output || output.length < 1 || output.length > 96 * 1024) {
        throw new Error("invalid response");
      }
      self.postMessage({ type: "result", operation: "export", answer }, [output.buffer]);
    } else {
      throw new Error("invalid request");
    }
  } catch {
    refuse();
  } finally {
    if (input) input.fill(0);
    if (currentPassword) currentPassword.fill(0);
    if (outputPassword) outputPassword.fill(0);
    if (output && output.byteLength) output.fill(0);
    self.close();
  }
};
