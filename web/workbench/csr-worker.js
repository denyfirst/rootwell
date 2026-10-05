"use strict";
importScripts("wasm_exec.js");
let initialized = false, ready = false, used = false;
function refuse() { self.postMessage({ type: "failure" }); self.close(); }
self.rootwellWasmReady = function () {
  if (typeof self.rootwellCSROperate !== "function") { refuse(); return; }
  ready = true;
  self.postMessage({ type: "ready" });
};
self.onmessage = function (event) {
  // Dedicated-worker messages use a private MessagePort channel: empty
  // origin and null source, not Window.postMessage or a shared-worker port.
  if (!event || event.origin !== "" || event.source !== null) { refuse(); return; }
  const request = event.data;
  if (!initialized) {
    initialized = true;
    if (!request || request.type !== "init" || !(request.module instanceof WebAssembly.Module)) { refuse(); return; }
    try { const go = new Go(); WebAssembly.instantiate(request.module, go.importObject).then(instance => go.run(instance)).then(refuse, refuse); }
    catch { refuse(); }
    return;
  }
  if (!ready || used || !request || request.type !== "operate") { refuse(); return; }
  used = true;
  let arrays, output, csr;
  try {
    if (!["generate", "key", "inspect", "convert", "match"].includes(request.operation) ||
        !(request.input instanceof ArrayBuffer) || !(request.certificate instanceof ArrayBuffer) || !(request.password instanceof ArrayBuffer) ||
        typeof request.option !== "string" || request.option.length > 16384) throw new Error("invalid request");
    arrays = [new Uint8Array(request.input), new Uint8Array(request.certificate), new Uint8Array(request.password)];
    if (arrays.some((bytes, index) => bytes.length > [64 << 10, 1 << 20, 256][index])) throw new Error("invalid request");
    const answer = self.rootwellCSROperate(request.operation, arrays[0], arrays[1], arrays[2], request.option);
    if (["inspect", "match"].includes(request.operation)) {
      if (typeof answer !== "string" || answer.length > 32768) throw new Error("invalid response");
    } else {
      output = answer && answer.result && answer.result.bytes;
      csr = answer && answer.result && answer.result.csr;
      if (!answer || answer.schema_version !== "rootwell.browser.csr.v1" || !answer.ok || answer.error !== null ||
          !(output instanceof Uint8Array) || !output.length || output.length > 256 << 10 ||
          !(csr instanceof Uint8Array) || !csr.length || csr.length > 96 << 10) throw new Error("invalid response");
    }
    self.postMessage({ type: "result", operation: request.operation, answer }, output ? [output.buffer, csr.buffer] : []);
  } catch { refuse(); }
  finally {
    if (arrays) for (const bytes of arrays) bytes.fill(0);
    if (output instanceof Uint8Array && output.byteLength) output.fill(0);
    if (csr instanceof Uint8Array && csr.byteLength) csr.fill(0);
    self.close();
  }
};
