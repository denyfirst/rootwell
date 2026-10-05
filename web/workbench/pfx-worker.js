"use strict";

importScripts("wasm_exec.js");

let initialized = false;
let ready = false;
let used = false;

function refuse() { self.postMessage({ type: "failure" }); self.close(); }

self.rootwellWasmReady = function () {
  if (typeof self.rootwellPFXInspect !== "function" || typeof self.rootwellPFXOutput !== "function") {
    refuse(); return;
  }
  ready = true;
  self.postMessage({ type: "ready" });
};

self.onmessage = function (event) {
  const request = event.data;
  if (!initialized) {
    initialized = true;
    if (!request || request.type !== "init" || !(request.module instanceof WebAssembly.Module)) { refuse(); return; }
    try {
      const go = new Go();
      WebAssembly.instantiate(request.module, go.importObject).then(instance => go.run(instance)).then(refuse, refuse);
    } catch { refuse(); }
    return;
  }
  if (!ready || used || !request || request.type !== "operate") { refuse(); return; }
  used = true;
  let arrays;
  let output;
  try {
    if (!Array.isArray(request.inputs) || request.inputs.length !== 3 ||
        !request.inputs.every(item => item instanceof ArrayBuffer) ||
        !(request.password instanceof ArrayBuffer) || !(request.secondPassword instanceof ArrayBuffer) ||
        typeof request.option !== "string" || request.option.length > 99) throw new Error("invalid request");
    arrays = [...request.inputs.map(item => new Uint8Array(item)), new Uint8Array(request.password), new Uint8Array(request.secondPassword)];
    if (arrays.some((item, index) => item.length > [1 << 20, 64 << 10, 1 << 20, 128, request.operation === "create" ? 256 : 128][index])) throw new Error("invalid request");
    let answer;
    if (request.operation === "inspect" && arrays[0].length > 0 && arrays[0].length <= 1 << 20 &&
        arrays[1].length === 0 && arrays[2].length === 0 && arrays[3].length > 0 && arrays[4].length === 0 && request.option === "") {
      answer = self.rootwellPFXInspect(arrays[0], arrays[3]);
      if (typeof answer !== "string" || answer.length > 65536) throw new Error("invalid response");
    } else if (["certificate", "key", "create", "reveal"].includes(request.operation)) {
      answer = self.rootwellPFXOutput(request.operation, arrays[0], arrays[1], arrays[2], arrays[3], arrays[4], request.option);
      if (answer && answer.result && answer.result.bytes instanceof Uint8Array) output = answer.result.bytes;
      if (!answer || answer.schema_version !== "rootwell.browser.pfx.v1" || !answer.ok ||
          !answer.result || !output || output.length < 1 || output.length > 1 << 20) throw new Error("invalid response");
    } else throw new Error("invalid request");
    self.postMessage({ type: "result", operation: request.operation, answer }, output ? [output.buffer] : []);
  } catch { refuse(); }
  finally {
    if (arrays) for (const bytes of arrays) bytes.fill(0);
    if (output && output.byteLength) output.fill(0);
    self.close();
  }
};
