"use strict";

(function () {
  function run(module, operation, inputs, password, secondPassword, option, signal) {
    if (!(module instanceof WebAssembly.Module) || !["inspect", "certificate", "key", "create"].includes(operation) ||
        !Array.isArray(inputs) || inputs.length !== 3 ||
        !inputs.every((item, index) => item instanceof Uint8Array && item.length <= [1 << 20, 64 << 10, 1 << 20][index]) ||
        !(password instanceof Uint8Array) || password.length > 128 ||
        !(secondPassword instanceof Uint8Array) || secondPassword.length > (operation === "create" ? 256 : 128) ||
        typeof option !== "string" || option.length > 99 || signal.aborted || typeof Worker !== "function") {
      return Promise.reject(new Error("PFX worker unavailable"));
    }
    const owned = [...inputs.map(item => item.slice()), password.slice(), secondPassword.slice()];
    return new Promise(function (resolve, reject) {
      let worker;
      let timer;
      let finished = false;
      let sent = false;
      function finish(failed, answer) {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        signal.removeEventListener("abort", abort);
        if (worker) worker.terminate();
        for (const bytes of owned) if (bytes.byteLength) bytes.fill(0);
        if (failed) reject(new Error("PFX worker failed or timed out"));
        else resolve(answer);
      }
      function abort() { finish(true); }
      try {
        worker = new Worker("pfx-worker.js", { name: "rootwell-pfx" });
        signal.addEventListener("abort", abort, { once: true });
        timer = setTimeout(() => finish(true), operation === "inspect" ? 45000 : 90000);
        worker.onerror = () => finish(true);
        worker.onmessage = function (event) {
          if (finished) return;
          const message = event.data;
          if (!message || typeof message !== "object") { finish(true); return; }
          if (!sent && message.type === "ready") {
            sent = true;
            try {
              worker.postMessage({ type: "operate", operation, inputs: owned.slice(0, 3).map(item => item.buffer),
                password: owned[3].buffer, secondPassword: owned[4].buffer, option }, owned.map(item => item.buffer));
            } catch { finish(true); }
          } else if (sent && message.type === "result" && message.operation === operation) {
            finish(false, message.answer);
          } else {
            finish(true);
          }
        };
        worker.postMessage({ type: "init", module });
        if (signal.aborted) finish(true);
      } catch { finish(true); }
    });
  }

  Object.defineProperty(globalThis, "rootwellPFXWorker", {
    configurable: false, enumerable: false, writable: false, value: Object.freeze({ run })
  });
})();
