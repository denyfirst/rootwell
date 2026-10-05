"use strict";

(function () {
  const INSPECT_DEADLINE_MS = 30000;
  const EXPORT_DEADLINE_MS = 60000;

  function run(module, operation, input, currentPassword, fingerprint, format, outputPassword, signal) {
    if (!(module instanceof WebAssembly.Module) || !["inspect", "export"].includes(operation) ||
        !(input instanceof Uint8Array) || input.length < 1 || input.length > 64 * 1024 ||
        !(currentPassword instanceof Uint8Array) || currentPassword.length > 256 ||
        !(outputPassword instanceof Uint8Array) || outputPassword.length > 256 ||
        signal.aborted || typeof Worker !== "function") {
      return Promise.reject(new Error("private worker unavailable"));
    }
    // Keep caller-owned buffers clearable while transferring distinct bounded
    // copies to the worker. Its own copies are cleared after each operation.
    const source = input.slice();
    const current = currentPassword.slice();
    const output = outputPassword.slice();
    return new Promise(function (resolve, reject) {
      let worker;
      let timer;
      let finished = false;
      let sent = false;
      function finish(error, answer) {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        signal.removeEventListener("abort", abort);
        if (worker) worker.terminate();
        if (source.byteLength) source.fill(0);
        if (current.byteLength) current.fill(0);
        if (output.byteLength) output.fill(0);
        if (error) reject(new Error("private worker failed or timed out"));
        else resolve(answer);
      }
      function abort() { finish(true); }
      try {
        worker = new Worker("private-key-worker.js", { name: "rootwell-private-key" });
        signal.addEventListener("abort", abort, { once: true });
        timer = setTimeout(function () { finish(true); }, operation === "inspect" ? INSPECT_DEADLINE_MS : EXPORT_DEADLINE_MS);
        worker.onerror = function () { finish(true); };
        worker.onmessage = function (event) {
          if (finished) return;
          const message = event.data;
          if (!message || typeof message !== "object") { finish(true); return; }
          if (!sent && message.type === "ready") {
            sent = true;
            try {
              worker.postMessage({ type: "operate", operation, input: source.buffer, currentPassword: current.buffer,
                outputPassword: output.buffer, fingerprint, format }, [source.buffer, current.buffer, output.buffer]);
            } catch { finish(true); }
          } else if (sent && message.type === "result" && message.operation === operation) {
            finish(false, message.answer);
          } else {
            finish(true);
          }
        };
        worker.postMessage({ type: "init", module });
        if (signal.aborted) finish(true);
      } catch {
        finish(true);
      }
    });
  }

  Object.defineProperty(globalThis, "rootwellPrivateWorker", {
    configurable: false, enumerable: false, writable: false, value: Object.freeze({ run })
  });
})();
