"use strict";
(function () {
  function run(module, operation, input, certificate, password, option, signal) {
    if (!(module instanceof WebAssembly.Module) || !["generate", "key", "inspect", "convert", "match", "certificate-key-match"].includes(operation) ||
        !(input instanceof Uint8Array) || input.length > 64 << 10 || !(certificate instanceof Uint8Array) || certificate.length > 1 << 20 ||
        !(password instanceof Uint8Array) || password.length > 256 || typeof option !== "string" || option.length > 16384 ||
        !signal || typeof signal.addEventListener !== "function" || typeof signal.removeEventListener !== "function" || signal.aborted || typeof Worker !== "function") return Promise.reject(new Error("request worker unavailable"));
    const owned = [input.slice(), certificate.slice(), password.slice()];
    return new Promise((resolve, reject) => {
      let worker, timer;
      let finished = false, sent = false;
      function finish(failed, answer) {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        signal.removeEventListener("abort", abort);
        if (worker) worker.terminate();
        for (const bytes of owned) if (bytes.byteLength) bytes.fill(0);
        if (failed) reject(new Error("request worker failed or timed out"));
        else resolve(answer);
      }
      function abort() { finish(true); }
      try {
        worker = new Worker("csr-worker.js", { name: "rootwell-csr" });
        signal.addEventListener("abort", abort, { once: true });
        timer = setTimeout(() => finish(true), operation === "generate" ? 180000 : operation === "key" ? 90000 : 30000);
        worker.onerror = () => finish(true);
        worker.onmessage = event => {
          if (finished) return;
          if (!event || event.origin !== "" || event.source !== null) { finish(true); return; }
          const message = event.data;
          if (!message || typeof message !== "object") { finish(true); return; }
          if (!sent && message.type === "ready") {
            sent = true;
            try { worker.postMessage({ type: "operate", operation, input: owned[0].buffer, certificate: owned[1].buffer,
              password: owned[2].buffer, option }, owned.map(bytes => bytes.buffer)); }
            catch { finish(true); }
          } else if (sent && message.type === "result" && message.operation === operation) finish(false, message.answer);
          else finish(true);
        };
        worker.postMessage({ type: "init", module });
        if (signal.aborted) finish(true);
      } catch { finish(true); }
    });
  }
  Object.defineProperty(globalThis, "rootwellCSRWorker", { configurable: false, enumerable: false, writable: false, value: Object.freeze({ run }) });
})();
