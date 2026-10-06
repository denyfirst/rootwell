"use strict";

// Only a fixed, authenticated same-origin asset request. Selected file bytes
// never enter this loader. The standalone Workbench loader remains unchanged.
(function () {
  let finish;
  let fail;
  const ready = new Promise((resolve, reject) => { finish = resolve; fail = reject; });
  const controller = new AbortController();
  const deadline = setTimeout(() => { controller.abort(); fail(new Error("Local public certificate engine unavailable.")); }, 20000);
  globalThis.rootwellWasmReady = function () {
    if (typeof globalThis.rootwellExplore !== "function" || typeof globalThis.rootwellExportBundle !== "function" ||
        typeof globalThis.rootwellExport !== "function" || globalThis.rootwellInspectMaxBytes !== 16 * 1024 * 1024) {
      fail(new Error("Local public certificate engine unavailable."));
      return;
    }
    finish(Object.freeze({ explore: globalThis.rootwellExplore, exportBundle: globalThis.rootwellExportBundle,
      exportPublic: globalThis.rootwellExport }));
  };
  Object.defineProperty(globalThis, "rootwellInventoryEngineReady", { value: ready.finally(() => {
    clearTimeout(deadline);
    delete globalThis.rootwellWasmReady;
  }) });
  // A failed asset must not become an unhandled rejection before Preview.
  globalThis.rootwellInventoryEngineReady.catch(() => {});
  (async function () {
    try {
      if (typeof Go !== "function") throw new Error();
      const go = new Go();
      const response = await fetch("/rootwell.wasm", { credentials: "same-origin", cache: "no-store", redirect: "error", signal: controller.signal });
      if (!response.ok) throw new Error();
      const result = await WebAssembly.instantiateStreaming(response, go.importObject);
      if (controller.signal.aborted) return;
      void go.run(result.instance).catch(() => fail(new Error("Local public certificate engine unavailable.")));
    } catch { fail(new Error("Local public certificate engine unavailable.")); }
  }());
}());
