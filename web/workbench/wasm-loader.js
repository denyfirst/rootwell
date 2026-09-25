"use strict";

(function () {
  const ready = new Promise(function (resolve, reject) {
    let settled = false;

    function fail() {
      if (settled) return;
      settled = true;
      reject(new Error("Rootwell local engine unavailable"));
    }

    globalThis.rootwellWasmReady = function () {
      if (settled) return;
      if (typeof globalThis.rootwellInspect !== "function" ||
          typeof globalThis.rootwellExplore !== "function" ||
          typeof globalThis.rootwellAnalyze !== "function" ||
          typeof globalThis.rootwellExportBundle !== "function" ||
          typeof globalThis.rootwellVerifySimple !== "function" ||
          typeof globalThis.rootwellVerifyExplicit !== "function" ||
          typeof globalThis.rootwellExport !== "function" ||
          !Number.isSafeInteger(globalThis.rootwellInspectMaxBytes)) {
        fail();
        return;
      }
      settled = true;
      resolve(Object.freeze({
        inspect: globalThis.rootwellInspect,
        explore: globalThis.rootwellExplore,
        analyze: globalThis.rootwellAnalyze,
        exportBundle: globalThis.rootwellExportBundle,
        verifySimple: globalThis.rootwellVerifySimple,
        verifyExplicit: globalThis.rootwellVerifyExplicit,
        exportPublic: globalThis.rootwellExport,
        maxBytes: globalThis.rootwellInspectMaxBytes
      }));
    };

    if (typeof Go !== "function" || typeof WebAssembly !== "object") {
      fail();
      return;
    }

    const go = new Go();
    fetch("rootwell.wasm", {
      cache: "no-store",
      credentials: "omit",
      redirect: "error"
    }).then(function (response) {
      if (!response.ok) throw new Error("Rootwell WebAssembly asset unavailable");
      if (typeof WebAssembly.instantiateStreaming === "function") {
        return WebAssembly.instantiateStreaming(response, go.importObject);
      }
      return response.arrayBuffer().then(function (bytes) {
        return WebAssembly.instantiate(bytes, go.importObject);
      });
    }).then(function (module) {
      return go.run(module.instance);
    }).then(fail, fail);
  });

  Object.defineProperty(globalThis, "rootwellWorkbenchReady", {
    configurable: false,
    enumerable: false,
    writable: false,
    value: ready.finally(function () {
      try {
        delete globalThis.rootwellWasmReady;
      } catch {
        // The one-shot callback has no file or network capability.
      }
    })
  });
})();
