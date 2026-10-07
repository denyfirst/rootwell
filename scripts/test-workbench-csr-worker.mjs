import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

class Module {}
const workers = [], timers = new Map(); let sequence = 0;
class Worker {
  constructor(path) { assert.equal(path, "csr-worker.js"); this.messages = []; workers.push(this); }
  postMessage(message, transfer = []) { this.messages.push(structuredClone(message, { transfer })); }
  terminate() { this.terminated = true; }
}
const context = vm.createContext({ WebAssembly: { Module }, Uint8Array, Worker,
  setTimeout(fn, ms) { timers.set(++sequence, { fn, ms }); return sequence; }, clearTimeout(id) { timers.delete(id); } });
vm.runInContext(fs.readFileSync("web/workbench/csr-worker-client.js", "utf8"), context);
const run = context.rootwellCSRWorker.run, source = Uint8Array.of(65), secret = Uint8Array.of(80), empty = new Uint8Array();
const message = (data, origin = "", source = null) => ({ data, origin, source });
const success = run(new Module(), "generate", empty, empty, secret, "{}", new AbortController().signal);
const first = workers.at(-1);
assert.equal(timers.values().next().value.ms, 180000);
first.onmessage(message({ type: "ready" }));
assert.equal(first.messages[1].type, "operate");
assert.deepEqual([...new Uint8Array(first.messages[1].password)], [80]);
first.onmessage(message({ type: "result", operation: "generate", answer: { ok: true } }));
assert.equal((await success).ok, true); assert.equal(first.terminated, true); assert.equal(timers.size, 0); assert.equal(secret[0], 80);
for (const operation of ["key", "inspect", "convert", "match", "certificate-key-match"]) {
  const pending = run(new Module(), operation, source, empty, empty, "", new AbortController().signal);
  const worker = workers.at(-1);
  assert.equal(timers.values().next().value.ms, operation === "key" ? 90000 : 30000);
  timers.values().next().value.fn(); await assert.rejects(pending); assert.equal(worker.terminated, true);
  worker.onmessage(message({ type: "ready" })); assert.equal(worker.messages.length, 1, "timeout transferred late secrets");
}
const controller = new AbortController();
const pending = run(new Module(), "key", source, empty, secret, "{}", controller.signal);
const cancelled = workers.at(-1); cancelled.onmessage(message({ type: "ready" })); controller.abort(); await assert.rejects(pending); assert.equal(cancelled.terminated, true);
const premature = run(new Module(), "inspect", source, empty, empty, "", new AbortController().signal);
workers.at(-1).onmessage(message({ type: "result", operation: "inspect", answer: "unexpected" })); await assert.rejects(premature);
for (const invalid of [message({ type: "ready" }, "https://untrusted.invalid"), message({ type: "ready" }, "", {}), { data: { type: "ready" } }]) {
  const waiting = run(new Module(), "key", source, empty, secret, "{}", new AbortController().signal);
  const worker = workers.at(-1); worker.onmessage(invalid); assert.equal(worker.terminated, true, "foreign readiness was accepted"); await assert.rejects(waiting);
  assert.equal(worker.messages.length, 1, "foreign message transferred secrets"); assert.equal(worker.terminated, true);
}
await assert.rejects(run(new Module(), "inspect", source, empty, empty, "", { aborted: false }));
await assert.rejects(run(new Module(), "inspect", new Uint8Array(65537), empty, empty, "", new AbortController().signal));

async function workerCase(malformed = false) {
  const posted = []; let input, password, output, csr;
  const scope = { Uint8Array, ArrayBuffer, WebAssembly: { Module, instantiate: async () => ({}) },
    importScripts(path) { assert.equal(path, "wasm_exec.js"); }, postMessage(message, transfer = []) { posted.push(structuredClone(message, { transfer })); }, close() { this.closed = true; } };
  scope.self = scope;
  scope.Go = class {
    constructor() { this.importObject = {}; }
    run() {
      scope.rootwellCSROperate = (_operation, bytes, _certificate, secret) => {
        input = bytes; password = secret; output = Uint8Array.of(0x50, 0x4b); csr = Uint8Array.of(45, 45);
        return { schema_version: "rootwell.browser.csr.v1", ok: true, error: null, result: { bytes: output, csr: malformed ? "unsafe" : csr } };
      };
      scope.rootwellWasmReady(); return new Promise(() => {});
    }
  };
  const workerContext = vm.createContext(scope); vm.runInContext(fs.readFileSync("web/workbench/csr-worker.js", "utf8"), workerContext);
  scope.onmessage(message({ type: "init", module: new Module() })); await new Promise(resolve => setImmediate(resolve));
  assert.equal(posted[0].type, "ready");
  scope.onmessage(message({ type: "operate", operation: "key", input: source.slice().buffer, certificate: empty.slice().buffer, password: secret.slice().buffer, option: "{}" }));
  assert.equal(scope.closed, true); assert.equal(input[0], 0); assert.equal(password[0], 0);
  if (malformed) { assert.equal(posted[1].type, "failure"); assert.equal(output[0], 0, "refused key package retained"); }
  else { assert.equal(posted[1].type, "result"); assert.deepEqual([...posted[1].answer.result.bytes], [0x50, 0x4b]); assert.deepEqual([...posted[1].answer.result.csr], [45, 45]); }
  scope.onmessage(message({ type: "operate" })); assert.equal(posted.at(-1).type, "failure", "worker was reusable");
}
await workerCase(); await workerCase(true);
for (const invalid of [message({ type: "init", module: new Module() }, "https://untrusted.invalid"), message({ type: "init", module: new Module() }, "", {}), { data: { type: "init", module: new Module() } }]) {
  const posted = []; let instantiated = false;
  const scope = { importScripts() {}, postMessage(value) { posted.push(value); }, close() { this.closed = true; }, Go: class { constructor() { this.importObject = {}; } }, WebAssembly: { Module, instantiate() { instantiated = true; return Promise.resolve({}); } } };
  scope.self = scope; vm.runInContext(fs.readFileSync("web/workbench/csr-worker.js", "utf8"), vm.createContext(scope));
  scope.onmessage(invalid); assert.equal(instantiated, false); assert.equal(scope.closed, true); assert.equal(posted[0].type, "failure");
}
console.log("CSR one-shot worker deadlines, abort/readiness, transfer, malformed response and buffer clearing passed.");
