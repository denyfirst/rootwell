import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

class Module {}
const workers = [];
const timers = new Map();
let timerID = 0;
class FakeWorker {
  constructor(path) {
    assert.equal(path, "private-key-worker.js");
    this.messages = [];
    workers.push(this);
  }
  postMessage(message, transfer = []) {
    this.messages.push(structuredClone(message, { transfer }));
  }
  terminate() { this.terminated = true; }
}
const context = vm.createContext({
  WebAssembly: { Module }, Worker: FakeWorker, Uint8Array, AbortController,
  setTimeout(fn, ms) { const id = ++timerID; timers.set(id, { fn, ms }); return id; },
  clearTimeout(id) { timers.delete(id); }
});
vm.runInContext(fs.readFileSync("web/workbench/private-worker-client.js", "utf8"), context);
const run = context.rootwellPrivateWorker.run;
const source = Uint8Array.of(65, 66);
const current = Uint8Array.of(80);
const output = Uint8Array.of(81);
const success = run(new Module(), "export", source, current, "A".repeat(95), "encrypted-pkcs8-pem", output, new AbortController().signal);
const first = workers.at(-1);
assert.equal(first.messages[0].type, "init");
assert.equal(timers.size, 1);
first.onmessage({ data: { type: "ready" } });
assert.equal(first.messages[1].type, "operate");
assert.deepEqual([...new Uint8Array(first.messages[1].input)], [65, 66]);
assert.deepEqual([...new Uint8Array(first.messages[1].currentPassword)], [80]);
assert.deepEqual([...new Uint8Array(first.messages[1].outputPassword)], [81]);
first.onmessage({ data: { type: "result", operation: "export", answer: { ok: true } } });
assert.deepEqual(await success, { ok: true });
assert.equal(first.terminated, true);
assert.equal(timers.size, 0);
assert.deepEqual([...source], [65, 66], "caller-owned input must remain clearable");

const timed = run(new Module(), "inspect", source, current, "", "", new Uint8Array(), new AbortController().signal);
const second = workers.at(-1);
assert.equal([...timers.values()][0].ms, 30000);
timers.values().next().value.fn();
await assert.rejects(timed);
assert.equal(second.terminated, true);
assert.equal(second.messages.length, 1, "timeout before readiness must not transfer secrets");
second.onmessage({ data: { type: "ready" } });
assert.equal(second.messages.length, 1, "late worker response revived timed-out work");

const controller = new AbortController();
const cancelled = run(new Module(), "export", source, current, "", "", output, controller.signal);
const third = workers.at(-1);
third.onmessage({ data: { type: "ready" } });
controller.abort();
await assert.rejects(cancelled);
assert.equal(third.terminated, true);
assert.equal(timers.size, 0);

const wrong = run(new Module(), "inspect", source, current, "", "", new Uint8Array(), new AbortController().signal);
const fourth = workers.at(-1);
fourth.onmessage({ data: { type: "result", operation: "inspect", answer: "unrequested" } });
await assert.rejects(wrong);
assert.equal(fourth.terminated, true);

await assert.rejects(run(null, "inspect", source, current, "", "", new Uint8Array(), new AbortController().signal));
assert.equal(workers.length, 4, "invalid module unexpectedly started a worker");

async function exerciseWorker(operation) {
  const posted = [];
  let observedInput;
  let observedPassword;
  const workerGlobal = {
    WebAssembly: { Module, instantiate: async () => ({}) }, Uint8Array, ArrayBuffer,
    importScripts(path) { assert.equal(path, "wasm_exec.js"); },
    postMessage(message, transfer = []) { posted.push(structuredClone(message, { transfer })); },
    close() { this.closed = true; }
  };
  workerGlobal.self = workerGlobal;
  workerGlobal.Go = class {
    constructor() { this.importObject = {}; }
    run() {
      workerGlobal.rootwellPrivateInspect = (input, password) => {
        observedInput = input;
        observedPassword = password;
        return "public-summary";
      };
      workerGlobal.rootwellPrivateExport = (input, _fingerprint, password, _format, _outputPassword) => {
        observedInput = input;
        observedPassword = password;
        return { schema_version: "rootwell.browser.private-convert.v1", ok: true,
          result: { bytes: Uint8Array.of(65, 66) } };
      };
      workerGlobal.rootwellWasmReady();
      return new Promise(() => {});
    }
  };
  const workerContext = vm.createContext(workerGlobal);
  vm.runInContext(fs.readFileSync("web/workbench/private-key-worker.js", "utf8"), workerContext);
  workerGlobal.onmessage({ data: { type: "init", module: new Module() } });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(posted[0].type, "ready");
  workerGlobal.onmessage({ data: { type: "operate", operation,
    input: Uint8Array.of(65).buffer, currentPassword: Uint8Array.of(80).buffer,
    outputPassword: operation === "inspect" ? new Uint8Array().buffer : Uint8Array.of(81).buffer,
    fingerprint: "A".repeat(95), format: "encrypted-pkcs8-pem" } });
  assert.equal(posted[1].type, "result");
  assert.equal(posted[1].operation, operation);
  assert.equal(observedInput[0], 0, "worker retained input after response");
  assert.equal(observedPassword[0], 0, "worker retained password after response");
  if (operation === "export") assert.deepEqual([...posted[1].answer.result.bytes], [65, 66]);
  assert.equal(workerGlobal.closed, true, "one-shot worker did not close after the operation");
}
await exerciseWorker("inspect");
await exerciseWorker("export");
console.log("Private worker deadline, transfer, abort, and refusal tests passed.");
