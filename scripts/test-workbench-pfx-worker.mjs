import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

class Module {}
const workers = [];
const timers = new Map();
let timerID = 0;
class FakeWorker {
  constructor(path) { assert.equal(path, "pfx-worker.js"); this.messages = []; workers.push(this); }
  postMessage(message, transfer = []) { this.messages.push(structuredClone(message, { transfer })); }
  terminate() { this.terminated = true; }
}
const context = vm.createContext({
  WebAssembly: { Module }, Worker: FakeWorker, Uint8Array, AbortController,
  setTimeout(fn, ms) { const id = ++timerID; timers.set(id, { fn, ms }); return id; },
  clearTimeout(id) { timers.delete(id); }
});
vm.runInContext(fs.readFileSync("web/workbench/pfx-worker-client.js", "utf8"), context);
const run = context.rootwellPFXWorker.run;
const source = Uint8Array.of(1, 2, 3);
const password = Uint8Array.of(80);
const outputPassword = Uint8Array.of(81);
const success = run(new Module(), "create", [source, source, new Uint8Array()], password, outputPassword, "", new AbortController().signal);
const first = workers.at(-1);
assert.equal(first.messages[0].type, "init");
first.onmessage({ data: { type: "ready" } });
assert.equal(first.messages[1].type, "operate");
assert.deepEqual([...new Uint8Array(first.messages[1].inputs[0])], [1, 2, 3]);
assert.deepEqual([...new Uint8Array(first.messages[1].password)], [80]);
assert.deepEqual([...new Uint8Array(first.messages[1].secondPassword)], [81]);
first.onmessage({ data: { type: "result", operation: "create", answer: { ok: true } } });
assert.deepEqual(await success, { ok: true });
assert.equal(first.terminated, true);
assert.equal(timers.size, 0);
assert.deepEqual([...source], [1, 2, 3], "caller-owned buffer unexpectedly detached or changed");

const timed = run(new Module(), "inspect", [source, new Uint8Array(), new Uint8Array()], password, new Uint8Array(), "", new AbortController().signal);
const second = workers.at(-1);
assert.equal([...timers.values()][0].ms, 45000);
timers.values().next().value.fn();
await assert.rejects(timed);
assert.equal(second.terminated, true);
second.onmessage({ data: { type: "ready" } });
assert.equal(second.messages.length, 1, "late ready transferred secrets after timeout");

const controller = new AbortController();
const cancelled = run(new Module(), "key", [source, new Uint8Array(), new Uint8Array()], password, outputPassword, "A".repeat(95), controller.signal);
const third = workers.at(-1);
third.onmessage({ data: { type: "ready" } });
controller.abort();
await assert.rejects(cancelled);
assert.equal(third.terminated, true);

const malformed = run(new Module(), "inspect", [source, new Uint8Array(), new Uint8Array()], password, new Uint8Array(), "", new AbortController().signal);
const fourth = workers.at(-1);
fourth.onmessage({ data: { type: "result", operation: "inspect", answer: "unrequested" } });
await assert.rejects(malformed);
assert.equal(fourth.terminated, true);
await assert.rejects(run(null, "inspect", [source, source, source], password, outputPassword, "", new AbortController().signal));
assert.equal(workers.length, 4);

const posted = [];
let seenInput;
let seenPassword;
let seenOutput;
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
    workerGlobal.rootwellPFXInspect = (input, secret) => { seenInput = input; seenPassword = secret; return "public-summary"; };
    workerGlobal.rootwellPFXOutput = (_operation, input, _key, _chain, secret) => {
      seenInput = input; seenPassword = secret;
      seenOutput = Uint8Array.of(65, 66);
      return { schema_version: "rootwell.browser.pfx.v1", ok: true, result: { bytes: seenOutput } };
    };
    workerGlobal.rootwellWasmReady();
    return new Promise(() => {});
  }
};
const workerContext = vm.createContext(workerGlobal);
vm.runInContext(fs.readFileSync("web/workbench/pfx-worker.js", "utf8"), workerContext);
workerGlobal.onmessage({ data: { type: "init", module: new Module() } });
await new Promise(resolve => setImmediate(resolve));
assert.equal(posted[0].type, "ready");
workerGlobal.onmessage({ data: { type: "operate", operation: "key", inputs: [source.slice().buffer, new Uint8Array().buffer, new Uint8Array().buffer],
  password: password.slice().buffer, secondPassword: outputPassword.slice().buffer, option: "A".repeat(95) } });
assert.equal(posted[1].type, "result");
assert.deepEqual([...posted[1].answer.result.bytes], [65, 66]);
assert.equal(seenInput[0], 0);
assert.equal(seenPassword[0], 0);
assert.equal(workerGlobal.closed, true);
console.log("PFX worker deadline, abort, transfer, one-shot and memory-clearing checks passed.");
