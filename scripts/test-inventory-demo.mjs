import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const child = spawn(process.execPath, [fileURLToPath(new URL("./inventory-demo.mjs", import.meta.url)), "--fixture-only", "--port", "0"],
  { stdio: ["ignore", "pipe", "pipe"] });
try {
  const address = await new Promise((resolve, reject) => {
    let output = "";
    const timeout = setTimeout(() => reject(new Error("demo did not start")), 5000);
    child.once("error", reject);
    child.once("exit", code => reject(new Error("demo exited: " + code)));
    child.stdout.on("data", chunk => {
      output += chunk.toString();
      const match = output.match(/http:\/\/127\.0\.0\.1:\d+\/inventory/);
      if (match) { clearTimeout(timeout); resolve(match[0]); }
    });
  });
  const page = await fetch(address);
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.match(html, /DEMO — generated fake records only/);
  assert.match(html, /id="certificate-file" type="file" disabled/);
  assert.match(html, /id="save-button" type="submit" disabled/);
  assert.equal(page.headers.get("cache-control"), "no-store");
  const origin = new URL(address).origin;
  const inventory = await fetch(origin + "/api/inventory", { headers: { "X-Rootwell-Request": "1" } });
  assert.equal(inventory.status, 200);
  const result = await inventory.json();
  assert.equal(result.verification, "not-performed");
  assert.equal(result.records.length, 3);
  assert.ok(result.records.every(record => record.subject.includes("demo-") && !Object.hasOwn(record, "der")));
  assert.equal((await fetch(origin + "/api/inventory")).status, 404);
  assert.equal((await fetch(origin + "/api/inventory", { method: "POST", body: "never save" })).status, 405);
  assert.equal((await fetch(origin + "/../docs/ENGINEERING.md")).status, 404);
  const script = await (await fetch(origin + "/inventory.js")).text();
  assert.match(script, /addButton\.disabled = true/);
  assert.match(script, /editOwnerButton\.disabled = true/);
  assert.match(script, /manageLocationButton\.disabled = true/);
  console.log("Rootwell read-only fake-data Inventory demo boundary passed.");
} finally {
  child.kill();
}
