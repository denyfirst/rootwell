// Synthetic-only loopback preview. This does not authenticate or store data.
import { readFileSync } from "node:fs";
import http from "node:http";

if (process.argv.length !== 3 || process.argv[2] !== "--synthetic-preview-only") {
  throw new Error("Run only with --synthetic-preview-only; never select real keys here.");
}

const types = new Map([
  ["index.html", "text/html; charset=utf-8"], ["style.css", "text/css; charset=utf-8"],
  ["worker-browser-smoke.html", "text/html; charset=utf-8"], ["worker-browser-smoke.js", "text/javascript; charset=utf-8"],
  ["favicon.svg", "image/svg+xml"], ["rootwell.wasm", "application/wasm"],
  ...["theme.js", "wasm_exec.js", "wasm-loader.js", "app.js", "secret-view.js", "private-key.js",
    "private-worker-client.js", "private-key-worker.js", "pfx.js", "pfx-worker-client.js", "pfx-worker.js"].map(name => [name, "text/javascript; charset=utf-8"]),
  ...["rootwell-demo-certificate.pem", "rootwell-demo-bundle.pem", "rootwell-verify-demo-leaf.pem",
    "rootwell-verify-demo-intermediate.pem", "rootwell-verify-demo-root.pem",
    "rootwell-verify-demo-ca-files.pem"].map(name => [name, "application/x-pem-file"])
]);
const policy = "default-src 'none'; style-src 'self'; script-src 'self' 'wasm-unsafe-eval'; img-src 'self'; connect-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const workerPolicy = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'none'; worker-src 'none'; object-src 'none'; base-uri 'none'";
const server = http.createServer((request, response) => {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("Referrer-Policy", "no-referrer");
  const path = request.url === "/" ? "index.html" : request.url.slice(1);
  response.setHeader("Content-Security-Policy", path === "private-key-worker.js" || path === "pfx-worker.js" ? workerPolicy : policy);
  if (request.method !== "GET") { response.writeHead(405).end(); return; }
  if (!types.has(path)) { response.writeHead(404).end(); return; }
  try {
    const body = readFileSync(new URL("../web/workbench/" + path, import.meta.url));
    response.writeHead(200, { "Content-Type": types.get(path) }).end(body);
  } catch {
    response.writeHead(404).end();
  }
});
server.listen(4190, "127.0.0.1", () => {
  process.stdout.write("Synthetic-only Rootwell preview: http://127.0.0.1:4190/\n");
});
