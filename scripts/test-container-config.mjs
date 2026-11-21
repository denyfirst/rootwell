import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { readdirSync } from 'node:fs';
import { checkContainerConfig } from './check-container-config.mjs';

const restricted = {
  read_only: true,
  cap_drop: ['ALL'],
  security_opt: ['no-new-privileges:true'],
};
const valid = {
  services: {
    rootwell: { ...restricted, network_mode: 'host', volumes: [{ target: '/data' }] },
    maintenance: { ...restricted, network_mode: 'none',
      volumes: [{ target: '/data' }, { target: '/backup' }],
      stdin_open: true, tty: true, logging: { driver: 'none' } },
  },
};
checkContainerConfig(valid);
const explicitEmptyLogOptions = structuredClone(valid);
explicitEmptyLogOptions.services.maintenance.logging.options = {};
checkContainerConfig(explicitEmptyLogOptions);
// Serving diagnostics remain available; only interactive maintenance is silent.
const serverDiagnostics = structuredClone(valid);
serverDiagnostics.services.rootwell.logging = { driver: 'local' };
checkContainerConfig(serverDiagnostics);

for (const logging of [undefined, null, false, 'none', [], {}, { driver: 'json-file' },
  { driver: 'local' }, { driver: 'syslog' }, { driver: 'none', options: { tag: 'unsafe' } },
  ...[null, false, '', [], 0].map((options) => ({ driver: 'none', options }))]) {
  const capturedMaintenance = structuredClone(valid);
  capturedMaintenance.services.maintenance.logging = logging;
  assert.throws(() => checkContainerConfig(capturedMaintenance), /maintenance\.logging/);
}

// Acceptance sabotage: expose backups to the serving process.
const overprivileged = structuredClone(valid);
overprivileged.services.rootwell.volumes.push({ target: '/backup' });
assert.throws(() => checkContainerConfig(overprivileged));

// Availability sabotage: omit the data volume so a restart loses the instance.
const ephemeral = structuredClone(valid);
ephemeral.services.rootwell.volumes = [];
assert.throws(() => checkContainerConfig(ephemeral));

const networkedMaintenance = structuredClone(valid);
networkedMaintenance.services.maintenance.network_mode = 'host';
assert.throws(() => checkContainerConfig(networkedMaintenance));

const secretEnvironment = structuredClone(valid);
secretEnvironment.services.maintenance.environment = { RECOVERY_CODE: 'test-only' };
assert.throws(() => checkContainerConfig(secretEnvironment));

// Fail closed on packaging drift: broad PEM inclusions must not replace the
// reviewed public receipt-root exceptions. The real Docker CI build
// exercises Docker's matcher and go:embed, not a home-grown glob emulator.
const dockerIgnore = (await readFile(new URL('../.dockerignore', import.meta.url), 'utf8'))
  .split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
const rootAsset = '!internal/acmecertificate/staging-roots.pem';
const productionRootAsset = '!internal/acmecertificate/production-roots.pem';
assert.equal(dockerIgnore[0], '**', 'Build context must deny unknown inputs by default.');
assert.ok(dockerIgnore.lastIndexOf(rootAsset) > dockerIgnore.lastIndexOf('**/*.pem')
  && dockerIgnore.includes('**/*.pem'), 'Public staging trust needs its exact final build-context exception.');
assert.ok(dockerIgnore.lastIndexOf(productionRootAsset) > dockerIgnore.lastIndexOf('**/*.pem'),
  'Public production trust needs its separate exact final build-context exception.');
const expectedPublicPEM = new Set([
  rootAsset,
  productionRootAsset,
  '!web/workbench/rootwell-demo-certificate.pem',
  '!web/workbench/rootwell-demo-bundle.pem',
  '!web/workbench/rootwell-verify-demo-root.pem',
  '!web/workbench/rootwell-verify-demo-leaf.pem',
  '!web/workbench/rootwell-verify-demo-intermediate.pem',
  '!web/workbench/rootwell-verify-demo-ca-files.pem',
]);
const reviewedSourceIncludes = new Set([
  '!go.mod', '!go.sum', '!cmd/**/*.go',
  '!cmd/rootwelld/auth/*.html', '!cmd/rootwelld/auth/*.css', '!cmd/rootwelld/auth/*.js',
  '!cmd/rootwelld/auth/website-examples.json', '!cmd/rootwelld/auth/schibsted-grotesk.woff2', '!internal/**/*.go',
  '!internal/account/password-blocklist.txt',
  ...['index.html', 'app.js', 'certificate-key-match.js', 'secret-view.js', 'private-key.js',
    'private-worker-client.js', 'private-key-worker.js', 'pfx.js', 'pfx-worker-client.js',
    'pfx-worker.js', 'csr.js', 'csr-worker-client.js', 'csr-worker.js', 'theme.js', 'session.js',
    'wasm-loader.js', 'style.css', 'favicon.svg'].map((name) => `!web/workbench/${name}`),
]);
for (const rule of dockerIgnore.filter((line) => line.startsWith('!'))) {
  assert.ok(reviewedSourceIncludes.has(rule) || expectedPublicPEM.has(rule),
    'An unreviewed/broad build-context inclusion is not permitted.');
  // A re-included directory brings every file under it (audit RW-05).
  assert.ok(!rule.endsWith('/') && !rule.endsWith('**') && /\.[A-Za-z0-9]+$|^!go\.(mod|sum)$/.test(rule),
    `A build-context exception must name files, not a directory: ${rule}`);
}
// Every Workbench asset the gate requires must reach the image.
for (const name of gateWorkbenchAssets(await readFile(new URL('../cmd/rootwelld/gate.go', import.meta.url), 'utf8'))) {
  if (name === 'wasm_exec.js' || name === 'rootwell.wasm') continue; // built inside the image
  assert.ok(reviewedSourceIncludes.has(`!web/workbench/${name}`) && dockerIgnore.includes(`!web/workbench/${name}`),
    `The gate requires web/workbench/${name}; the build context must include it.`);
}

// Every file a package under internal/ embeds must reach the build context by
// name, or the image fails to compile.
for (const entry of readdirSync(new URL('../internal/', import.meta.url), { recursive: true })) {
  const file = String(entry).replaceAll('\\', '/');
  if (!file.endsWith('.go') || file.endsWith('_test.go')) continue;
  const source = await readFile(new URL('../internal/' + file, import.meta.url), 'utf8');
  for (const [, names] of source.matchAll(/^\/\/go:embed (.+)$/gm)) {
    for (const name of names.trim().split(/\s+/)) {
      const path = 'internal/' + file.slice(0, file.lastIndexOf('/') + 1) + name;
      assert.ok(dockerIgnore.includes('!' + path), `the build context must include the embedded file ${path}`);
    }
  }
}

function gateWorkbenchAssets(source) {
  const list = source.match(/for _, name := range \[\]string\{([^}]+)\}/);
  assert.ok(list, 'The gate lists the Workbench assets it requires.');
  return [...list[1].matchAll(/"([^"]+)"/g)].map((match) => match[1]);
}
assert.ok(dockerIgnore.includes('!cmd/rootwelld/auth/website-examples.json'),
  'Public generated website examples must survive the deny-default context.');
const gateSource = await readFile(new URL('../cmd/rootwelld/gate.go', import.meta.url), 'utf8');
assert.match(gateSource, /\/\/go:embed auth\/\* auth\/website-examples\.json/,
  'The actual Docker compile must refuse a missing generated example asset.');
assert.deepEqual(new Set(dockerIgnore.filter((line) => line.startsWith('!') && /\.pem$/i.test(line))),
  expectedPublicPEM, 'Only the exact reviewed public PEM assets may be included.');

console.log('Container configuration positive/sabotage and exact public trust packaging checks passed.');
