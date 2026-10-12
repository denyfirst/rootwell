import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
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
// single reviewed public staging-root exception. The real Docker CI build
// exercises Docker's matcher and go:embed, not a home-grown glob emulator.
const dockerIgnore = (await readFile(new URL('../.dockerignore', import.meta.url), 'utf8'))
  .split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
const rootAsset = '!internal/acmecertificate/staging-roots.pem';
assert.equal(dockerIgnore[0], '**', 'Build context must deny unknown inputs by default.');
assert.ok(dockerIgnore.lastIndexOf(rootAsset) > dockerIgnore.lastIndexOf('**/*.pem')
  && dockerIgnore.includes('**/*.pem'), 'Public staging trust needs its exact final build-context exception.');
const expectedPublicPEM = new Set([
  rootAsset,
  '!web/workbench/rootwell-demo-certificate.pem',
  '!web/workbench/rootwell-demo-bundle.pem',
  '!web/workbench/rootwell-verify-demo-root.pem',
  '!web/workbench/rootwell-verify-demo-leaf.pem',
  '!web/workbench/rootwell-verify-demo-intermediate.pem',
  '!web/workbench/rootwell-verify-demo-ca-files.pem',
]);
const reviewedSourceIncludes = new Set([
  '!go.mod', '!go.sum', '!cmd/', '!cmd/**/', '!cmd/**/*.go',
  '!cmd/rootwelld/auth/*.html', '!cmd/rootwelld/auth/*.css', '!cmd/rootwelld/auth/*.js',
  '!internal/', '!internal/**/', '!internal/**/*.go', '!web/', '!web/workbench/',
  '!web/workbench/index.html', '!web/workbench/app.js', '!web/workbench/theme.js',
  '!web/workbench/wasm-loader.js', '!web/workbench/style.css', '!web/workbench/favicon.svg',
]);
for (const rule of dockerIgnore.filter((line) => line.startsWith('!'))) {
  assert.ok(reviewedSourceIncludes.has(rule) || expectedPublicPEM.has(rule),
    'An unreviewed/broad build-context inclusion is not permitted.');
}
assert.deepEqual(new Set(dockerIgnore.filter((line) => line.startsWith('!') && /\.pem$/i.test(line))),
  expectedPublicPEM, 'Only the exact reviewed public PEM assets may be included.');

console.log('Container configuration positive/sabotage and exact public trust packaging checks passed.');
