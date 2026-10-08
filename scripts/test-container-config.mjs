import assert from 'node:assert/strict';
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

console.log('Container configuration positive and sabotage checks passed.');
