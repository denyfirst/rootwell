import { pathToFileURL } from 'node:url';

function sameTargets(service, expected) {
  const volumes = service?.volumes;
  if (!Array.isArray(volumes)) return false;
  const actual = volumes.map((mount) => mount?.target).sort();
  return JSON.stringify(actual) === JSON.stringify([...expected].sort());
}

export function checkContainerConfig(config) {
  const server = config?.services?.rootwell;
  const maintenance = config?.services?.maintenance;
  const requireBoundary = (condition, label) => {
    if (!condition) throw new Error(`Compose boundary changed: ${label}`);
  };
  for (const [name, service] of [['server', server], ['maintenance', maintenance]]) {
    requireBoundary(service?.read_only === true, `${name}.read_only`);
    requireBoundary(Array.isArray(service.cap_drop) && service.cap_drop.includes('ALL'), `${name}.cap_drop`);
    requireBoundary(Array.isArray(service.security_opt) &&
      service.security_opt.includes('no-new-privileges:true'), `${name}.security_opt`);
    requireBoundary(!service.ports || service.ports.length === 0, `${name}.ports`);
    requireBoundary(!service.environment || Object.keys(service.environment).length === 0, `${name}.environment`);
  }
  requireBoundary(server.network_mode === 'host', 'server.network_mode');
  requireBoundary(maintenance.network_mode === 'none', 'maintenance.network_mode');
  requireBoundary(sameTargets(server, ['/data']), 'server.volumes');
  requireBoundary(sameTargets(maintenance, ['/data', '/backup']), 'maintenance.volumes');
  requireBoundary(maintenance.stdin_open === true && maintenance.tty === true, 'maintenance.terminal');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let input = '';
  for await (const chunk of process.stdin) {
    input += chunk;
    if (input.length > 1_000_000) throw new Error('Compose configuration is oversized');
  }
  checkContainerConfig(JSON.parse(input));
}
