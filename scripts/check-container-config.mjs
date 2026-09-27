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
  const restricted = (service) => service?.read_only === true &&
    Array.isArray(service.cap_drop) && service.cap_drop.includes('ALL') &&
    Array.isArray(service.security_opt) &&
    service.security_opt.includes('no-new-privileges:true') &&
    (!service.ports || service.ports.length === 0) &&
    (!service.environment || Object.keys(service.environment).length === 0);
  if (!restricted(server) || !restricted(maintenance) ||
      server.network_mode !== 'host' || maintenance.network_mode !== 'none' ||
      !sameTargets(server, ['/data']) ||
      !sameTargets(maintenance, ['/data', '/backup']) ||
      maintenance.stdin_open !== true || maintenance.tty !== true) {
    throw new Error('Compose network, mount, or capability boundary changed');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  let input = '';
  for await (const chunk of process.stdin) {
    input += chunk;
    if (input.length > 1_000_000) throw new Error('Compose configuration is oversized');
  }
  checkContainerConfig(JSON.parse(input));
}
