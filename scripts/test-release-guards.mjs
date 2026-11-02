import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const bash = process.platform === 'win32' ? 'C:/Program Files/Git/bin/bash.exe' : 'bash';
const temporary = mkdtempSync(resolve(tmpdir(), 'rootwell-release-guard-'));
const invoke = (script, env) => spawnSync(bash, [script], {
  cwd: repo, env: { ...process.env, ...env }, encoding: 'utf8', timeout: 10000,
});
try {
  for (const baseline of ['', '0'.repeat(40), 'A'.repeat(40), 'a'.repeat(64),
    '--upload-pack=secret-do-not-print', 'a'.repeat(40) + '\n']) {
    const result = invoke('scripts/test-container-volume.sh', {
      RUNNER_TEMP: temporary.replaceAll('\\', '/'), ROOTWELL_UPGRADE_BASE: baseline,
    });
    assert.equal(result.status, 1, 'Invalid baseline must fail before Docker, Git fetch or volume creation.');
    assert.equal(result.stdout, '');
    assert.equal(result.stderr.trim(), 'An exact previous protected-base commit is required for the upgrade drill');
  }
  const proof = invoke('scripts/test-reproducible-build.sh', { RUNNER_TEMP: '' });
  assert.equal(proof.status, 1);
  assert.equal(proof.stdout, '');
  assert.equal(proof.stderr.trim(), 'An isolated Linux amd64 runner with RUNNER_TEMP is required');
} finally {
  // Only the exact directory this test created, never a caller-provided path.
  assert.equal(dirname(temporary), resolve(tmpdir()));
  rmSync(temporary, { recursive: true });
}
console.log('Release proof and upgrade-baseline refusals passed without Docker, fetches or instance data.');
