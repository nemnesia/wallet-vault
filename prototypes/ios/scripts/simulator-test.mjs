import { spawnSync } from 'node:child_process';
import { readFileSync, mkdirSync, copyFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const root = fileURLToPath(new URL('..', import.meta.url));
const device = process.argv[2];
if (!device) throw new Error('Usage: npm run test:simulator -- <Simulator UDID>');
const bundle = 'dev.vault.prototype.ios.simulator';
function sim(...args) {
  const result = spawnSync('xcrun', ['simctl', ...args], { encoding: 'utf8', cwd: root });
  if (result.status !== 0) throw new Error(`simctl ${args[0]} failed: ${result.stderr.trim()}`);
  return result.stdout.trim();
}

sim('bootstatus', device, '-b');
sim('install', device, resolve(root, 'build/VaultSimulator.app'));
const container = sim('get_app_container', device, bundle, 'data');
const runID = randomUUID();
mkdirSync(resolve(root, 'build/evidence'), { recursive: true });
for (const phase of ['roundtrip', 'restart']) {
  sim('launch', '--terminate-running-process', device, bundle,
    '--integration-tests', phase, '--test-run', runID);
  const source = resolve(container, `Documents/ios-integration-${phase}.json`);
  const deadline = Date.now() + 45000;
  let report;
  while (Date.now() < deadline) {
    try {
      const value = JSON.parse(readFileSync(source, 'utf8'));
      if (value.runId === runID) { report = value; break; }
    } catch (error) {
      if (!['ENOENT', 'EACCES'].includes(error.code) && !(error instanceof SyntaxError)) throw error;
    }
    await new Promise(resolve => setTimeout(resolve, 200));
  }
  if (!report) throw new Error(`${phase}: no completed report within 45 seconds`);
  copyFileSync(source, resolve(root, `build/evidence/ios-integration-${phase}.json`));
  const failures = report.observations.filter(row => row.result !== 'PASS');
  console.log(`${phase}: ${report.result} (${report.observations.length} checks / ${report.authentication} / ${report.backend})`);
  if (report.result !== 'PASS' || failures.length) throw new Error(JSON.stringify(failures));
}
sim('launch', '--terminate-running-process', device, bundle);
console.log('PASS: separate process restart verified; interactive app left locked.');
