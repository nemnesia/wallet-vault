import { spawnSync } from 'node:child_process';
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const root = fileURLToPath(new URL('..', import.meta.url));
const device = process.argv[2];
if (!device) throw new Error('Usage: npm run test:biometrics -- <Simulator UDID>');
const bundle = 'dev.vault.prototype.ios.simulator';
function sim(...args) {
  const result = spawnSync('xcrun', ['simctl', ...args], { encoding: 'utf8', cwd: root });
  if (result.status !== 0) throw new Error(`simctl ${args[0]} failed: ${result.stderr.trim()}`);
  return result.stdout.trim();
}
const notify = (...args) => sim('spawn', device, 'notifyutil', ...args);
// Private Simulator testing notifications; not used by the application or on devices.
const enrollment = 'com.apple.BiometricKit.enrollmentChanged';
sim('bootstatus', device, '-b');
sim('install', device, resolve(root, 'build/VaultSimulator.app'));
const container = sim('get_app_container', device, bundle, 'data');
const previous = notify('-g', enrollment).match(/([0-9]+)\s*$/)?.[1];
if (!previous) throw new Error('Cannot read Simulator enrollment state');
const runID = randomUUID();
mkdirSync(resolve(root, 'build/evidence'), { recursive: true });
function readJSON(path) {
  try { return JSON.parse(readFileSync(path, 'utf8')); }
  catch (error) { if (error.code === 'ENOENT' || error instanceof SyntaxError) return undefined; throw error; }
}
try {
  for (const phase of ['unenrolled', 'enrolled']) {
    notify('-s', enrollment, phase === 'enrolled' ? '1' : '0', '-p', enrollment);
    sim('launch', '--terminate-running-process', device, bundle, '--biometric-tests', phase, runID);
    const source = resolve(container, `Documents/ios-biometric-${phase}.json`);
    const progressPath = resolve(container, 'Documents/ios-biometric-progress.json');
    const deadline = Date.now() + 90000;
    const posted = new Set();
    const inputs = [];
    let lastCall = 0;
    let seenAt = 0;
    let lastPostAt = 0;
    let report;
    while (Date.now() < deadline) {
      const result = readJSON(source);
      if (result?.runId === runID) { report = result; break; }
      const progress = readJSON(progressPath);
      if (progress?.runId === runID && progress.status === 'waiting') {
        if (lastCall !== progress.call) { lastCall = progress.call; seenAt = Date.now(); lastPostAt = 0; }
        const shouldPost = !posted.has(progress.call) || (progress.intent === 'match' && Date.now() - lastPostAt > 1200);
        if (shouldPost && Date.now() - seenAt > 900 && progress.intent !== 'hold') {
          notify('-p', `com.apple.BiometricKit_Sim.pearl.${progress.intent === 'nonmatch' ? 'nomatch' : 'match'}`);
          posted.add(progress.call);
          lastPostAt = Date.now();
          inputs.push({ call: progress.call, intent: progress.intent });
        }
      }
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!report) throw new Error(`${phase}: no completed report`);
    report.simulatorInputs = inputs;
    writeFileSync(resolve(root, `build/evidence/ios-biometric-${phase}.json`), JSON.stringify(report, null, 2) + '\n');
    console.log(`${phase}: ${report.result} (${report.observations.length} checks / ${report.authentication})`);
    if (report.result !== 'PASS') throw new Error(JSON.stringify(report.observations.filter(row => row.result !== 'PASS')));
    if (phase === 'enrolled' && (!inputs.some(input => input.intent === 'nonmatch') || report.authenticationCalls !== 8
        || ![1, 2, 3, 4, 5, 8].every(call => inputs.some(input => input.call === call && input.intent === 'match')))) {
      throw new Error('Expected independent match/non-match scenarios were not exercised');
    }
  }
} finally {
  notify('-s', enrollment, previous, '-p', enrollment);
  sim('launch', '--terminate-running-process', device, bundle);
}
console.log('PASS: LocalAuthentication with simulated Face ID; enrollment state restored.');
