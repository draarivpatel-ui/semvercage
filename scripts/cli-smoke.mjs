import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'bin', 'semvercage.mjs');

function run(args) {
  return spawnSync(process.execPath, [cli, ...args], { cwd: root, encoding: 'utf8', timeout: 10000 });
}

function assertClean(result) {
  assert.equal(result.stderr.includes('\n    at '), false, result.stderr);
  assert.equal(result.stderr.includes('node:internal'), false, result.stderr);
}

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'semvercage-smoke-'));
try {
  assert.equal(run(['--version']).stdout.trim(), 'semvercage 1.0.0');
  const parsed = run(['parse', '1.2.3-rc.1+build.5']);
  assert.equal(parsed.status, 0);
  assert.equal(parsed.stdout.trim(), '1.2.3-rc.1+build.5');
  const badParse = run(['parse', '01.2.3']);
  assert.equal(badParse.status, 2);
  assertClean(badParse);
  assert.equal(run(['satisfies', '1.2.4', '^1.2.0']).status, 0);
  assert.equal(run(['satisfies', '2.0.0', '^1.2.0']).status, 1);
  assert.equal(run(['audit-spec', 'smoke-package', '1.2.3']).status, 0);
  assert.equal(run(['audit-spec', 'smoke-package', '*', '--json']).status, 1);

  const manifestPath = path.join(scratch, 'package.json');
  fs.writeFileSync(manifestPath, JSON.stringify({ name: 'smoke-package', dependencies: { 'smoke-dep': '1.2.3' } }), 'utf8');
  assert.equal(run(['audit-manifest', manifestPath]).status, 0);
  fs.writeFileSync(manifestPath, JSON.stringify({ name: 'smoke-package', scripts: { postinstall: 'node install.js' } }), 'utf8');
  assert.equal(run(['audit-manifest', manifestPath, '--strict']).status, 1);

  const integrity = 'sha512-' + 'A'.repeat(86) + '==';
  const lockfilePath = path.join(scratch, 'package-lock.json');
  fs.writeFileSync(lockfilePath, JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': { name: 'smoke-package' },
      'node_modules/smoke-dep': {
        version: '1.2.3',
        resolved: 'https://registry.npmjs.org/smoke-dep/-/smoke-dep-1.2.3.tgz',
        integrity
      }
    }
  }), 'utf8');
  assert.equal(run(['audit-lockfile', lockfilePath]).status, 0);
  fs.writeFileSync(lockfilePath, JSON.stringify({
    lockfileVersion: 3,
    packages: {
      '': {},
      'node_modules/smoke-dep': {
        version: '1.2.3',
        resolved: 'http://registry.npmjs.org/smoke-dep/-/smoke-dep-1.2.3.tgz',
        integrity: 'sha1-' + 'A'.repeat(27) + '='
      }
    }
  }), 'utf8');
  assert.equal(run(['audit-lockfile', lockfilePath, '--ci']).status, 1);
  assert.equal(run(['audit-upgrade', '1.0.0', '1.1.0']).status, 0);
  assert.equal(run(['audit-upgrade', '2.1.0', '1.9.0']).status, 1);
  const unknown = run(['does-not-exist']);
  assert.equal(unknown.status, 2);
  assertClean(unknown);
  process.stdout.write('semvercage CLI smoke passed\n');
} finally {
  fs.rmSync(scratch, { recursive: true, force: true });
}
