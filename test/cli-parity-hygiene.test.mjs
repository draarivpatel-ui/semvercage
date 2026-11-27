import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import * as esm from '../src/index.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'bin', 'semvercage.mjs');
const require = createRequire(import.meta.url);
const cjs = require('../dist/cjs/index.cjs');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

function runCli(args) {
  return spawnSync(process.execPath, [cli, ...args], { cwd: root, encoding: 'utf8', timeout: 10000 });
}

function cleanFailure(result) {
  assert.equal(result.stderr.includes('\n    at '), false, result.stderr);
  assert.equal(result.stderr.includes('node:internal'), false, result.stderr);
}

function scratchDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'semvercage-test-'));
}

test('CLI version output is exact', () => {
  const result = runCli(['--version']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), 'semvercage 1.0.0');
});
test('CLI help exits successfully', () => {
  const result = runCli(['--help']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.includes('audit-lockfile'), true);
});
test('CLI with no arguments exits as usage error', () => {
  const result = runCli([]);
  assert.equal(result.status, 2);
  cleanFailure(result);
});
test('CLI parse prints canonical version', () => {
  const result = runCli(['parse', '1.2.3-alpha.1+build.2']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), '1.2.3-alpha.1+build.2');
});
test('CLI parse JSON emits structured parsed version', () => {
  const result = runCli(['parse', '1.2.3', '--json']);
  assert.equal(result.status, 0);
  assert.equal(JSON.parse(result.stdout).major, 1);
});
test('CLI parse invalid input has clean error', () => {
  const result = runCli(['parse', '01.2.3']);
  assert.equal(result.status, 2);
  assert.equal(result.stderr.includes('SEMVERCAGE_INVALID_VERSION'), true);
  cleanFailure(result);
});
test('CLI satisfies true exits zero', () => {
  const result = runCli(['satisfies', '1.2.4', '^1.2.0']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), 'true');
});
test('CLI satisfies false exits one', () => {
  const result = runCli(['satisfies', '2.0.0', '^1.2.0']);
  assert.equal(result.status, 1);
  assert.equal(result.stdout.trim(), 'false');
});
test('CLI prerelease isolation can be controlled', () => {
  assert.equal(runCli(['satisfies', '1.0.0-alpha', '*']).status, 1);
  assert.equal(runCli(['satisfies', '1.0.0-alpha', '*', '--include-prerelease']).status, 0);
});
test('CLI audit-spec passes exact dependency', () => {
  const result = runCli(['audit-spec', 'simplepackage', '1.2.3']);
  assert.equal(result.status, 0);
});
test('CLI audit-spec blocks wildcard dependency', () => {
  const result = runCli(['audit-spec', 'simplepackage', '*', '--json']);
  assert.equal(result.status, 1);
  const report = JSON.parse(result.stdout);
  assert.equal(report.findings[0].code, 'SEMVERCAGE_SPEC_UNPINNED_WILDCARD');
});
test('CLI strict policy blocks low severity separator confusion', () => {
  assert.equal(runCli(['audit-spec', 'foo_bar-baz', '1.0.0']).status, 0);
  assert.equal(runCli(['audit-spec', 'foo_bar-baz', '1.0.0', '--strict']).status, 1);
});
test('CLI audit-upgrade passes ordinary minor upgrade', () => {
  const result = runCli(['audit-upgrade', '1.0.0', '1.1.0']);
  assert.equal(result.status, 0);
});
test('CLI audit-upgrade blocks downgrade', () => {
  const result = runCli(['audit-upgrade', '2.1.0', '1.9.0', '--ci']);
  assert.equal(result.status, 1);
});
test('CLI unknown command has clean error', () => {
  const result = runCli(['not-a-command']);
  assert.equal(result.status, 2);
  cleanFailure(result);
});
test('CLI unknown option has clean error', () => {
  const result = runCli(['parse', '1.0.0', '--unknown']);
  assert.equal(result.status, 2);
  cleanFailure(result);
});
test('CLI error output strips hostile control characters', () => {
  const result = runCli(['parse', '1.0.0' + String.fromCharCode(27)]);
  assert.equal(result.status, 2);
  assert.equal(result.stderr.includes(String.fromCharCode(27)), false);
});

test('CLI audit-manifest reads package.json', () => {
  const dir = scratchDir();
  try {
    const file = path.join(dir, 'package.json');
    fs.writeFileSync(file, JSON.stringify({ name: 'simplepackage', dependencies: { dep: '1.0.0' } }), 'utf8');
    const result = runCli(['audit-manifest', file]);
    assert.equal(result.status, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
test('CLI audit-manifest blocks lifecycle hooks', () => {
  const dir = scratchDir();
  try {
    const file = path.join(dir, 'package.json');
    fs.writeFileSync(file, JSON.stringify({ name: 'simplepackage', scripts: { install: 'node x.js' } }), 'utf8');
    const result = runCli(['audit-manifest', file]);
    assert.equal(result.status, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
test('CLI audit-lockfile reads package-lock.json', () => {
  const dir = scratchDir();
  try {
    const file = path.join(dir, 'package-lock.json');
    fs.writeFileSync(file, JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': {},
        'node_modules/dep': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/dep/-/dep-1.0.0.tgz',
          integrity: 'sha512-' + 'A'.repeat(86) + '=='
        }
      }
    }), 'utf8');
    const result = runCli(['audit-lockfile', file]);
    assert.equal(result.status, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
test('CLI audit-lockfile blocks weak integrity', () => {
  const dir = scratchDir();
  try {
    const file = path.join(dir, 'package-lock.json');
    fs.writeFileSync(file, JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': {},
        'node_modules/dep': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/dep/-/dep-1.0.0.tgz',
          integrity: 'sha1-' + 'A'.repeat(27) + '='
        }
      }
    }), 'utf8');
    const result = runCli(['audit-lockfile', file, '--json']);
    assert.equal(result.status, 1);
    assert.equal(JSON.parse(result.stdout).findings.some((finding) => finding.code === 'SEMVERCAGE_LOCKFILE_WEAK_INTEGRITY'), true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('ESM and CJS export the same public keys', () => {
  const esmKeys = Object.keys(esm).filter((key) => key !== 'default').sort();
  const cjsKeys = Object.keys(cjs).filter((key) => key !== 'default').sort();
  assert.deepEqual(cjsKeys, esmKeys);
});

const parityCases = [
  ['parse version', () => [esm.parseSemver('1.2.3-rc.1').version, cjs.parseSemver('1.2.3-rc.1').version]],
  ['compare versions', () => [esm.compareSemver('1.0.0-alpha', '1.0.0'), cjs.compareSemver('1.0.0-alpha', '1.0.0')]],
  ['range satisfaction', () => [esm.satisfies('1.2.3', '^1.0.0'), cjs.satisfies('1.2.3', '^1.0.0')]],
  ['range negative', () => [esm.satisfies('2.2.3', '^1.0.0'), cjs.satisfies('2.2.3', '^1.0.0')]],
  ['valid semver', () => [esm.isValidSemver('1.0.0'), cjs.isValidSemver('1.0.0')]],
  ['invalid semver', () => [esm.isValidSemver('01.0.0'), cjs.isValidSemver('01.0.0')]],
  ['valid range', () => [esm.isValidRange('^1.0.0'), cjs.isValidRange('^1.0.0')]],
  ['invalid range', () => [esm.isValidRange('>='), cjs.isValidRange('>=')]],
  ['specifier audit', () => [esm.auditSpecifier('simplepackage', '*').counts.critical, cjs.auditSpecifier('simplepackage', '*').counts.critical]],
  ['manifest audit', () => [esm.auditPackageJson({ name: 'x', scripts: { install: 'x' } }).counts.high, cjs.auditPackageJson({ name: 'x', scripts: { install: 'x' } }).counts.high]],
  ['lockfile audit', () => [esm.auditLockfile({ lockfileVersion: 1, packages: {} }).counts.critical, cjs.auditLockfile({ lockfileVersion: 1, packages: {} }).counts.critical]],
  ['upgrade audit', () => [esm.auditUpgrade('2.0.0', '1.0.0').counts.critical, cjs.auditUpgrade('2.0.0', '1.0.0').counts.critical]],
  ['strict policy', () => [esm.getPolicy('strict').failOn, cjs.getPolicy('strict').failOn]],
  ['custom policy', () => [esm.createPolicy('ci', { maxMajorJump: 2 }).maxMajorJump, cjs.createPolicy('ci', { maxMajorJump: 2 }).maxMajorJump]],
  ['error guard', () => [esm.isSemverCageError(new esm.SemverCageError('SEMVERCAGE_INVALID_INPUT', 'x')), cjs.isSemverCageError(new cjs.SemverCageError('SEMVERCAGE_INVALID_INPUT', 'x'))]],
  ['range shape', () => [esm.parseRange('1.x').comparatorCount, cjs.parseRange('1.x').comparatorCount]]
];

for (const [label, evaluate] of parityCases) {
  test('CJS parity ' + label, () => {
    const [left, right] = evaluate();
    assert.deepEqual(right, left);
  });
}

test('CJS version and default export are correct', () => {
  assert.equal(cjs.SEMVERCAGE_VERSION, '1.0.0');
  assert.equal(cjs.default.SEMVERCAGE_VERSION, '1.0.0');
  assert.equal(esm.default.SEMVERCAGE_VERSION, '1.0.0');
});
test('package has zero runtime and development dependencies', () => {
  assert.deepEqual(pkg.dependencies, {});
  assert.deepEqual(pkg.devDependencies, {});
});
test('package exports ESM CJS and types correctly', () => {
  assert.equal(pkg.exports['.'].import, './src/index.mjs');
  assert.equal(pkg.exports['.'].require, './dist/cjs/index.cjs');
  assert.equal(pkg.exports['.'].types, './types/index.d.ts');
});
test('package requires Node 18 or newer', () => {
  assert.equal(pkg.engines.node, '>=18.0.0');
});
test('package is marked free of side effects', () => {
  assert.equal(pkg.sideEffects, false);
});
test('package bin points at semvercage CLI', () => {
  assert.equal(pkg.bin.semvercage, 'bin/semvercage.mjs');
});
test('repository points at the public semvercage repository', () => {
  assert.equal(pkg.repository.url, 'git+https://github.com/draarivpatel-ui/semvercage.git');
});

function repoTextFiles() {
  const output = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === '.git' || entry.name === 'node_modules') continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (!entry.name.endsWith('.tgz')) output.push(full);
    }
  };
  walk(root);
  return output;
}

test('repository files contain no em dash or en dash characters', () => {
  const emDash = String.fromCharCode(0x2014);
  const enDash = String.fromCharCode(0x2013);
  for (const file of repoTextFiles()) {
    const text = fs.readFileSync(file, 'utf8');
    assert.equal(text.includes(emDash), false, file);
    assert.equal(text.includes(enDash), false, file);
  }
});
test('repository files contain no local user filesystem paths', () => {
  const forbidden = '/' + 'Users/';
  for (const file of repoTextFiles()) {
    const text = fs.readFileSync(file, 'utf8');
    assert.equal(text.includes(forbidden), false, file);
  }
});
test('repository files contain no common personal mailbox provider fragments', () => {
  const providers = [['gmail', '.com'], ['outlook', '.com'], ['hotmail', '.com'], ['icloud', '.com'], ['proton', '.me']].map((parts) => parts.join(''));
  for (const file of repoTextFiles()) {
    const text = fs.readFileSync(file, 'utf8').toLowerCase();
    for (const provider of providers) assert.equal(text.includes(provider), false, file + ' contains ' + provider);
  }
});
test('repository files contain no commit coauthor trailer marker', () => {
  const marker = 'Co-' + 'Authored-' + 'By:';
  for (const file of repoTextFiles()) {
    assert.equal(fs.readFileSync(file, 'utf8').includes(marker), false, file);
  }
});
test('source never constructs a dynamic RegExp', () => {
  for (const file of fs.readdirSync(path.join(root, 'src'))) {
    const text = fs.readFileSync(path.join(root, 'src', file), 'utf8');
    assert.equal(text.includes('new RegExp'), false, file);
  }
});
test('source never uses eval or the Function constructor', () => {
  for (const file of fs.readdirSync(path.join(root, 'src'))) {
    const text = fs.readFileSync(path.join(root, 'src', file), 'utf8');
    assert.equal(text.includes('eval('), false, file);
    assert.equal(text.includes('new Function'), false, file);
  }
});
test('CI uses two operating systems and four Node versions for eight matrix jobs', () => {
  const ci = fs.readFileSync(path.join(root, '.github/workflows/ci.yml'), 'utf8');
  assert.equal(ci.includes('os: [ubuntu-latest, windows-latest]'), true);
  assert.equal(ci.includes('node: [18, 20, 22, 24]'), true);
});
test('type checker script is Windows safe', () => {
  const script = fs.readFileSync(path.join(root, 'scripts/check-types.mjs'), 'utf8');
  assert.equal(script.includes('tsc.cmd'), true);
  assert.equal(script.includes('shell: isWindows'), true);
});
for (const file of ['README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'CHANGELOG.md', 'LICENSE']) {
  test('required documentation file exists ' + file, () => {
    assert.equal(fs.statSync(path.join(root, file)).size > 100, true);
  });
}
for (const file of ['examples/basic.mjs', 'examples/manifest-audit.mjs', 'examples/lockfile-audit.mjs']) {
  test('example file exists ' + file, () => {
    assert.equal(fs.statSync(path.join(root, file)).size > 100, true);
  });
}
test('generated CJS file exists and is marked generated', () => {
  const text = fs.readFileSync(path.join(root, 'dist/cjs/index.cjs'), 'utf8');
  assert.equal(text.includes('Generated by scripts/build-cjs.mjs'), true);
});
test('public API objects are frozen', () => {
  assert.equal(Object.isFrozen(esm.SEMVERCAGE_ERROR_CODES), true);
  assert.equal(Object.isFrozen(esm.SEMVERCAGE_POLICY_PRESETS), true);
  assert.equal(Object.isFrozen(esm.getPolicy('strict')), true);
  assert.equal(Object.isFrozen(esm.default), true);
});
test('types declaration has no explicit any type', () => {
  const text = fs.readFileSync(path.join(root, 'types/index.d.ts'), 'utf8');
  assert.equal(/(:|=>)\s*any\b|\bas\s+any\b|\bArray<\s*any\s*>|\bany\s*\[\s*\]/u.test(text), false);
});
test('policy rejects info as a blocking threshold', () => {
  assert.throws(() => esm.createPolicy('balanced', { failOn: 'info' }), (error) => error.code === 'SEMVERCAGE_INVALID_POLICY');
});
