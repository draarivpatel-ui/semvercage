import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const errors = [];

if (packageJson.name !== 'semvercage') errors.push('package name is not semvercage');
if (Object.keys(packageJson.dependencies || {}).length !== 0) errors.push('runtime dependencies are not empty');
const devDependencyNames = Object.keys(packageJson.devDependencies || {});
if (devDependencyNames.length !== 1 || devDependencyNames[0] !== 'fast-check') errors.push('development dependencies are not limited to fast-check');
if (!packageJson.exports || packageJson.exports['.'].import !== './src/index.mjs') errors.push('ESM export is incorrect');
if (!packageJson.exports || packageJson.exports['.'].require !== './dist/cjs/index.cjs') errors.push('CJS export is incorrect');
if (!packageJson.exports || packageJson.exports['.'].types !== './types/index.d.ts') errors.push('types export is incorrect');

const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const packEnv = { ...process.env };
for (const key of Object.keys(packEnv)) {
  if (key.toLowerCase() === 'npm_config_store_dir') delete packEnv[key];
}
const packed = spawnSync(npmCommand, ['pack', '--dry-run', '--json'], {
  cwd: root,
  encoding: 'utf8',
  env: packEnv,
  shell: process.platform === 'win32'
});
if (packed.error) throw packed.error;
if (packed.status !== 0) errors.push('npm pack --dry-run failed: ' + packed.stderr + packed.stdout);
if (/npm warn/i.test(packed.stderr)) errors.push('npm pack emitted warnings: ' + packed.stderr.trim());

let entries = [];
if (packed.status === 0) {
  try {
    const start = packed.stdout.indexOf('[');
    entries = JSON.parse(packed.stdout.slice(start));
  } catch (error) {
    errors.push('npm pack JSON output could not be parsed: ' + error.message);
  }
}
const files = entries.length > 0 && Array.isArray(entries[0].files) ? entries[0].files.map((file) => file.path) : [];
if (files.length === 0) errors.push('npm pack reported no files');
const allowed = /^(?:package\.json|README\.md|LICENSE|CHANGELOG\.md|SECURITY\.md|CONTRIBUTING\.md|(?:bin|src|types|examples)\/[^/]+|dist\/cjs\/index\.cjs)$/;
for (const file of files) {
  if (!allowed.test(file)) errors.push('unexpected file in tarball: ' + file);
  if (file.includes('..') || file.startsWith('/')) errors.push('unsafe tarball path: ' + file);
  if (/^(?:test|tests|scripts|\.github)\//.test(file)) errors.push('development file leaked into tarball: ' + file);
}
for (const required of ['package.json', 'README.md', 'LICENSE', 'bin/semvercage.mjs', 'src/index.mjs', 'dist/cjs/index.cjs', 'types/index.d.ts']) {
  if (!files.includes(required)) errors.push('required package file missing: ' + required);
}

if (errors.length > 0) {
  for (const error of errors) console.error(error);
  process.exitCode = 1;
} else {
  console.log('pack check ok: ' + files.length + ' files, zero npm warnings');
}
