import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const isWindows = process.platform === 'win32';
const tscCommand = isWindows ? 'tsc.cmd' : 'tsc';

function runTsc(args, options = {}) {
  return spawnSync(tscCommand, args, {
    encoding: 'utf8',
    shell: isWindows,
    ...options
  });
}

const declaration = fs.readFileSync(path.join(root, 'types', 'index.d.ts'), 'utf8');
if (/(:|=>)\s*any\b|\bas\s+any\b|\bArray<\s*any\s*>|\bany\s*\[\s*\]/u.test(declaration)) {
  console.error('types/index.d.ts must not use an explicit any type');
  process.exit(1);
}
for (const required of ['parseSemver', 'compareSemver', 'satisfies', 'parseRange', 'auditSpecifier', 'auditPackageJson', 'auditLockfile', 'auditUpgrade']) {
  if (!declaration.includes('function ' + required + '(')) {
    console.error('types/index.d.ts does not declare ' + required);
    process.exit(1);
  }
}

const probe = runTsc(['--version']);
if (probe.error || probe.status !== 0) {
  console.log('strict type check skipped: tsc is not installed');
  process.exitCode = 0;
} else {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'semvercage-types-'));
  try {
    fs.copyFileSync(path.join(root, 'types', 'index.d.ts'), path.join(scratch, 'index.d.ts'));
    fs.writeFileSync(path.join(scratch, 'check.ts'), [
      'import semvercage, {',
      '  SEMVERCAGE_VERSION,',
      '  auditLockfile,',
      '  auditPackageJson,',
      '  auditSpecifier,',
      '  auditUpgrade,',
      '  compareSemver,',
      '  createPolicy,',
      '  getPolicy,',
      '  isValidSemver,',
      '  parseRange,',
      '  parseSemver,',
      '  satisfies,',
      '  type AuditOptions,',
      '  type SemverCageReport,',
      '  type SemverRange,',
      '  type SemverVersion',
      '} from "./index";',
      'const version: SemverVersion = parseSemver("1.2.3-rc.1+build.7");',
      'const comparison: -1 | 0 | 1 = compareSemver(version, "1.2.4");',
      'const range: SemverRange = parseRange("^1.2.0", { policy: "strict", maxRangeLength: 256 });',
      'const matched: boolean = satisfies(version, range, { includePrerelease: true });',
      'const options: AuditOptions = { policy: "balanced", dependencyType: "dependencies", maxObjectKeys: 100 };',
      'const one: SemverCageReport = auditSpecifier("example-package", "1.2.3", options);',
      'const two: SemverCageReport = auditPackageJson({ name: "example-package" }, options);',
      'const three: SemverCageReport = auditLockfile({ lockfileVersion: 3, packages: {} }, options);',
      'const four: SemverCageReport = auditUpgrade("1.0.0", "1.1.0", "strict");',
      'const policy = createPolicy("ci", { maxMajorJump: 2 });',
      'const preset = getPolicy("strict");',
      'const valid: boolean = isValidSemver("1.0.0");',
      'const text: string = SEMVERCAGE_VERSION;',
      'console.log(version, comparison, range, matched, one, two, three, four, policy, preset, valid, text, semvercage.SEMVERCAGE_VERSION);'
    ].join('\n'), 'utf8');
    const result = runTsc(['--noEmit', '--strict', '--target', 'es2022', '--module', 'nodenext', '--moduleResolution', 'nodenext', 'check.ts'], { cwd: scratch });
    if (result.status !== 0) {
      process.stderr.write(result.stderr + result.stdout);
      process.exitCode = 1;
    } else {
      console.log('strict type check ok');
    }
  } finally {
    fs.rmSync(scratch, { recursive: true, force: true });
  }
}
