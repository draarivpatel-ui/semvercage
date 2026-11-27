import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

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

function declaredMembers(interfaceName) {
  const start = declaration.indexOf('export interface ' + interfaceName + ' {');
  if (start === -1) return null;
  const end = declaration.indexOf('\n}', start);
  const members = new Map();
  for (const line of declaration.slice(start, end).split('\n')) {
    const match = /^\s+readonly ([A-Za-z]+)(\??):/u.exec(line);
    if (match) members.set(match[1], match[2] === '?');
  }
  return members;
}

const runtime = await import(pathToFileURL(path.join(root, 'src', 'index.mjs')).href);
const drift = [];
const policyMembers = declaredMembers('SemverCagePolicy');
const overrideMembers = declaredMembers('SemverCagePolicyOverrides');
const reportMembers = declaredMembers('SemverCageReport');
if (!policyMembers || !overrideMembers || !reportMembers) {
  console.error('types/index.d.ts is missing a policy or report interface');
  process.exit(1);
}
for (const key of Object.keys(runtime.SEMVERCAGE_DEFAULT_POLICY)) {
  if (!policyMembers.has(key)) drift.push('SemverCagePolicy.' + key);
  if (key !== 'name' && overrideMembers.get(key) !== true) drift.push('SemverCagePolicyOverrides.' + key + '?');
}
const sampleReports = [
  runtime.auditSpecifier('example-package', '^1.2.0', { dependencyType: 'devDependencies' }),
  runtime.auditPackageJson({ name: 'example-package', dependencies: { left: '1.0.0' }, scripts: { postinstall: 'node x.js' } }),
  runtime.auditLockfile({ lockfileVersion: 3, packages: { '': { name: 'example-package' } } }),
  runtime.auditLockfile({ lockfileVersion: 99 }),
  runtime.auditUpgrade('1.0.0', '1.1.0')
];
for (const report of sampleReports) {
  for (const key of Object.keys(report)) {
    if (!reportMembers.has(key)) drift.push('SemverCageReport.' + key + ' (' + report.target + ' report)');
  }
}
if (drift.length > 0) {
  console.error('types/index.d.ts does not declare runtime surface: ' + Array.from(new Set(drift)).join(', '));
  process.exit(1);
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
      '  SEMVERCAGE_FINDING_CODES,',
      '  resolvePolicy,',
      '  type AuditOptions,',
      '  type SemverCageFinding,',
      '  type SemverCagePolicy,',
      '  type SemverCagePolicyOverrides,',
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
      'const hardened = createPolicy("strict", { requireIntegrity: true, requireHttps: false, allowPrerelease: false, failOn: "high" });',
      'const integrityRequired: boolean = hardened.requireIntegrity;',
      'const httpsRequired: boolean = hardened.requireHttps;',
      'const overrides: SemverCagePolicyOverrides = { requireIntegrity: false, requireHttps: true, trustedRegistries: ["registry.npmjs.org"], privateNamePrefixes: ["corp-"] };',
      'const resolved: SemverCagePolicy = resolvePolicy({ ...overrides, policy: "ci" });',
      'const accessor: SemverCageFinding | undefined = two.findings.find((finding) => finding.code === SEMVERCAGE_FINDING_CODES.OBJECT_ACCESSOR);',
      'const accessorKey: string | undefined = accessor?.key;',
      'const accessorPath: string | undefined = accessor?.path;',
      'const mismatch: SemverCageFinding | undefined = three.findings.find((finding) => finding.code === SEMVERCAGE_FINDING_CODES.LOCKFILE_RESOLVED_MISMATCH);',
      'const mismatchPackagePath: string | undefined = mismatch?.packagePath;',
      'const breadth: number | undefined = three.findings[0]?.count;',
      'const bound: number | undefined = three.findings[0]?.bound;',
      'const depth: number | undefined = three.findings[0]?.depth;',
      'const dependencyCount: number | undefined = two.dependencyCount;',
      'const lifecycleScriptCount: number | undefined = two.lifecycleScriptCount;',
      'const packageCount: number | undefined = three.packageCount;',
      'const installScriptCount: number | undefined = three.installScriptCount;',
      'const reportedName: string | undefined = one.packageName;',
      'const reportedSpecifier: string | undefined = one.specifier;',
      'const reportedType: string | undefined = one.dependencyType;',
      'const fromVersion: string | undefined = four.fromVersion;',
      'const toVersion: string | undefined = four.toVersion;',
      'const upgradeComparison: -1 | 0 | 1 | undefined = four.comparison;',
      '// @ts-expect-error requireIntegrity is a boolean policy override',
      'createPolicy("strict", { requireIntegrity: "yes" });',
      '// @ts-expect-error requireHttps is a boolean policy override',
      'createPolicy("balanced", { requireHttps: 1 });',
      '// @ts-expect-error info is not a blocking failOn severity',
      'createPolicy("ci", { failOn: "info" });',
      '// @ts-expect-error unknown policy overrides are rejected',
      'createPolicy("ci", { requireIntegrty: true });',
      '// @ts-expect-error policy objects are readonly',
      'hardened.requireHttps = false;',
      '// @ts-expect-error packageCount is numeric metadata',
      'const packageCountText: string | undefined = three.packageCount;',
      '// @ts-expect-error installScriptCount is optional',
      'const installScriptsRequired: number = three.installScriptCount;',
      '// @ts-expect-error dependencyCount is numeric metadata',
      'const dependencyCountText: string | undefined = two.dependencyCount;',
      '// @ts-expect-error finding key is string metadata',
      'const accessorKeyNumber: number | undefined = accessor?.key;',
      '// @ts-expect-error finding count is numeric metadata',
      'const breadthText: string | undefined = three.findings[0]?.count;',
      '// @ts-expect-error upgrade comparison is a comparison result',
      'const upgradeComparisonText: string | undefined = four.comparison;',
      'console.log(version, comparison, range, matched, one, two, three, four, policy, preset, valid, text, semvercage.SEMVERCAGE_VERSION);',
      'console.log(integrityRequired, httpsRequired, resolved, accessorKey, accessorPath, mismatchPackagePath, breadth, bound, depth);',
      'console.log(dependencyCount, lifecycleScriptCount, packageCount, installScriptCount, reportedName, reportedSpecifier, reportedType, fromVersion, toVersion, upgradeComparison);',
      'console.log(packageCountText, installScriptsRequired, dependencyCountText, accessorKeyNumber, breadthText, upgradeComparisonText);'
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
