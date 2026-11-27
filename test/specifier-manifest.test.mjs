import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SEMVERCAGE_ERROR_CODES,
  SEMVERCAGE_FINDING_CODES,
  auditPackageJson,
  auditSpecifier
} from '../src/index.mjs';

function reportCodes(report) {
  return new Set(report.findings.map((finding) => finding.code));
}

function hasFinding(report, code, severity = undefined) {
  return report.findings.some((finding) => finding.code === code && (severity === undefined || finding.severity === severity));
}

const safeSpecifiers = [
  '1.2.3',
  '=1.2.3',
  '^1.2.3',
  '~1.2.3',
  '>=1.2.0 <2.0.0',
  '>1.2.0 <2.0.0',
  '>=1.2.0 <=1.9.0',
  '1.2.x',
  '1.x',
  '1.2.3 - 1.9.0',
  '^1.0.0 || >=2.0.0 <3.0.0',
  '0.2.3',
  '^0.2.3',
  '~0.2.3',
  '1.2.3+build.1',
  '1.2.3 || 1.2.4',
  '2.x',
  '>=0.1.0 <0.2.0'
];

for (const specifier of safeSpecifiers) {
  test('safe dependency specifier passes ' + specifier, () => {
    const report = auditSpecifier('simplepackage', specifier);
    assert.deepEqual(report.findings, []);
    assert.equal(report.ok, true);
  });
}

const wildcardAndBroadCases = [
  ['*', SEMVERCAGE_FINDING_CODES.SPEC_UNPINNED_WILDCARD, 'critical'],
  ['x', SEMVERCAGE_FINDING_CODES.SPEC_UNPINNED_WILDCARD, 'critical'],
  ['X', SEMVERCAGE_FINDING_CODES.SPEC_UNPINNED_WILDCARD, 'critical'],
  ['* || ^1.0.0', SEMVERCAGE_FINDING_CODES.SPEC_UNPINNED_WILDCARD, 'critical'],
  ['latest', SEMVERCAGE_FINDING_CODES.SPEC_UNPINNED_DIST_TAG, 'high'],
  ['next', SEMVERCAGE_FINDING_CODES.SPEC_UNPINNED_DIST_TAG, 'high'],
  ['>=1.0.0', SEMVERCAGE_FINDING_CODES.SPEC_BROAD_UNBOUNDED_RANGE, 'high'],
  ['>1.0.0', SEMVERCAGE_FINDING_CODES.SPEC_BROAD_UNBOUNDED_RANGE, 'high'],
  ['>=0.0.0', SEMVERCAGE_FINDING_CODES.SPEC_BROAD_UNBOUNDED_RANGE, 'high'],
  ['>0', SEMVERCAGE_FINDING_CODES.SPEC_BROAD_UNBOUNDED_RANGE, 'high'],
  ['>=1.0.0 || >=2.0.0', SEMVERCAGE_FINDING_CODES.SPEC_BROAD_UNBOUNDED_RANGE, 'high']
];

for (const [specifier, code, severity] of wildcardAndBroadCases) {
  test('flags mutable or broad specifier ' + specifier, () => {
    const report = auditSpecifier('simplepackage', specifier);
    assert.equal(hasFinding(report, code, severity), true);
    assert.equal(report.ok, false);
  });
}

const prereleaseSpecifiers = [
  '1.0.0-alpha',
  '1.0.0-alpha.1',
  '1.0.0-beta',
  '1.0.0-rc.1',
  '1.0.0-canary.1',
  '1.0.0-next.1',
  '1.0.0-dev',
  '1.0.0-snapshot',
  '^1.0.0-alpha',
  '~1.0.0-beta',
  '0.0.0-alpha',
  '0.0.0-*'
];

for (const specifier of prereleaseSpecifiers) {
  test('flags prerelease drift ' + specifier, () => {
    const report = auditSpecifier('simplepackage', specifier);
    assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.SPEC_PRERELEASE_DRIFT), true);
    assert.equal(report.ok, false);
  });
}

const remoteCases = [
  ['git+http://example.com/org/repo.git', SEMVERCAGE_FINDING_CODES.SPEC_GIT_TRANSPORT],
  ['git+https://example.com/org/repo.git', SEMVERCAGE_FINDING_CODES.SPEC_GIT_TRANSPORT],
  ['git+ssh://git@example.com/org/repo.git', SEMVERCAGE_FINDING_CODES.SPEC_GIT_TRANSPORT],
  ['git://example.com/org/repo.git', SEMVERCAGE_FINDING_CODES.SPEC_GIT_TRANSPORT],
  ['ssh://git@example.com/org/repo.git', SEMVERCAGE_FINDING_CODES.SPEC_GIT_TRANSPORT],
  ['git@example.com:org/repo.git', SEMVERCAGE_FINDING_CODES.SPEC_HOSTING_SHORTHAND],
  ['github:org/repo', SEMVERCAGE_FINDING_CODES.SPEC_HOSTING_SHORTHAND],
  ['bitbucket:org/repo', SEMVERCAGE_FINDING_CODES.SPEC_HOSTING_SHORTHAND],
  ['gitlab:org/repo', SEMVERCAGE_FINDING_CODES.SPEC_HOSTING_SHORTHAND],
  ['gist:org/abcdef', SEMVERCAGE_FINDING_CODES.SPEC_HOSTING_SHORTHAND],
  ['org/repo', SEMVERCAGE_FINDING_CODES.SPEC_HOSTING_SHORTHAND],
  ['org/repo#commit', SEMVERCAGE_FINDING_CODES.SPEC_HOSTING_SHORTHAND],
  ['http://example.com/package.tgz', SEMVERCAGE_FINDING_CODES.SPEC_REMOTE_TARBALL],
  ['https://example.com/package.tgz', SEMVERCAGE_FINDING_CODES.SPEC_REMOTE_TARBALL],
  ['file:../local-package', SEMVERCAGE_FINDING_CODES.SPEC_LOCAL_PATH],
  ['file:/opt/local-package', SEMVERCAGE_FINDING_CODES.SPEC_LOCAL_PATH],
  ['link:../local-package', SEMVERCAGE_FINDING_CODES.SPEC_LOCAL_PATH],
  ['portal:../local-package', SEMVERCAGE_FINDING_CODES.SPEC_LOCAL_PATH],
  ['workspace:*', SEMVERCAGE_FINDING_CODES.SPEC_WORKSPACE_PROTOCOL],
  ['workspace:^1.0.0', SEMVERCAGE_FINDING_CODES.SPEC_WORKSPACE_PROTOCOL]
];

for (const [specifier, code] of remoteCases) {
  test('flags non registry specifier ' + specifier, () => {
    const report = auditSpecifier('simplepackage', specifier);
    assert.equal(hasFinding(report, code), true);
    assert.equal(report.ok, false);
  });
}

const aliasCases = [
  'npm:evil-package@1.0.0',
  'npm:@scope/evil-package@1.0.0',
  'npm:evil-package',
  'npm:evil-package@latest',
  'npm:evil-package@^1.0.0',
  'npm:evil-package@git+https://example.com/repo.git',
  'npm:safe-package@1.0.0',
  'npm:internal-tool@1.0.0'
];

for (const specifier of aliasCases) {
  test('flags npm alias confusion ' + specifier, () => {
    const report = auditSpecifier('simplepackage', specifier);
    assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.SPEC_NPM_ALIAS, 'high'), true);
    assert.equal(report.ok, false);
  });
}

test('npm alias target package is validated', () => {
  const report = auditSpecifier('simplepackage', 'npm:internal-tool@1.0.0');
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.SPEC_PRIVATE_NAME_CONFUSION), true);
});
test('npm alias to mutable tag is flagged through recursion', () => {
  const report = auditSpecifier('simplepackage', 'npm:evil-package@latest');
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.SPEC_UNPINNED_DIST_TAG), true);
});

const credentialSpecifiers = [
  'https://user:pass@example.com/package.tgz',
  'http://user:pass@example.com/package.tgz',
  'git+https://user:pass@example.com/org/repo.git',
  'git+ssh://user:pass@example.com/org/repo.git',
  'npm:evil@https://user:pass@example.com/package.tgz',
  'https://user:pass@example.com/a.tgz https://user:pass@example.org/b.tgz'
];

for (const specifier of credentialSpecifiers) {
  test('flags and redacts credential specifier', () => {
    const report = auditSpecifier('simplepackage', specifier);
    assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.SPEC_CREDENTIALS, 'critical'), true);
    assert.equal(JSON.stringify(report).includes('user:pass'), false);
    assert.equal(JSON.stringify(report).includes('<redacted>@'), true);
  });
}

const invalidSpecifierCases = [
  'not-a-version',
  '1.0.0??',
  '01.0.0',
  '>=',
  '^',
  '1.0.0 ||',
  '1.0.0  <2.0.0',
  '1.0.0\tevil',
  '1.0.0é',
  '1.0.0\u202e',
  'v1.0.0',
  '1.0.0-alpha_1'
];

for (const specifier of invalidSpecifierCases) {
  test('flags invalid specifier range ' + JSON.stringify(specifier), () => {
    const report = auditSpecifier('simplepackage', specifier);
    assert.equal(reportCodes(report).has(SEMVERCAGE_FINDING_CODES.SPEC_INVALID_RANGE) || reportCodes(report).has(SEMVERCAGE_FINDING_CODES.SPEC_CONTROL_CHARACTERS), true);
    assert.equal(report.ok, false);
  });
}

const validPackageNames = [
  'lodash',
  'react',
  'a',
  'simplepackage',
  'package.name',
  'package_name',
  'package-name',
  '@scope/name',
  '@a-b/name-1',
  '@scope/package.name'
];

for (const packageName of validPackageNames) {
  test('valid package name produces no naming finding ' + packageName, () => {
    const report = auditSpecifier(packageName, '1.0.0');
    assert.deepEqual(report.findings, []);
    assert.equal(report.ok, true);
  });
}

const invalidPackageNames = [
  'UPPERCASE',
  'MixedCase',
  'has space',
  'bad/name/again',
  '.leadingdot',
  '_leadingunderscore',
  '@scope',
  '@scope/',
  '@/name',
  '@scope/name/extra',
  '@sco pe/name',
  '@scope/na me',
  'bad%name',
  'bad?name',
  'bad@name'
];

for (const packageName of invalidPackageNames) {
  test('invalid package name is flagged ' + JSON.stringify(packageName), () => {
    const report = auditSpecifier(packageName, '1.0.0');
    assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.SPEC_INVALID_PACKAGE_NAME), true);
    assert.equal(report.ok, false);
  });
}

const hostilePackageNames = [
  ['packäge', SEMVERCAGE_FINDING_CODES.SPEC_HOMOGLYPH_NAME],
  ['pack\u202eage', SEMVERCAGE_FINDING_CODES.SPEC_HOMOGLYPH_NAME],
  ['pack\0age', SEMVERCAGE_FINDING_CODES.SPEC_CONTROL_CHARACTERS],
  ['pack\u001bage', SEMVERCAGE_FINDING_CODES.SPEC_CONTROL_CHARACTERS]
];

for (const [packageName, code] of hostilePackageNames) {
  test('hostile package name is flagged ' + JSON.stringify(packageName), () => {
    const report = auditSpecifier(packageName, '1.0.0');
    assert.equal(hasFinding(report, code), true);
    assert.equal(report.ok, false);
  });
}

const privateNames = ['internal-tool', 'corp-ui', 'private-api', 'company-lib', 'local-utils', 'infra-client'];
for (const packageName of privateNames) {
  test('private-looking unscoped name is flagged ' + packageName, () => {
    const report = auditSpecifier(packageName, '1.0.0');
    assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.SPEC_PRIVATE_NAME_CONFUSION, 'medium'), true);
  });
}

test('scoped internal package does not trigger unscoped dependency confusion signal', () => {
  const report = auditSpecifier('@corp/internal-tool', '1.0.0');
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.SPEC_PRIVATE_NAME_CONFUSION), false);
});

const separatorNames = ['foo_bar-baz', 'foo--bar', 'foo..bar', 'foo_-bar', '-foo', 'foo-'];
for (const packageName of separatorNames) {
  test('separator confusion is reported ' + packageName, () => {
    const report = auditSpecifier(packageName, '1.0.0');
    assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.SPEC_SEPARATOR_CONFUSION), true);
  });
}

test('auditSpecifier report is frozen', () => {
  const report = auditSpecifier('simplepackage', '*');
  assert.equal(Object.isFrozen(report), true);
  assert.equal(Object.isFrozen(report.findings), true);
  assert.equal(Object.isFrozen(report.findings[0]), true);
});
test('auditSpecifier rejects non string input', () => {
  assert.throws(() => auditSpecifier(null, '1.0.0'), (error) => error.code === SEMVERCAGE_ERROR_CODES.INVALID_INPUT);
});

test('clean package manifest passes', () => {
  const report = auditPackageJson({
    name: 'clean-service',
    dependencies: { simplepackage: '1.2.3' },
    devDependencies: { testtools: '^1.0.0' }
  });
  assert.deepEqual(report.findings, []);
  assert.equal(report.ok, true);
  assert.equal(report.dependencyCount, 2);
});

for (const field of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
  test('manifest audits dependency field ' + field, () => {
    const manifest = { name: 'clean-service' };
    manifest[field] = { simplepackage: '*' };
    const report = auditPackageJson(manifest);
    assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.SPEC_UNPINNED_WILDCARD), true);
    assert.equal(report.ok, false);
  });
  test('manifest rejects non object dependency field ' + field, () => {
    const manifest = { name: 'clean-service' };
    manifest[field] = ['simplepackage'];
    const report = auditPackageJson(manifest);
    assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.MANIFEST_INVALID_DEPENDENCY_FIELD), true);
  });
}

test('manifest audits direct overrides', () => {
  const report = auditPackageJson({ name: 'clean-service', overrides: { simplepackage: '>=1.0.0' } });
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.SPEC_BROAD_UNBOUNDED_RANGE), true);
});
test('manifest audits nested overrides', () => {
  const report = auditPackageJson({ name: 'clean-service', overrides: { parent: { simplepackage: 'github:org/repo' } } });
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.SPEC_HOSTING_SHORTHAND), true);
});
test('manifest audits resolutions', () => {
  const report = auditPackageJson({ name: 'clean-service', resolutions: { simplepackage: 'latest' } });
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.SPEC_UNPINNED_DIST_TAG), true);
});
test('manifest flags invalid override leaf', () => {
  const report = auditPackageJson({ name: 'clean-service', overrides: { simplepackage: true } });
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.MANIFEST_INVALID_DEPENDENCY_FIELD), true);
});

for (const hook of ['preinstall', 'install', 'postinstall']) {
  test('manifest flags high risk lifecycle hook ' + hook, () => {
    const manifest = { name: 'clean-service', scripts: {} };
    manifest.scripts[hook] = 'node hook.js';
    const report = auditPackageJson(manifest);
    assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.MANIFEST_LIFECYCLE_SCRIPT, 'high'), true);
    assert.equal(report.lifecycleScriptCount, 1);
  });
}
test('manifest flags prepare lifecycle hook as medium risk', () => {
  const report = auditPackageJson({ name: 'clean-service', scripts: { prepare: 'node build.js' } });
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.MANIFEST_LIFECYCLE_SCRIPT, 'medium'), true);
});
test('manifest does not flag ordinary scripts', () => {
  const report = auditPackageJson({ name: 'clean-service', scripts: { test: 'node test.js', build: 'node build.js' } });
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.MANIFEST_LIFECYCLE_SCRIPT), false);
});

for (const field of ['bundledDependencies', 'bundleDependencies']) {
  test('manifest flags bundled dependencies field ' + field, () => {
    const manifest = { name: 'clean-service' };
    manifest[field] = ['simplepackage'];
    const report = auditPackageJson(manifest);
    assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.MANIFEST_BUNDLED_DEPENDENCIES), true);
  });
}

for (const serialized of [
  '{"name":"clean-service","__proto__":{"polluted":true}}',
  '{"name":"clean-service","constructor":{"prototype":{"polluted":true}}}',
  '{"name":"clean-service","dependencies":{"__proto__":"1.0.0"}}'
]) {
  test('manifest detects prototype pollution keys', () => {
    const report = auditPackageJson(serialized);
    assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.PROTOTYPE_POLLUTION_KEY, 'critical'), true);
    assert.equal(report.ok, false);
  });
}

test('manifest root package name is audited', () => {
  const report = auditPackageJson({ name: 'UPPERCASE', dependencies: { simplepackage: '1.0.0' } });
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.SPEC_INVALID_PACKAGE_NAME), true);
});
test('manifest JSON input is accepted', () => {
  const report = auditPackageJson('{"name":"clean-service","dependencies":{"simplepackage":"1.0.0"}}');
  assert.equal(report.ok, true);
});
test('invalid manifest JSON throws a structured error', () => {
  assert.throws(() => auditPackageJson('{'), (error) => error.code === SEMVERCAGE_ERROR_CODES.INVALID_MANIFEST);
});
test('manifest report is frozen', () => {
  const report = auditPackageJson({ name: 'clean-service', dependencies: { simplepackage: '*' } });
  assert.equal(Object.isFrozen(report), true);
  assert.equal(Object.isFrozen(report.counts), true);
});
