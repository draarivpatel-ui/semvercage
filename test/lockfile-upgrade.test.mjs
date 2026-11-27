import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SEMVERCAGE_ERROR_CODES,
  SEMVERCAGE_FINDING_CODES,
  auditLockfile,
  auditUpgrade
} from '../src/index.mjs';

const SHA512 = 'sha512-' + 'A'.repeat(86) + '==';
const SHA384 = 'sha384-' + 'B'.repeat(64);
const SHA256 = 'sha256-' + 'C'.repeat(43) + '=';
const SHA1 = 'sha1-' + 'D'.repeat(27) + '=';

function validLock() {
  return {
    lockfileVersion: 3,
    packages: {
      '': { name: 'root-package' },
      'node_modules/sample-package': {
        version: '1.2.3',
        resolved: 'https://registry.npmjs.org/sample-package/-/sample-package-1.2.3.tgz',
        integrity: SHA512
      }
    }
  };
}

function mutateValid(mutator) {
  const lockfile = validLock();
  mutator(lockfile);
  return lockfile;
}

function hasFinding(report, code, severity = undefined) {
  return report.findings.some((finding) => finding.code === code && (severity === undefined || finding.severity === severity));
}

for (const lockfileVersion of [2, 3]) {
  test('valid package-lock v' + lockfileVersion + ' passes', () => {
    const lockfile = validLock();
    lockfile.lockfileVersion = lockfileVersion;
    const report = auditLockfile(lockfile);
    assert.deepEqual(report.findings, []);
    assert.equal(report.ok, true);
    assert.equal(report.packageCount, 1);
  });
}

for (const version of [0, 1, 4, '3', null]) {
  test('unsupported lockfile version is critical ' + JSON.stringify(version), () => {
    const lockfile = validLock();
    lockfile.lockfileVersion = version;
    const report = auditLockfile(lockfile);
    assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_UNSUPPORTED_VERSION, 'critical'), true);
    assert.equal(report.ok, false);
  });
}

test('missing packages object is critical', () => {
  const report = auditLockfile({ lockfileVersion: 3 });
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_MISSING_PACKAGES, 'critical'), true);
});
for (const packages of [null, [], 'bad']) {
  test('invalid packages object is critical ' + JSON.stringify(packages), () => {
    const report = auditLockfile({ lockfileVersion: 3, packages });
    assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_MISSING_PACKAGES, 'critical'), true);
  });
}
for (const entry of [null, [], 'bad']) {
  test('invalid package entry is flagged ' + JSON.stringify(entry), () => {
    const report = auditLockfile(mutateValid((lockfile) => {
      lockfile.packages['node_modules/sample-package'] = entry;
    }));
    assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_INVALID_PACKAGE_ENTRY, 'high'), true);
  });
}

const integrityCases = [
  ['missing', undefined, SEMVERCAGE_FINDING_CODES.LOCKFILE_MISSING_INTEGRITY, 'high'],
  ['sha1', SHA1, SEMVERCAGE_FINDING_CODES.LOCKFILE_WEAK_INTEGRITY, 'high'],
  ['sha384', SHA384, SEMVERCAGE_FINDING_CODES.LOCKFILE_WEAK_INTEGRITY, 'medium'],
  ['sha256', SHA256, SEMVERCAGE_FINDING_CODES.LOCKFILE_WEAK_INTEGRITY, 'medium'],
  ['empty', '', SEMVERCAGE_FINDING_CODES.LOCKFILE_MALFORMED_INTEGRITY, 'high'],
  ['wrong type', 42, SEMVERCAGE_FINDING_CODES.LOCKFILE_MALFORMED_INTEGRITY, 'high'],
  ['bad algorithm', 'md5-' + 'A'.repeat(32), SEMVERCAGE_FINDING_CODES.LOCKFILE_MALFORMED_INTEGRITY, 'high'],
  ['short sha512', 'sha512-AAAA', SEMVERCAGE_FINDING_CODES.LOCKFILE_MALFORMED_INTEGRITY, 'high'],
  ['bad base64', 'sha512-' + '!'.repeat(86) + '==', SEMVERCAGE_FINDING_CODES.LOCKFILE_MALFORMED_INTEGRITY, 'high'],
  ['interior padding', 'sha512-' + 'A'.repeat(40) + '==' + 'A'.repeat(44), SEMVERCAGE_FINDING_CODES.LOCKFILE_MALFORMED_INTEGRITY, 'high'],
  ['excess padding', 'sha512-' + 'A'.repeat(85) + '===', SEMVERCAGE_FINDING_CODES.LOCKFILE_MALFORMED_INTEGRITY, 'high'],
  ['mixed sha512 sha1', SHA512 + ' ' + SHA1, SEMVERCAGE_FINDING_CODES.LOCKFILE_WEAK_INTEGRITY, 'high']
];

for (const [label, integrity, code, severity] of integrityCases) {
  test('lockfile integrity case ' + label, () => {
    const report = auditLockfile(mutateValid((lockfile) => {
      const entry = lockfile.packages['node_modules/sample-package'];
      if (integrity === undefined) delete entry.integrity;
      else entry.integrity = integrity;
    }));
    assert.equal(hasFinding(report, code, severity), true);
    assert.equal(report.ok, false);
  });
}

test('strong sha512 integrity produces no integrity finding', () => {
  const report = auditLockfile(validLock());
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_WEAK_INTEGRITY), false);
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_MALFORMED_INTEGRITY), false);
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_MISSING_INTEGRITY), false);
});

const resolvedCases = [
  ['http URL', 'http://registry.npmjs.org/sample-package/-/sample-package-1.2.3.tgz', SEMVERCAGE_FINDING_CODES.LOCKFILE_NON_HTTPS_RESOLVED, 'critical'],
  ['git URL', 'git://registry.npmjs.org/sample-package.git', SEMVERCAGE_FINDING_CODES.LOCKFILE_NON_HTTPS_RESOLVED, 'critical'],
  ['credentials', 'https://user:pass@registry.npmjs.org/sample-package/-/sample-package-1.2.3.tgz', SEMVERCAGE_FINDING_CODES.LOCKFILE_CREDENTIALS_RESOLVED, 'critical'],
  ['ipv4 literal', 'https://127.0.0.1/sample-package/-/sample-package-1.2.3.tgz', SEMVERCAGE_FINDING_CODES.LOCKFILE_IP_LITERAL_RESOLVED, 'critical'],
  ['ipv6 literal', 'https://[2001:db8::1]/sample-package/-/sample-package-1.2.3.tgz', SEMVERCAGE_FINDING_CODES.LOCKFILE_IP_LITERAL_RESOLVED, 'critical'],
  ['untrusted host', 'https://evil.example.com/sample-package/-/sample-package-1.2.3.tgz', SEMVERCAGE_FINDING_CODES.LOCKFILE_UNTRUSTED_REGISTRY, 'high'],
  ['explicit unusual port', 'https://registry.npmjs.org:444/sample-package/-/sample-package-1.2.3.tgz', SEMVERCAGE_FINDING_CODES.LOCKFILE_UNTRUSTED_REGISTRY, 'high'],
  ['control character', 'https://registry.npmjs.org/sample-package\0', SEMVERCAGE_FINDING_CODES.LOCKFILE_UNTRUSTED_REGISTRY, 'critical'],
  ['non ASCII', 'https://registry.npmjs.org/packäge.tgz', SEMVERCAGE_FINDING_CODES.LOCKFILE_UNTRUSTED_REGISTRY, 'critical'],
  ['unparseable', 'https://', SEMVERCAGE_FINDING_CODES.LOCKFILE_UNTRUSTED_REGISTRY, 'high']
];

for (const [label, resolved, code, severity] of resolvedCases) {
  test('lockfile resolved URL case ' + label, () => {
    const report = auditLockfile(mutateValid((lockfile) => {
      lockfile.packages['node_modules/sample-package'].resolved = resolved;
    }));
    assert.equal(hasFinding(report, code, severity), true);
    assert.equal(report.ok, false);
  });
}

test('credential-bearing resolved URL is redacted', () => {
  const report = auditLockfile(mutateValid((lockfile) => {
    lockfile.packages['node_modules/sample-package'].resolved = 'https://user:pass@registry.npmjs.org/sample-package/-/sample-package-1.2.3.tgz';
  }));
  assert.equal(JSON.stringify(report).includes('user:pass'), false);
  assert.equal(JSON.stringify(report).includes('<redacted>@'), true);
});
test('missing resolved URL is flagged', () => {
  const report = auditLockfile(mutateValid((lockfile) => {
    delete lockfile.packages['node_modules/sample-package'].resolved;
  }));
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_MISSING_RESOLVED, 'medium'), true);
});
test('trusted registry override accepts an internal mirror', () => {
  const report = auditLockfile(mutateValid((lockfile) => {
    lockfile.packages['node_modules/sample-package'].resolved = 'https://registry.example.com/sample-package/-/sample-package-1.2.3.tgz';
  }), { trustedRegistries: ['registry.example.com'] });
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_UNTRUSTED_REGISTRY), false);
});
test('default policy flags an internal mirror as unexpected', () => {
  const report = auditLockfile(mutateValid((lockfile) => {
    lockfile.packages['node_modules/sample-package'].resolved = 'https://registry.example.com/sample-package/-/sample-package-1.2.3.tgz';
  }));
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_UNTRUSTED_REGISTRY), true);
});
test('linked workspace entries do not require registry integrity metadata', () => {
  const report = auditLockfile(mutateValid((lockfile) => {
    lockfile.packages['node_modules/sample-package'] = { link: true, resolved: '../sample-package' };
  }));
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_MISSING_INTEGRITY), false);
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_MISSING_RESOLVED), false);
});

const invalidVersions = ['', '1', '1.2', '01.0.0', '1.0.0-01', 'v1.0.0', '1.0.0 ', '1.0.0é', null, 42, true, '9007199254740992.0.0'];
for (const version of invalidVersions) {
  test('lockfile invalid version is flagged ' + JSON.stringify(version), () => {
    const report = auditLockfile(mutateValid((lockfile) => {
      lockfile.packages['node_modules/sample-package'].version = version;
    }));
    assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_INVALID_VERSION, 'high'), true);
  });
}

for (const [entryVersion, urlVersion, shouldFlag] of [
  ['1.2.4', '1.2.3', true],
  ['2.0.0', '1.2.3', true],
  ['1.2.3', '1.2.3', false],
  ['1.2.3+build', '1.2.3', false]
]) {
  test('tarball URL version consistency ' + entryVersion + ' versus ' + urlVersion, () => {
    const report = auditLockfile(mutateValid((lockfile) => {
      const entry = lockfile.packages['node_modules/sample-package'];
      entry.version = entryVersion;
      entry.resolved = 'https://registry.npmjs.org/sample-package/-/sample-package-' + urlVersion + '.tgz';
    }));
    assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_VERSION_MISMATCH), shouldFlag);
  });
}

test('entry name mismatch is flagged', () => {
  const report = auditLockfile(mutateValid((lockfile) => {
    lockfile.packages['node_modules/sample-package'].name = 'other-package';
  }));
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_PACKAGE_NAME_MISMATCH, 'high'), true);
});
test('matching entry name is accepted', () => {
  const report = auditLockfile(mutateValid((lockfile) => {
    lockfile.packages['node_modules/sample-package'].name = 'sample-package';
  }));
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_PACKAGE_NAME_MISMATCH), false);
});
test('private-looking transitive package name is flagged', () => {
  const report = auditLockfile(mutateValid((lockfile) => {
    lockfile.packages['node_modules/internal-tool'] = {
      version: '1.0.0',
      resolved: 'https://registry.npmjs.org/internal-tool/-/internal-tool-1.0.0.tgz',
      integrity: SHA512
    };
  }));
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.SPEC_PRIVATE_NAME_CONFUSION), true);
});
test('scoped transitive package path is inferred', () => {
  const report = auditLockfile(mutateValid((lockfile) => {
    lockfile.packages['node_modules/@scope/sample-package'] = {
      version: '1.0.0',
      resolved: 'https://registry.npmjs.org/@scope/sample-package/-/sample-package-1.0.0.tgz',
      integrity: SHA512
    };
  }));
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.SPEC_INVALID_PACKAGE_NAME), false);
});

test('one transitive install script is flagged', () => {
  const report = auditLockfile(mutateValid((lockfile) => {
    lockfile.packages['node_modules/sample-package'].hasInstallScript = true;
  }));
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_INSTALL_SCRIPT, 'high'), true);
  assert.equal(report.installScriptCount, 1);
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_DUPLICATE_INSTALL_SCRIPT), false);
});
test('multiple transitive install scripts produce duplicate risk finding', () => {
  const report = auditLockfile(mutateValid((lockfile) => {
    lockfile.packages['node_modules/sample-package'].hasInstallScript = true;
    lockfile.packages['node_modules/other-package'] = {
      version: '1.0.0',
      resolved: 'https://registry.npmjs.org/other-package/-/other-package-1.0.0.tgz',
      integrity: SHA512,
      hasInstallScript: true
    };
  }));
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_DUPLICATE_INSTALL_SCRIPT, 'high'), true);
  assert.equal(report.installScriptCount, 2);
});

function addLegacy(lockfile, legacyEntry) {
  lockfile.dependencies = { 'sample-package': legacyEntry };
}
test('matching legacy dependency snapshot produces no consistency finding', () => {
  const report = auditLockfile(mutateValid((lockfile) => {
    addLegacy(lockfile, { version: '1.2.3', integrity: SHA512 });
  }));
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_VERSION_MISMATCH), false);
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_INTEGRITY_MISMATCH), false);
});
test('legacy version mismatch is flagged', () => {
  const report = auditLockfile(mutateValid((lockfile) => {
    addLegacy(lockfile, { version: '1.2.4', integrity: SHA512 });
  }));
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_VERSION_MISMATCH, 'high'), true);
});
test('legacy integrity mismatch is flagged', () => {
  const report = auditLockfile(mutateValid((lockfile) => {
    addLegacy(lockfile, { version: '1.2.3', integrity: 'sha512-' + 'B'.repeat(86) + '==' });
  }));
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_INTEGRITY_MISMATCH, 'high'), true);
});
test('legacy install script matching packages snapshot is not undeclared', () => {
  const report = auditLockfile(mutateValid((lockfile) => {
    lockfile.packages['node_modules/sample-package'].hasInstallScript = true;
    addLegacy(lockfile, { version: '1.2.3', integrity: SHA512, hasInstallScript: true });
  }));
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_UNDECLARED_INSTALL_SCRIPT), false);
});
test('legacy install script missing from packages snapshot is critical', () => {
  const report = auditLockfile(mutateValid((lockfile) => {
    addLegacy(lockfile, { version: '1.2.3', integrity: SHA512, hasInstallScript: true });
  }));
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.LOCKFILE_UNDECLARED_INSTALL_SCRIPT, 'critical'), true);
});

for (const serialized of [
  '{"lockfileVersion":3,"packages":{"__proto__":{}}}',
  '{"lockfileVersion":3,"packages":{"":{"constructor":{"prototype":{}}}}}'
]) {
  test('lockfile detects prototype pollution keys', () => {
    const report = auditLockfile(serialized);
    assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.PROTOTYPE_POLLUTION_KEY, 'critical'), true);
  });
}

test('object breadth bound is enforced', () => {
  const lockfile = validLock();
  for (let index = 0; index < 20; index += 1) {
    lockfile.packages['node_modules/p' + index] = { version: '1.0.0', resolved: 'https://registry.npmjs.org/p' + index + '/-/p' + index + '-1.0.0.tgz', integrity: SHA512 };
  }
  const report = auditLockfile(lockfile, { maxObjectKeys: 10 });
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.OBJECT_BREADTH_EXCEEDED, 'high'), true);
});
test('object depth bound is enforced', () => {
  const report = auditLockfile({ lockfileVersion: 3, packages: {}, extra: { a: { b: { c: {} } } } }, { maxObjectDepth: 2 });
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.OBJECT_DEPTH_EXCEEDED, 'high'), true);
});
test('cyclic direct object input is flagged without hanging', () => {
  const lockfile = validLock();
  lockfile.self = lockfile;
  const report = auditLockfile(lockfile);
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.OBJECT_CYCLE, 'high'), true);
});
test('invalid lockfile JSON throws a structured error', () => {
  assert.throws(() => auditLockfile('{'), (error) => error.code === SEMVERCAGE_ERROR_CODES.INVALID_LOCKFILE);
});
test('lockfile report is frozen', () => {
  const report = auditLockfile(validLock());
  assert.equal(Object.isFrozen(report), true);
  assert.equal(Object.isFrozen(report.findings), true);
});

const upgradeCases = [
  ['2.1.0', '1.9.0', 'balanced', SEMVERCAGE_FINDING_CODES.UPGRADE_DOWNGRADE, 'critical'],
  ['1.2.3', '1.2.2', 'balanced', SEMVERCAGE_FINDING_CODES.UPGRADE_DOWNGRADE, 'critical'],
  ['2.0.0-alpha', '1.9.9', 'balanced', SEMVERCAGE_FINDING_CODES.UPGRADE_DOWNGRADE, 'critical'],
  ['1.0.0+one', '1.0.0+two', 'balanced', SEMVERCAGE_FINDING_CODES.UPGRADE_BUILD_METADATA_ONLY, 'critical'],
  ['1.0.0-alpha+one', '1.0.0-alpha+two', 'balanced', SEMVERCAGE_FINDING_CODES.UPGRADE_BUILD_METADATA_ONLY, 'critical'],
  ['1.0.0', '1.0.0', 'balanced', SEMVERCAGE_FINDING_CODES.UPGRADE_NO_CHANGE, 'info'],
  ['1.0.0', '2.0.0', 'strict', SEMVERCAGE_FINDING_CODES.UPGRADE_MAJOR_JUMP, 'medium'],
  ['1.0.0', '3.0.0', 'strict', SEMVERCAGE_FINDING_CODES.UPGRADE_MAJOR_JUMP, 'high'],
  ['1.0.0', '3.0.0', 'balanced', SEMVERCAGE_FINDING_CODES.UPGRADE_MAJOR_JUMP, 'high'],
  ['1.2.3', '1.3.0-rc.1', 'balanced', SEMVERCAGE_FINDING_CODES.UPGRADE_PRERELEASE_TRANSITION, 'high'],
  ['1.2.3-rc.1', '1.2.4-rc.2', 'balanced', SEMVERCAGE_FINDING_CODES.UPGRADE_PRERELEASE_TRANSITION, 'medium']
];

for (const [from, to, policy, code, severity] of upgradeCases) {
  test('upgrade guard ' + from + ' to ' + to + ' policy ' + policy, () => {
    const report = auditUpgrade(from, to, policy);
    assert.equal(hasFinding(report, code, severity), true);
  });
}

const cleanUpgradeCases = [
  ['1.0.0', '1.0.1'],
  ['1.0.0', '1.1.0'],
  ['1.0.0-alpha', '1.0.0'],
  ['0.9.9', '0.10.0']
];

for (const [from, to] of cleanUpgradeCases) {
  test('ordinary upgrade has no blocking finding ' + from + ' to ' + to, () => {
    const report = auditUpgrade(from, to, 'balanced');
    assert.equal(report.findings.filter((finding) => finding.severity !== 'info').length, 0);
    assert.equal(report.ok, true);
  });
}

test('balanced policy permits one major jump by default', () => {
  const report = auditUpgrade('1.0.0', '2.0.0', 'balanced');
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.UPGRADE_MAJOR_JUMP), false);
});
test('custom maxMajorJump permits configured jumps', () => {
  const report = auditUpgrade('1.0.0', '3.0.0', { policy: 'strict', maxMajorJump: 2 });
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.UPGRADE_MAJOR_JUMP), false);
});
test('custom maxMajorJump still detects excess jumps', () => {
  const report = auditUpgrade('1.0.0', '4.0.0', { policy: 'strict', maxMajorJump: 2 });
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.UPGRADE_MAJOR_JUMP), true);
});
test('downgrade is blocked in every policy', () => {
  for (const policy of ['strict', 'balanced', 'ci']) {
    const report = auditUpgrade('2.0.0', '1.0.0', policy);
    assert.equal(report.ok, false);
  }
});
test('build metadata substitution is blocked in every policy', () => {
  for (const policy of ['strict', 'balanced', 'ci']) {
    const report = auditUpgrade('1.0.0+aaa', '1.0.0+bbb', policy);
    assert.equal(report.ok, false);
  }
});
test('stable to prerelease transition is blocked in ci policy', () => {
  const report = auditUpgrade('1.0.0', '1.1.0-alpha', 'ci');
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.UPGRADE_PRERELEASE_TRANSITION, 'high'), true);
  assert.equal(report.ok, false);
});
test('upgrade report is frozen and includes comparison', () => {
  const report = auditUpgrade('1.0.0', '1.1.0');
  assert.equal(Object.isFrozen(report), true);
  assert.equal(report.comparison, -1);
});
test('shared noncyclic object references do not produce a cycle finding', () => {
  const shared = { note: 'shared' };
  const lockfile = validLock();
  lockfile.extraA = shared;
  lockfile.extraB = shared;
  const report = auditLockfile(lockfile);
  assert.equal(hasFinding(report, SEMVERCAGE_FINDING_CODES.OBJECT_CYCLE), false);
});
