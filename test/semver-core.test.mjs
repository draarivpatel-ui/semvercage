import test from 'node:test';
import assert from 'node:assert/strict';
import {
  SEMVERCAGE_ERROR_CODES,
  SemverCageError,
  compareSemver,
  isValidSemver,
  parseSemver,
  tryParseSemver
} from '../src/index.mjs';

const validVersions = [];
for (const major of ['0', '1', '2', '10', '9007199254740991']) {
  for (const minor of ['0', '1', '23']) {
    for (const patch of ['0', '1', '9']) {
      validVersions.push([major + '.' + minor + '.' + patch, [Number(major), Number(minor), Number(patch)]]);
    }
  }
}

for (const [version, expected] of validVersions) {
  test('parses strict core version ' + version, () => {
    const parsed = parseSemver(version);
    assert.equal(parsed.version, version);
    assert.equal(parsed.major, expected[0]);
    assert.equal(parsed.minor, expected[1]);
    assert.equal(parsed.patch, expected[2]);
    assert.deepEqual(parsed.prerelease, []);
    assert.deepEqual(parsed.build, []);
    assert.equal(parsed.isPrerelease, false);
    assert.equal(parsed.hasBuild, false);
    assert.equal(Object.isFrozen(parsed), true);
    assert.equal(Object.isFrozen(parsed.prerelease), true);
  });
}

const prereleaseCases = [
  ['1.0.0-alpha', ['alpha']],
  ['1.0.0-alpha.1', ['alpha', '1']],
  ['1.0.0-0.3.7', ['0', '3', '7']],
  ['1.0.0-x-y-z', ['x-y-z']],
  ['1.0.0-alpha-beta', ['alpha-beta']],
  ['1.0.0-alpha.beta-1', ['alpha', 'beta-1']],
  ['1.0.0-a.b.c.d.e', ['a', 'b', 'c', 'd', 'e']],
  ['1.0.0-01alpha', ['01alpha']],
  ['1.0.0-alpha01', ['alpha01']],
  ['1.0.0-A.B-C.9', ['A', 'B-C', '9']],
  ['2.3.4-rc.11', ['rc', '11']],
  ['2.3.4-rc.11.z', ['rc', '11', 'z']],
  ['2.3.4-0', ['0']],
  ['2.3.4-0alpha', ['0alpha']],
  ['2.3.4-z-', ['z-']],
  ['2.3.4--z', ['-z']],
  ['2.3.4-a--b', ['a--b']],
  ['2.3.4--alpha', ['-alpha']]
];

for (const [version, identifiers] of prereleaseCases) {
  test('parses prerelease identifiers ' + version, () => {
    const parsed = parseSemver(version);
    assert.deepEqual([...parsed.prerelease], identifiers);
    assert.equal(parsed.isPrerelease, true);
    assert.equal(parsed.version, version);
  });
}

const buildCases = [
  ['1.0.0+001', ['001']],
  ['1.0.0+build', ['build']],
  ['1.0.0+build.1', ['build', '1']],
  ['1.0.0+meta-data', ['meta-data']],
  ['1.0.0+x.y.z', ['x', 'y', 'z']],
  ['1.0.0+0001.002.003', ['0001', '002', '003']],
  ['1.0.0+ABC-def.9', ['ABC-def', '9']],
  ['1.0.0-alpha+001', ['001']],
  ['1.0.0-alpha.1+build.001', ['build', '001']],
  ['1.0.0-0+meta.data', ['meta', 'data']],
  ['1.0.0+-alpha', ['-alpha']]
];

for (const [version, identifiers] of buildCases) {
  test('parses build metadata ' + version, () => {
    const parsed = parseSemver(version);
    assert.deepEqual([...parsed.build], identifiers);
    assert.equal(parsed.hasBuild, true);
    assert.equal(parsed.version, version);
  });
}

const invalidVersions = [
  '',
  '1',
  '1.2',
  '1.2.3.4',
  '1.2.x',
  'v1.2.3',
  '1.2.3v',
  '01.2.3',
  '1.02.3',
  '1.2.03',
  '00.0.0',
  '1.2.-3',
  '1..3',
  '.1.2.3',
  '1.2.3 ',
  ' 1.2.3',
  '1.2.3\t',
  '1.2.3\n',
  '1.2.3\r',
  '1.2.3\0',
  '1.2.3\u001b',
  '1.2.3é',
  '1.2.3\u202e',
  '1.2.3+',
  '1.0.0-',
  '1.0.0-alpha..1',
  '1.0.0-..',
  '1.0.0-alpha+',
  '1.0.0+alpha..1',
  '1.0.0+..',
  '1.0.0+a+b',
  '1.0.0-a+b+c',
  '1.0.0-00',
  '1.0.0-01',
  '1.0.0-0.01',
  '1.0.0-alpha.01',
  '1.0.0-000000000000000000000',
  '9007199254740992.0.0',
  '1.9007199254740992.0',
  '1.0.9007199254740992',
  '1.0.0-9007199254740992',
  '1.0.0-alpha_1',
  '1.0.0-alpha/1',
  '1.0.0-alpha@1',
  '1.0.0-alpha:1',
  '1.0.0+meta_data',
  '1.0.0+meta/data',
  '1.0.0+meta@data',
  '1.0.0-+alpha',
  '1.0.0-alpha#x',
  '1.0.0#x',
  '1.0.0?x',
  '1.0.0=1.0.0',
  '-1.0.0',
  '+1.0.0'
];

for (const version of invalidVersions) {
  test('rejects invalid semver input ' + JSON.stringify(version), () => {
    assert.equal(isValidSemver(version), false);
    assert.equal(tryParseSemver(version), null);
    assert.throws(() => parseSemver(version), SemverCageError);
  });
}

const overflowBoundary = '9007199254740991';
test('accepts the maximum safe integer boundary', () => {
  const parsed = parseSemver(overflowBoundary + '.' + overflowBoundary + '.' + overflowBoundary);
  assert.equal(parsed.major, Number(overflowBoundary));
});
test('rejects numeric prerelease overflow at the boundary', () => {
  assert.equal(isValidSemver('1.0.0-9007199254740992'), false);
});
test('accepts large numeric-looking build metadata because build identifiers are lexical', () => {
  assert.equal(isValidSemver('1.0.0+900719925474099200000'), true);
});
test('rejects an identifier over the default identifier bound', () => {
  assert.equal(isValidSemver('1.0.0-' + 'a'.repeat(65)), false);
});
test('accepts an identifier at the default identifier bound', () => {
  assert.equal(isValidSemver('1.0.0-' + 'a'.repeat(64)), true);
});
test('rejects a version over the default input length bound', () => {
  const version = '1.0.0-' + 'a.'.repeat(130) + 'z';
  assert.equal(version.length > 256, true);
  assert.equal(isValidSemver(version), false);
});
test('custom version length bound is enforced', () => {
  assert.throws(() => parseSemver('1.0.0', { maxVersionLength: 4 }), (error) => error.code === SEMVERCAGE_ERROR_CODES.INPUT_TOO_LONG);
});
test('custom identifier count bound is enforced', () => {
  assert.equal(isValidSemver('1.0.0-a.b.c', { maxVersionIdentifiers: 2 }), false);
});
test('parser rejects non string input', () => {
  assert.equal(tryParseSemver(null), null);
  assert.throws(() => parseSemver(null), SemverCageError);
});

const precedenceChain = [
  '1.0.0-alpha',
  '1.0.0-alpha.1',
  '1.0.0-alpha.beta',
  '1.0.0-beta',
  '1.0.0-beta.2',
  '1.0.0-beta.11',
  '1.0.0-rc.1',
  '1.0.0'
];

for (let index = 0; index < precedenceChain.length - 1; index += 1) {
  test('semver precedence chain ' + precedenceChain[index] + ' below ' + precedenceChain[index + 1], () => {
    assert.equal(compareSemver(precedenceChain[index], precedenceChain[index + 1]), -1);
    assert.equal(compareSemver(precedenceChain[index + 1], precedenceChain[index]), 1);
    assert.equal(compareSemver(precedenceChain[index], precedenceChain[index]), 0);
  });
}

const comparisonCases = [
  ['0.0.0', '0.0.1', -1],
  ['0.0.9', '0.1.0', -1],
  ['0.9.9', '1.0.0', -1],
  ['1.0.0', '1.0.1', -1],
  ['1.0.9', '1.1.0', -1],
  ['1.9.9', '2.0.0', -1],
  ['2.0.0', '10.0.0', -1],
  ['10.0.0', '2.0.0', 1],
  ['1.0.0-alpha', '1.0.0', -1],
  ['1.0.0-alpha', '1.0.0-alpha.0', -1],
  ['1.0.0-1', '1.0.0-alpha', -1],
  ['1.0.0-alpha.2', '1.0.0-alpha.10', -1],
  ['1.0.0-a', '1.0.0-b', -1],
  ['1.0.0-a.b', '1.0.0-a', 1],
  ['1.0.0+build', '1.0.0', 0],
  ['1.0.0+build.1', '1.0.0+build.2', 0],
  ['1.0.0-alpha+one', '1.0.0-alpha+two', 0],
  ['1.0.0-rc.1+exp', '1.0.0-rc.1', 0]
];

for (const [left, right, expected] of comparisonCases) {
  test('compares ' + left + ' and ' + right, () => {
    assert.equal(compareSemver(left, right), expected);
  });
}

for (const major of [0, 1, 2, 9]) {
  for (const minor of [0, 1, 7]) {
    for (const patch of [0, 3]) {
      const lower = major + '.' + minor + '.' + patch;
      const higher = major + '.' + minor + '.' + String(patch + 1);
      test('generated patch ordering ' + lower + ' below ' + higher, () => {
        assert.equal(compareSemver(lower, higher), -1);
      });
    }
  }
}

test('compare accepts parsed semver objects', () => {
  assert.equal(compareSemver(parseSemver('1.0.0'), parseSemver('1.0.1')), -1);
});
test('compare rejects malformed objects', () => {
  assert.throws(() => compareSemver({}, '1.0.0'), SemverCageError);
});
test('errors expose stable machine-readable codes', () => {
  try {
    parseSemver('01.0.0');
    assert.fail('parse should throw');
  } catch (error) {
    assert.equal(error instanceof SemverCageError, true);
    assert.equal(error.code, SEMVERCAGE_ERROR_CODES.INVALID_VERSION);
    assert.equal(Object.isFrozen(error.details), true);
  }
});
test('parser options must be an object', () => {
  assert.throws(() => parseSemver('1.0.0', null), (error) => error.code === SEMVERCAGE_ERROR_CODES.INVALID_INPUT);
  assert.throws(() => parseSemver('1.0.0', []), (error) => error.code === SEMVERCAGE_ERROR_CODES.INVALID_INPUT);
});
