import test from 'node:test';
import assert from 'node:assert/strict';
import { SEMVERCAGE_ERROR_CODES, parseRange, satisfies } from '../src/index.mjs';

function expectMatch(version, range, expected) {
  test('range ' + range + ' versus ' + version + ' is ' + expected, () => {
    assert.equal(satisfies(version, range), expected);
  });
}

const exactCases = [
  ['1.2.3', '1.2.3', true],
  ['1.2.3+build', '1.2.3', true],
  ['1.2.3', '1.2.3+build', true],
  ['1.2.4', '1.2.3', false],
  ['1.2.3-alpha', '1.2.3', false],
  ['1.2.3-alpha', '1.2.3-alpha', true],
  ['1.2.3-alpha+build', '1.2.3-alpha', true],
  ['1.2.3-beta', '1.2.3-alpha', false],
  ['1.2.0', '1.2', true],
  ['1.2.99', '1.2', true],
  ['1.3.0', '1.2', false],
  ['1.1.9', '1.2', false],
  ['1.0.0', '1', true],
  ['1.99.99', '1', true],
  ['2.0.0', '1', false],
  ['0.9.9', '1', false],
  ['0.0.0', '0', true],
  ['0.99.99', '0', true],
  ['1.0.0', '0', false],
  ['1.2.3', '=1.2.3', true],
  ['1.2.4', '=1.2.3', false],
  ['1.2.0', '=1.2', true],
  ['1.3.0', '=1.2', false]
];
for (const [version, range, expected] of exactCases) expectMatch(version, range, expected);

const operatorCases = [
  ['1.2.3', '>=1.2.3', true],
  ['1.2.4', '>=1.2.3', true],
  ['1.2.2', '>=1.2.3', false],
  ['2.0.0', '>=1.2.3', true],
  ['1.2.4', '>1.2.3', true],
  ['1.2.3', '>1.2.3', false],
  ['1.2.2', '>1.2.3', false],
  ['1.2.2', '<1.2.3', true],
  ['1.2.3', '<1.2.3', false],
  ['1.2.4', '<1.2.3', false],
  ['1.2.3', '<=1.2.3', true],
  ['1.2.2', '<=1.2.3', true],
  ['1.2.4', '<=1.2.3', false],
  ['1.2.0', '>=1.2', true],
  ['1.2.99', '>=1.2', true],
  ['1.1.99', '>=1.2', false],
  ['1.3.0', '>1.2', true],
  ['1.2.99', '>1.2', false],
  ['2.0.0', '>1.2', true],
  ['1.1.99', '<1.2', true],
  ['1.2.0', '<1.2', false],
  ['0.0.0', '<1.2', true],
  ['1.2.99', '<=1.2', true],
  ['1.3.0', '<=1.2', false],
  ['1.9.99', '<=1', true],
  ['2.0.0', '<=1', false],
  ['1.0.0', '>0', true],
  ['0.9.9', '>0', false],
  ['0.0.0', '<0', false],
  ['0.0.1', '<0', false],
  ['1.0.0', '<2', true],
  ['2.0.0', '<2', false],
  ['1.2.3', '>=1.2.3 <2.0.0', true],
  ['1.9.9', '>=1.2.3 <2.0.0', true],
  ['2.0.0', '>=1.2.3 <2.0.0', false],
  ['1.2.2', '>=1.2.3 <2.0.0', false]
];
for (const [version, range, expected] of operatorCases) expectMatch(version, range, expected);

const caretCases = [
  ['1.2.3', '^1.2.3', true],
  ['1.9.9', '^1.2.3', true],
  ['2.0.0', '^1.2.3', false],
  ['1.2.2', '^1.2.3', false],
  ['0.2.3', '^0.2.3', true],
  ['0.2.9', '^0.2.3', true],
  ['0.3.0', '^0.2.3', false],
  ['0.0.3', '^0.0.3', true],
  ['0.0.4', '^0.0.3', false],
  ['0.0.2', '^0.0.3', false],
  ['1.2.0', '^1.2', true],
  ['1.9.9', '^1.2', true],
  ['2.0.0', '^1.2', false],
  ['0.2.0', '^0.2', true],
  ['0.2.9', '^0.2', true],
  ['0.3.0', '^0.2', false],
  ['0.0.0', '^0', true],
  ['0.9.9', '^0', true],
  ['1.0.0', '^0', false],
  ['0.0.0', '^0.0', true],
  ['0.0.9', '^0.0', true],
  ['0.1.0', '^0.0', false],
  ['1.2.3-rc.1', '^1.2.3-rc.1', true],
  ['1.2.3-rc.2', '^1.2.3-rc.1', true],
  ['1.2.4', '^1.2.3-rc.1', true],
  ['1.2.4-rc.1', '^1.2.3-rc.1', false]
];
for (const [version, range, expected] of caretCases) expectMatch(version, range, expected);

const tildeCases = [
  ['1.2.3', '~1.2.3', true],
  ['1.2.9', '~1.2.3', true],
  ['1.3.0', '~1.2.3', false],
  ['1.2.2', '~1.2.3', false],
  ['1.2.0', '~1.2', true],
  ['1.2.99', '~1.2', true],
  ['1.3.0', '~1.2', false],
  ['1.0.0', '~1', true],
  ['1.99.99', '~1', true],
  ['2.0.0', '~1', false],
  ['0.0.0', '~0', true],
  ['0.99.99', '~0', true],
  ['1.0.0', '~0', false],
  ['0.2.0', '~0.2', true],
  ['0.2.99', '~0.2', true],
  ['0.3.0', '~0.2', false],
  ['1.2.3-beta.1', '~1.2.3-beta.1', true],
  ['1.2.3-beta.2', '~1.2.3-beta.1', true],
  ['1.2.4-beta.1', '~1.2.3-beta.1', false],
  ['1.2.4', '~1.2.3-beta.1', true]
];
for (const [version, range, expected] of tildeCases) expectMatch(version, range, expected);

const xRangeCases = [
  ['1.0.0', '*', true],
  ['999.0.0', '*', true],
  ['1.0.0-alpha', '*', false],
  ['1.0.0', 'x', true],
  ['1.0.0', 'X', true],
  ['1.2.0', '1.2.x', true],
  ['1.2.99', '1.2.x', true],
  ['1.3.0', '1.2.x', false],
  ['1.1.99', '1.2.x', false],
  ['1.0.0', '1.x', true],
  ['1.99.99', '1.x', true],
  ['2.0.0', '1.x', false],
  ['0.9.9', '1.x', false],
  ['1.2.0', '1.2.*', true],
  ['1.3.0', '1.2.*', false],
  ['1.0.0', '1.x.x', true],
  ['2.0.0', '1.x.x', false],
  ['0.0.0', '0.x', true],
  ['0.9.9', '0.x', true],
  ['1.0.0', '0.x', false]
];
for (const [version, range, expected] of xRangeCases) expectMatch(version, range, expected);

const hyphenCases = [
  ['1.2.3', '1.2.3 - 2.3.4', true],
  ['1.5.0', '1.2.3 - 2.3.4', true],
  ['2.3.4', '1.2.3 - 2.3.4', true],
  ['2.3.5', '1.2.3 - 2.3.4', false],
  ['1.2.2', '1.2.3 - 2.3.4', false],
  ['1.0.0', '1.2 - 2.3', false],
  ['2.3.99', '1.2 - 2.3', true],
  ['2.4.0', '1.2 - 2.3', false],
  ['1.1.99', '1.2 - 2.3', false],
  ['1.0.0', '1 - 2', true],
  ['2.99.99', '1 - 2', true],
  ['3.0.0', '1 - 2', false],
  ['0.9.9', '1 - 2', false],
  ['1.2.3-alpha', '1.2.3-alpha - 1.2.4', true],
  ['1.2.3-beta', '1.2.3-alpha - 1.2.4', true],
  ['1.2.4-beta', '1.2.3-alpha - 1.2.4', false],
  ['1.2.4', '1.2.3-alpha - 1.2.4', true]
];
for (const [version, range, expected] of hyphenCases) expectMatch(version, range, expected);

const unionCases = [
  ['1.0.0', '1.0.0 || 2.0.0', true],
  ['2.0.0', '1.0.0 || 2.0.0', true],
  ['1.5.0', '1.0.0 || 2.0.0', false],
  ['1.5.0', '^1.0.0 || ^2.0.0', true],
  ['2.5.0', '^1.0.0 || ^2.0.0', true],
  ['3.0.0', '^1.0.0 || ^2.0.0', false],
  ['0.9.0', '<1.0.0 || >=2.0.0', true],
  ['2.0.0', '<1.0.0 || >=2.0.0', true],
  ['1.5.0', '<1.0.0 || >=2.0.0', false],
  ['1.2.0', '1.2.x || 2.2.x', true],
  ['2.2.0', '1.2.x || 2.2.x', true],
  ['2.3.0', '1.2.x || 2.2.x', false],
  ['1.0.0', '1.0.0||2.0.0', true],
  ['2.0.0', '1.0.0||2.0.0', true]
];
for (const [version, range, expected] of unionCases) expectMatch(version, range, expected);

const prereleaseCases = [
  ['1.0.0-alpha', '*', false, false],
  ['1.0.0-alpha', '*', true, true],
  ['1.0.0-alpha', '1.0.0-alpha', false, true],
  ['1.0.0-beta', '1.0.0-alpha', false, false],
  ['1.0.0-beta', '>1.0.0-alpha', false, true],
  ['1.0.0-alpha', '>1.0.0-alpha', false, false],
  ['1.0.1-beta', '>1.0.0-alpha', false, false],
  ['1.0.1-beta', '>1.0.0-alpha', true, true],
  ['1.0.1', '>1.0.0-alpha', false, true],
  ['1.0.0-beta', '>=1.0.0-alpha <2.0.0', false, true],
  ['1.5.0-beta', '>=1.0.0-alpha <2.0.0', false, false],
  ['1.5.0-beta', '>=1.0.0-alpha <2.0.0', true, true],
  ['1.5.0', '>=1.0.0-alpha <2.0.0', false, true],
  ['2.0.0-beta', '>=1.0.0-alpha <2.0.0', false, false],
  ['0.0.0-alpha', '*', false, false]
];

for (const [version, range, include, expected] of prereleaseCases) {
  test('prerelease isolation ' + version + ' in ' + range + ' include=' + include, () => {
    assert.equal(satisfies(version, range, { includePrerelease: include }), expected);
  });
}

test('parseRange returns frozen structured output', () => {
  const range = parseRange('>=1.0.0 <2.0.0 || ^3.0.0');
  assert.equal(range.kind, 'SEMVERCAGE_RANGE');
  assert.equal(range.unionCount, 2);
  assert.equal(range.comparatorCount, 4);
  assert.equal(Object.isFrozen(range), true);
  assert.equal(Object.isFrozen(range.unions), true);
  assert.equal(Object.isFrozen(range.unions[0].comparators), true);
});

test('parsed range objects can be reused for evaluation', () => {
  const range = parseRange('^1.2.0');
  assert.equal(satisfies('1.9.0', range), true);
  assert.equal(satisfies('2.0.0', range), false);
});

const malformedRanges = [
  '',
  ' ',
  ' 1.0.0',
  '1.0.0 ',
  '1.0.0  <2.0.0',
  '1.0.0\t<2.0.0',
  '1.0.0\n<2.0.0',
  '1.0.0\0',
  '1.0.0é',
  '1.0.0\u202e',
  '||',
  '1.0.0||',
  '||1.0.0',
  '1.0.0 ||| 2.0.0',
  '>=',
  '<=',
  '>',
  '<',
  '=',
  '^',
  '~',
  '>=*',
  '>x',
  '<x',
  '<=*',
  '= =1.0.0',
  '=>1.0.0',
  '=<1.0.0',
  '><1.0.0',
  '^=1.0.0',
  '~=1.0.0',
  '^^1.0.0',
  '~~1.0.0',
  '1.x.2',
  'x.1',
  '1.2.3.4',
  '01.2.3',
  '1.02.3',
  '1.2.03',
  '1.2-alpha',
  '1.2.3-',
  '1.2.3+',
  '1.2.3-01',
  '1.2.3-é',
  '1.2.3 é',
  '1.2.3_4',
  '1.2.3,4',
  '1.2.3;4',
  '1.0.0 | 2.0.0',
  '1.2.3 - ',
  ' - 1.2.3',
  '1.2.3 - 2.0.0 - 3.0.0',
  '1.2.3-2.0.0 - ',
  '1.2.3..4',
  'v1.2.3',
  '1.2.3=4',
  '1.2.3#4'
];

for (const range of malformedRanges) {
  test('rejects malformed range ' + JSON.stringify(range), () => {
    assert.throws(() => parseRange(range), (error) => error.code === SEMVERCAGE_ERROR_CODES.INVALID_RANGE || error.code === SEMVERCAGE_ERROR_CODES.INPUT_TOO_LONG);
  });
}

test('range union bound is enforced', () => {
  assert.throws(() => parseRange('1.0.0||2.0.0', { maxUnions: 1 }), (error) => error.code === SEMVERCAGE_ERROR_CODES.RANGE_TOO_COMPLEX);
});
test('range per union comparator bound is enforced', () => {
  assert.throws(() => parseRange('>=1.0.0 <2.0.0', { maxComparatorsPerUnion: 1 }), (error) => error.code === SEMVERCAGE_ERROR_CODES.RANGE_TOO_COMPLEX);
});
test('range total comparator bound is enforced', () => {
  assert.throws(() => parseRange('^1.0.0 || ^2.0.0', { maxComparatorsPerUnion: 2, maxTotalComparators: 3 }), (error) => error.code === SEMVERCAGE_ERROR_CODES.RANGE_TOO_COMPLEX);
});
test('range input length bound is enforced', () => {
  assert.throws(() => parseRange('1.0.0', { maxRangeLength: 4 }), (error) => error.code === SEMVERCAGE_ERROR_CODES.INPUT_TOO_LONG);
});
test('strict policy has tighter range bounds than balanced policy', () => {
  const range = Array.from({ length: 9 }, (_, index) => String(index + 1) + '.0.0').join('||');
  assert.throws(() => parseRange(range, { policy: 'strict' }), (error) => error.code === SEMVERCAGE_ERROR_CODES.RANGE_TOO_COMPLEX);
  assert.equal(parseRange(range, { policy: 'balanced' }).unionCount, 9);
});
test('empty comparator unions are rejected before evaluation', () => {
  for (const range of ['1.0.0 ||', '|| 1.0.0', '1.0.0 |||| 2.0.0']) {
    assert.throws(() => parseRange(range), (error) => error.code === SEMVERCAGE_ERROR_CODES.INVALID_RANGE);
  }
});
test('non string ranges are rejected', () => {
  assert.throws(() => parseRange(null), (error) => error.code === SEMVERCAGE_ERROR_CODES.INVALID_INPUT);
});
test('strict policy version length bound applies during satisfaction checks', () => {
  const longVersion = '1.0.0-' + Array.from({ length: 5 }, () => 'a'.repeat(40)).join('.');
  assert.throws(() => satisfies(longVersion, '*', { policy: 'strict' }), (error) => error.code === SEMVERCAGE_ERROR_CODES.INPUT_TOO_LONG);
});
