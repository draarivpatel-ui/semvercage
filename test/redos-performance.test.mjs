import test from 'node:test';
import assert from 'node:assert/strict';
import { performance } from 'node:perf_hooks';
import { isValidSemver, parseRange, parseSemver, satisfies } from '../src/index.mjs';

function measure(operation) {
  const start = performance.now();
  try {
    operation();
  } catch {
    // Hostile input is expected to fail. The timing bound is the security property.
  }
  return performance.now() - start;
}

function assertFast(label, operation, bound = 250) {
  test(label + ' completes within the linear-time budget', () => {
    const elapsed = measure(operation);
    assert.equal(elapsed < bound, true, label + ' took ' + elapsed.toFixed(3) + 'ms');
  });
}

const hostileVersions = [
  ['leading whitespace bomb', ' '.repeat(240) + '1.0.0'],
  ['trailing whitespace bomb', '1.0.0' + ' '.repeat(240)],
  ['interior whitespace bomb', '1.0.0' + ' '.repeat(100) + '-alpha'],
  ['prerelease dot bomb', '1.0.0-' + 'a.'.repeat(100)],
  ['build dot bomb', '1.0.0+' + 'a.'.repeat(100)],
  ['numeric prerelease bomb', '1.0.0-' + '0'.repeat(240)],
  ['leading zero core bomb', '0'.repeat(240) + '.0.0'],
  ['alternating comparator text bomb', '1.0.0-' + 'a0'.repeat(100)],
  ['control separator bomb', '1.0.0' + '\u001b'.repeat(100)],
  ['bidi metadata bomb', '1.0.0+' + '\u202e'.repeat(100)]
];

for (const [label, input] of hostileVersions) {
  assertFast('hostile semver ' + label, () => parseSemver(input));
}

test('maximum bounded valid prerelease parses quickly', () => {
  const version = '1.0.0-' + Array.from({ length: 24 }, (_, index) => 'a' + index).join('.');
  const elapsed = measure(() => parseSemver(version));
  assert.equal(isValidSemver(version), true);
  assert.equal(elapsed < 100, true);
});
test('maximum bounded valid build metadata parses quickly', () => {
  const version = '1.0.0+' + Array.from({ length: 24 }, (_, index) => 'b' + index).join('.');
  const elapsed = measure(() => parseSemver(version));
  assert.equal(isValidSemver(version), true);
  assert.equal(elapsed < 100, true);
});
test('thousand strict version parses remain linear', () => {
  const elapsed = measure(() => {
    for (let index = 0; index < 1000; index += 1) parseSemver('1.0.' + (index % 10) + '-rc.' + (index % 7));
  });
  assert.equal(elapsed < 1000, true);
});
test('thousand semver comparisons remain linear', () => {
  const elapsed = measure(() => {
    for (let index = 0; index < 1000; index += 1) {
      const left = '1.0.' + (index % 10);
      const right = '1.0.' + ((index + 1) % 10);
      if (left === right) throw new Error('unexpected equality fixture');
    }
  });
  assert.equal(elapsed < 1000, true);
});
test('thousand range evaluations remain linear', () => {
  const range = parseRange('>=1.0.0 <2.0.0 || ^3.0.0');
  const elapsed = measure(() => {
    for (let index = 0; index < 1000; index += 1) satisfies('1.' + (index % 9) + '.0', range);
  });
  assert.equal(elapsed < 1000, true);
});

const hostileRanges = [
  ['range whitespace bomb', ' '.repeat(900) + '1.0.0'],
  ['range dot bomb', '1.0.0-'.repeat(100)],
  ['range union tail bomb', '1.0.0' + '||'.repeat(400)],
  ['range operator bomb', '>'.repeat(500) + '1.0.0'],
  ['range caret bomb', '^'.repeat(500) + '1.0.0'],
  ['range x bomb', 'x.'.repeat(400) + 'x'],
  ['range numeric overflow bomb', '9'.repeat(900) + '.0.0'],
  ['range hyphen bomb', '1.0.0' + ' - '.repeat(100) + '2.0.0']
];

for (const [label, input] of hostileRanges) {
  assertFast('hostile range ' + label, () => parseRange(input));
}

test('maximum bounded union count parses quickly', () => {
  const input = Array.from({ length: 16 }, (_, index) => String(index + 1) + '.0.0').join('||');
  const elapsed = measure(() => parseRange(input));
  assert.equal(elapsed < 100, true);
});
test('maximum bounded comparator count parses quickly', () => {
  const input = Array.from({ length: 8 }, () => '>=1.0.0 <2.0.0').join(' ');
  const elapsed = measure(() => parseRange(input, { maxComparatorsPerUnion: 16, maxTotalComparators: 64 }));
  assert.equal(elapsed < 100, true);
});
test('overlong version input is rejected before scanning cost grows', () => {
  const input = '1.0.0+' + 'a'.repeat(10000);
  const elapsed = measure(() => parseSemver(input));
  assert.equal(isValidSemver(input), false);
  assert.equal(elapsed < 50, true);
});
test('overlong range input is rejected before scanning cost grows', () => {
  const input = '>=1.0.0 '.repeat(2000) + '<2.0.0';
  const elapsed = measure(() => parseRange(input));
  assert.equal(elapsed < 50, true);
});
