import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { SemverCageError, compareSemver, isValidSemver, parseSemver } from '../src/index.mjs';

const component = fc.integer({ min: 0, max: 999 });
const versionTuple = fc.tuple(component, component, component);
const hostileCharacter = fc.constantFrom('/', '_', '@', '#', '?', '=', '\0', '\n', 'é', '\u202e');
const fuzzOptions = { seed: 20261127, numRuns: 110 };

function versionOf([major, minor, patch]) {
  return major + '.' + minor + '.' + patch;
}

test('fast-check valid strict versions parse exactly and compare numerically', () => {
  fc.assert(fc.property(versionTuple, versionTuple, (leftTuple, rightTuple) => {
    const leftVersion = versionOf(leftTuple);
    const rightVersion = versionOf(rightTuple);
    const left = parseSemver(leftVersion);
    const right = parseSemver(rightVersion);
    assert.equal(isValidSemver(leftVersion), true);
    assert.equal(isValidSemver(rightVersion), true);
    assert.equal(left.major, leftTuple[0]);
    assert.equal(left.minor, leftTuple[1]);
    assert.equal(left.patch, leftTuple[2]);
    const expected = Math.sign(
      (leftTuple[0] - rightTuple[0]) ||
      (leftTuple[1] - rightTuple[1]) ||
      (leftTuple[2] - rightTuple[2])
    );
    assert.equal(compareSemver(left, right), expected);
  }), fuzzOptions);
});

test('fast-check forbidden character insertion is always rejected', () => {
  fc.assert(fc.property(versionTuple, hostileCharacter, fc.integer({ min: 0, max: 8 }), (tuple, character, index) => {
    const version = versionOf(tuple);
    const at = index % (version.length + 1);
    const hostile = version.slice(0, at) + character + version.slice(at);
    assert.equal(isValidSemver(hostile), false, 'hostile version was accepted: ' + JSON.stringify(hostile));
    assert.throws(() => parseSemver(hostile), SemverCageError);
  }), fuzzOptions);
});

test('fast-check leading zero numeric components are always rejected', () => {
  fc.assert(fc.property(component, fc.integer({ min: 0, max: 2 }), (value, position) => {
    const parts = ['1', '2', '3'];
    parts[position] = '0' + String(value);
    const hostile = parts.join('.');
    assert.equal(isValidSemver(hostile), false);
    assert.throws(() => parseSemver(hostile), SemverCageError);
  }), fuzzOptions);
});
