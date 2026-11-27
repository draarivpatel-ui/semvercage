import { SEMVERCAGE_ERROR_CODES } from './constants.mjs';
import { SemverCageError } from './errors.mjs';
import { deepFreeze, hasOnlyAsciiDigits, isAsciiAlphanumeric, isAsciiDigit } from './utils.mjs';

const MAX_SAFE_INTEGER_TEXT = '9007199254740991';

function versionError(message, details = {}) {
  return new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_VERSION, message, details);
}

function positiveBound(value, fallback, maximum) {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_INPUT, 'semver parser bound is invalid');
  }
  return value;
}

function checkIntegerOverflow(text, kind) {
  if (text.length > MAX_SAFE_INTEGER_TEXT.length || (text.length === MAX_SAFE_INTEGER_TEXT.length && text > MAX_SAFE_INTEGER_TEXT)) {
    throw versionError('numeric identifier exceeds the safe integer boundary', { kind, identifier: text });
  }
}

function parseNumericIdentifier(text, kind) {
  if (text.length === 0 || !hasOnlyAsciiDigits(text)) {
    throw versionError('numeric identifier is empty or contains non digits', { kind, identifier: text });
  }
  if (text.length > 1 && text[0] === '0') {
    throw versionError('numeric identifier has a leading zero', { kind, identifier: text });
  }
  checkIntegerOverflow(text, kind);
  return Number(text);
}

function validIdentifierCharacter(code) {
  return isAsciiAlphanumeric(code) || code === 45;
}

function validateIdentifierList(text, kind, options, numericRules) {
  if (text.length === 0) {
    throw versionError(kind + ' identifier list is empty');
  }
  const parts = text.split('.');
  if (parts.length > options.maxVersionIdentifiers) {
    throw versionError(kind + ' identifier count exceeds the parser bound', { count: parts.length });
  }
  for (const part of parts) {
    if (part.length === 0) {
      throw versionError(kind + ' identifier is empty', { kind });
    }
    if (part.length > options.maxIdentifierLength) {
      throw versionError(kind + ' identifier exceeds the parser bound', { kind, length: part.length });
    }
    for (let index = 0; index < part.length; index += 1) {
      if (!validIdentifierCharacter(part.charCodeAt(index))) {
        throw versionError(kind + ' identifier contains an invalid character', { kind, character: part[index] });
      }
    }
    if (numericRules && hasOnlyAsciiDigits(part)) {
      if (part.length > 1 && part[0] === '0') {
        throw versionError('numeric prerelease identifier has a leading zero', { identifier: part });
      }
      checkIntegerOverflow(part, kind);
    }
  }
  return parts;
}

export function makeVersion(major, minor, patch, prerelease = [], build = []) {
  const pre = prerelease.slice();
  const meta = build.slice();
  let text = String(major) + '.' + String(minor) + '.' + String(patch);
  if (pre.length > 0) text += '-' + pre.join('.');
  if (meta.length > 0) text += '+' + meta.join('.');
  return deepFreeze({
    version: text,
    major,
    minor,
    patch,
    prerelease: Object.freeze(pre),
    build: Object.freeze(meta),
    isPrerelease: pre.length > 0,
    hasBuild: meta.length > 0
  });
}

export function parseSemver(input, options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_INPUT, 'semver parser options must be an object');
  }
  if (typeof input !== 'string') {
    throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_INPUT, 'version must be a string', { actual: typeof input });
  }
  const maxVersionLength = positiveBound(options.maxVersionLength, 256, 8192);
  const maxIdentifierLength = positiveBound(options.maxIdentifierLength, 64, 1024);
  const maxVersionIdentifiers = positiveBound(options.maxVersionIdentifiers, 32, 512);
  const parserOptions = { maxIdentifierLength, maxVersionIdentifiers };
  if (input.length === 0) throw versionError('version is empty');
  if (input.length > maxVersionLength) {
    throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INPUT_TOO_LONG, 'version exceeds the parser length bound', { length: input.length, bound: maxVersionLength });
  }
  for (let index = 0; index < input.length; index += 1) {
    const code = input.charCodeAt(index);
    if (code < 33 || code > 126) {
      throw versionError('version contains whitespace, control, bidirectional, or non ASCII input', { index, charCode: code });
    }
  }

  let position = 0;
  while (position < input.length) {
    const code = input.charCodeAt(position);
    if (!isAsciiDigit(code) && input[position] !== '.') break;
    position += 1;
  }
  const coreText = input.slice(0, position);
  const coreParts = coreText.split('.');
  if (coreParts.length !== 3) {
    throw versionError('version core must contain exactly major, minor, and patch numeric identifiers');
  }
  const major = parseNumericIdentifier(coreParts[0], 'major');
  const minor = parseNumericIdentifier(coreParts[1], 'minor');
  const patch = parseNumericIdentifier(coreParts[2], 'patch');

  let prerelease = [];
  let build = [];
  if (position < input.length && input[position] === '-') {
    position += 1;
    const start = position;
    while (position < input.length && input[position] !== '+') position += 1;
    prerelease = validateIdentifierList(input.slice(start, position), 'prerelease', parserOptions, true);
  }
  if (position < input.length && input[position] === '+') {
    position += 1;
    build = validateIdentifierList(input.slice(position), 'build', parserOptions, false);
    position = input.length;
  }
  if (position !== input.length) {
    throw versionError('version contains malformed or trailing input', { position });
  }
  return makeVersion(major, minor, patch, prerelease, build);
}

function coerceVersion(value) {
  if (typeof value === 'string') return parseSemver(value);
  if (value && typeof value === 'object' && typeof value.version === 'string') return parseSemver(value.version);
  throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_INPUT, 'version must be a string or parsed semver object');
}

function compareIdentifiers(left, right) {
  const leftNumeric = hasOnlyAsciiDigits(left);
  const rightNumeric = hasOnlyAsciiDigits(right);
  if (leftNumeric && rightNumeric) {
    const a = Number(left);
    const b = Number(right);
    return a < b ? -1 : a > b ? 1 : 0;
  }
  if (leftNumeric) return -1;
  if (rightNumeric) return 1;
  return left < right ? -1 : left > right ? 1 : 0;
}

export function compareSemver(left, right) {
  const a = coerceVersion(left);
  const b = coerceVersion(right);
  for (const key of ['major', 'minor', 'patch']) {
    if (a[key] < b[key]) return -1;
    if (a[key] > b[key]) return 1;
  }
  const aLength = a.prerelease.length;
  const bLength = b.prerelease.length;
  if (aLength === 0 && bLength === 0) return 0;
  if (aLength === 0) return 1;
  if (bLength === 0) return -1;
  const shared = Math.min(aLength, bLength);
  for (let index = 0; index < shared; index += 1) {
    const result = compareIdentifiers(a.prerelease[index], b.prerelease[index]);
    if (result !== 0) return result;
  }
  if (aLength < bLength) return -1;
  if (aLength > bLength) return 1;
  return 0;
}

export function tryParseSemver(input, options = {}) {
  try {
    return parseSemver(input, options);
  } catch (error) {
    if (error instanceof SemverCageError) return null;
    throw error;
  }
}

export function isValidSemver(input, options = {}) {
  return tryParseSemver(input, options) !== null;
}
