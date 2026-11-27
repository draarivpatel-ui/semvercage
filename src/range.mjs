import { SEMVERCAGE_ERROR_CODES } from './constants.mjs';
import { SemverCageError } from './errors.mjs';
import { resolvePolicy } from './policy.mjs';
import { compareSemver, makeVersion, parseSemver, tryParseSemver } from './semver.mjs';
import { deepFreeze, hasOnlyAsciiDigits } from './utils.mjs';

function rangeError(message, details = {}) {
  return new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_RANGE, message, details);
}

function complexityError(message, details = {}) {
  return new SemverCageError(SEMVERCAGE_ERROR_CODES.RANGE_TOO_COMPLEX, message, details);
}

function isWildcardPart(part) {
  return part === 'x' || part === 'X' || part === '*';
}

function validNumericPart(part) {
  if (part.length === 0 || !hasOnlyAsciiDigits(part)) return false;
  if (part.length > 1 && part[0] === '0') return false;
  const maximum = '9007199254740991';
  return part.length < maximum.length || (part.length === maximum.length && part <= maximum);
}

function makeComparator(operator, version, source) {
  return deepFreeze({ operator, version, source });
}

function increment(value) {
  if (!Number.isSafeInteger(value) || value >= Number.MAX_SAFE_INTEGER) return null;
  return value + 1;
}

function lowerBoundary(partial) {
  return makeVersion(
    partial.major || 0,
    partial.minor || 0,
    partial.patch || 0,
    partial.precision === 3 ? partial.prerelease : [],
    []
  );
}

function partialUpperBoundary(partial) {
  if (partial.precision === 0) return null;
  if (partial.precision === 1) {
    const major = increment(partial.major || 0);
    return major === null ? null : makeVersion(major, 0, 0);
  }
  if (partial.precision === 2) {
    const minor = increment(partial.minor || 0);
    return minor === null ? null : makeVersion(partial.major || 0, minor, 0);
  }
  return null;
}

export function parsePartialVersion(input, options = {}) {
  if (typeof input !== 'string' || input.length === 0) {
    throw rangeError('range comparator is empty');
  }
  const parsed = tryParseSemver(input, options);
  if (parsed) {
    return deepFreeze({
      precision: 3,
      major: parsed.major,
      minor: parsed.minor,
      patch: parsed.patch,
      prerelease: parsed.prerelease,
      source: input
    });
  }
  const parts = input.split('.');
  if (parts.length > 3) throw rangeError('partial version has too many numeric identifiers', { comparator: input });
  let concrete = parts.length;
  while (concrete > 0 && isWildcardPart(parts[concrete - 1])) concrete -= 1;
  if (concrete === 0) {
    return deepFreeze({ precision: 0, major: null, minor: null, patch: null, prerelease: Object.freeze([]), source: input });
  }
  for (let index = 0; index < concrete; index += 1) {
    if (isWildcardPart(parts[index])) throw rangeError('wildcard cannot precede a numeric identifier', { comparator: input });
    if (!validNumericPart(parts[index])) throw rangeError('partial version numeric identifier is invalid', { comparator: input });
  }
  for (let index = concrete; index < parts.length; index += 1) {
    if (!isWildcardPart(parts[index])) throw rangeError('partial version contains malformed wildcard placement', { comparator: input });
  }
  if (concrete === 3 && parts.length === 3) throw rangeError('complete version is not valid strict semver', { comparator: input });
  const values = parts.slice(0, concrete).map((part) => Number(part));
  return deepFreeze({
    precision: concrete,
    major: values[0],
    minor: concrete > 1 ? values[1] : null,
    patch: concrete > 2 ? values[2] : null,
    prerelease: Object.freeze([]),
    source: input
  });
}

function anyComparator(source) {
  return [makeComparator('any', null, source)];
}

function noneComparator(source) {
  return [makeComparator('none', null, source)];
}

function expandBasic(operator, partial, source) {
  if (partial.precision === 0) {
    if (operator === '' || operator === '=') return anyComparator(source);
    throw rangeError('comparison operators cannot be applied to a wildcard', { comparator: source });
  }
  if (operator === '' || operator === '=') {
    if (partial.precision === 3) return [makeComparator('eq', lowerBoundary(partial), source)];
    const lower = lowerBoundary(partial);
    const upper = partialUpperBoundary(partial);
    const output = [makeComparator('gte', lower, source)];
    if (upper) output.push(makeComparator('lt', upper, source));
    return output;
  }
  if (partial.precision === 3) {
    const version = lowerBoundary(partial);
    const operatorMap = { '>': 'gt', '>=': 'gte', '<': 'lt', '<=': 'lte' };
    const mapped = operatorMap[operator];
    if (!mapped) throw rangeError('unsupported comparator operator', { comparator: source });
    if ((mapped === 'lt' || mapped === 'lte') && version.major === 0 && version.minor === 0 && version.patch === 0 && version.prerelease.length === 0 && mapped === 'lt') {
      return noneComparator(source);
    }
    return [makeComparator(mapped, version, source)];
  }
  const lower = lowerBoundary(partial);
  const upper = partialUpperBoundary(partial);
  if (operator === '>=') return [makeComparator('gte', lower, source)];
  if (operator === '>') {
    if (!upper) return noneComparator(source);
    return [makeComparator('gte', upper, source)];
  }
  if (operator === '<') {
    if (lower.major === 0 && lower.minor === 0 && lower.patch === 0) return noneComparator(source);
    return [makeComparator('lt', lower, source)];
  }
  if (operator === '<=') {
    if (!upper) return anyComparator(source);
    return [makeComparator('lt', upper, source)];
  }
  throw rangeError('unsupported comparator operator', { comparator: source });
}

function expandCaret(partial, source) {
  if (partial.precision === 0) return anyComparator(source);
  const lower = lowerBoundary(partial);
  let upper = null;
  if (partial.precision === 1) {
    const major = partial.major === 0 ? 1 : increment(partial.major);
    upper = major === null ? null : makeVersion(major, 0, 0);
  } else if (partial.precision === 2) {
    if (partial.major > 0) {
      const major = increment(partial.major);
      upper = major === null ? null : makeVersion(major, 0, 0);
    } else {
      const minor = increment(partial.minor || 0);
      upper = minor === null ? null : makeVersion(0, minor, 0);
    }
  } else if (partial.major > 0) {
    const major = increment(partial.major);
    upper = major === null ? null : makeVersion(major, 0, 0);
  } else if (partial.minor > 0) {
    const minor = increment(partial.minor);
    upper = minor === null ? null : makeVersion(0, minor, 0);
  } else {
    const patch = increment(partial.patch);
    upper = patch === null ? null : makeVersion(0, 0, patch);
  }
  const output = [makeComparator('gte', lower, source)];
  if (upper) output.push(makeComparator('lt', upper, source));
  return output;
}

function expandTilde(partial, source) {
  if (partial.precision === 0) return anyComparator(source);
  const lower = lowerBoundary(partial);
  let upper = null;
  if (partial.precision === 1) {
    const major = increment(partial.major || 0);
    upper = major === null ? null : makeVersion(major, 0, 0);
  } else {
    const minor = increment(partial.minor || 0);
    upper = minor === null ? null : makeVersion(partial.major || 0, minor, 0);
  }
  const output = [makeComparator('gte', lower, source)];
  if (upper) output.push(makeComparator('lt', upper, source));
  return output;
}

function expandHyphen(startText, endText, options) {
  const start = parsePartialVersion(startText, options);
  const end = parsePartialVersion(endText, options);
  const output = [];
  if (start.precision !== 0) output.push(makeComparator('gte', lowerBoundary(start), startText));
  if (end.precision === 0) return output.length === 0 ? anyComparator(startText + ' - ' + endText) : output;
  if (end.precision === 3) {
    output.push(makeComparator('lte', lowerBoundary(end), endText));
    return output;
  }
  const upper = partialUpperBoundary(end);
  if (upper) output.push(makeComparator('lt', upper, endText));
  return output;
}

function expandComparatorToken(token, options) {
  if (token.length === 0) throw rangeError('empty comparator');
  let operator = '';
  let body = token;
  for (const candidate of ['>=', '<=', '>', '<', '=']) {
    if (token.startsWith(candidate)) {
      operator = candidate;
      body = token.slice(candidate.length);
      break;
    }
  }
  if (body.length === 0) throw rangeError('comparator operator has no version', { comparator: token });
  if (body[0] === '^' || body[0] === '~') {
    if (operator !== '') throw rangeError('caret or tilde cannot be combined with another operator', { comparator: token });
    const partial = parsePartialVersion(body.slice(1), options);
    return body[0] === '^' ? expandCaret(partial, token) : expandTilde(partial, token);
  }
  const partial = parsePartialVersion(body, options);
  return expandBasic(operator, partial, token);
}

function trimAsciiSpaces(text) {
  let start = 0;
  let end = text.length;
  while (start < end && text[start] === ' ') start += 1;
  while (end > start && text[end - 1] === ' ') end -= 1;
  return text.slice(start, end);
}

function splitUnionTokens(text) {
  if (text.length === 0) throw rangeError('empty range union');
  if (text[0] === ' ' || text[text.length - 1] === ' ') throw rangeError('leading or trailing whitespace creates an empty comparator');
  if (text.includes('  ')) throw rangeError('repeated whitespace creates an empty comparator');
  return text.split(' ');
}

function countHyphenDelimiters(text) {
  let count = 0;
  let position = 0;
  while (position <= text.length - 3) {
    const found = text.indexOf(' - ', position);
    if (found === -1) break;
    count += 1;
    position = found + 3;
  }
  return count;
}

function validateRangeCharacters(input) {
  for (let index = 0; index < input.length; index += 1) {
    const code = input.charCodeAt(index);
    if (code !== 32 && (code < 33 || code > 126)) {
      throw rangeError('range contains control, bidirectional, or non ASCII input', { index, charCode: code });
    }
  }
}

export function parseRange(input, options = {}) {
  const policy = resolvePolicy(options);
  if (typeof input !== 'string') {
    throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_INPUT, 'range must be a string', { actual: typeof input });
  }
  if (input.length === 0) throw rangeError('range is empty');
  if (input.length > policy.maxRangeLength) {
    throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INPUT_TOO_LONG, 'range exceeds the parser length bound', { length: input.length, bound: policy.maxRangeLength });
  }
  validateRangeCharacters(input);
  if (input[0] === ' ' || input[input.length - 1] === ' ') {
    throw rangeError('leading or trailing whitespace creates an empty comparator');
  }
  if (input.includes('  ')) throw rangeError('repeated whitespace creates an empty comparator');
  const unionTexts = input.split('||');
  if (unionTexts.length > policy.maxUnions) {
    throw complexityError('range union count exceeds the parser bound', { count: unionTexts.length, bound: policy.maxUnions });
  }
  const unions = [];
  let totalComparators = 0;
  for (const rawUnionText of unionTexts) {
    const unionText = trimAsciiSpaces(rawUnionText);
    if (unionText.length === 0) throw rangeError('empty comparator union');
    let comparators = [];
    const hyphenCount = countHyphenDelimiters(unionText);
    if (hyphenCount > 1) throw rangeError('range contains multiple hyphen delimiters');
    if (hyphenCount === 1) {
      const parts = unionText.split(' - ');
      if (parts.length !== 2 || parts[0].length === 0 || parts[1].length === 0) throw rangeError('hyphen range has an empty boundary');
      comparators = expandHyphen(parts[0], parts[1], policy);
    } else {
      for (const token of splitUnionTokens(unionText)) {
        comparators.push(...expandComparatorToken(token, policy));
      }
    }
    if (comparators.length > policy.maxComparatorsPerUnion) {
      throw complexityError('range comparator count exceeds the per union bound', { count: comparators.length, bound: policy.maxComparatorsPerUnion });
    }
    totalComparators += comparators.length;
    if (totalComparators > policy.maxTotalComparators) {
      throw complexityError('range comparator count exceeds the total bound', { count: totalComparators, bound: policy.maxTotalComparators });
    }
    unions.push(deepFreeze({ source: unionText, comparators: Object.freeze(comparators) }));
  }
  return deepFreeze({
    kind: 'SEMVERCAGE_RANGE',
    input,
    unions: Object.freeze(unions),
    unionCount: unions.length,
    comparatorCount: totalComparators
  });
}

function compareForOperator(operator, version, comparatorVersion) {
  const result = compareSemver(version, comparatorVersion);
  if (operator === 'eq') return result === 0;
  if (operator === 'gt') return result > 0;
  if (operator === 'gte') return result >= 0;
  if (operator === 'lt') return result < 0;
  if (operator === 'lte') return result <= 0;
  return false;
}

function comparatorAllowsPrerelease(comparator, version) {
  if (!comparator.version || comparator.version.prerelease.length === 0) return false;
  return comparator.version.major === version.major && comparator.version.minor === version.minor && comparator.version.patch === version.patch;
}

function validParsedRange(range) {
  return Boolean(range && typeof range === 'object' && range.kind === 'SEMVERCAGE_RANGE' && Array.isArray(range.unions));
}

export function satisfies(versionInput, rangeInput, options = {}) {
  const policy = resolvePolicy(options);
  const version = typeof versionInput === 'string' ? parseSemver(versionInput, policy) : parseSemver(versionInput && versionInput.version, policy);
  const range = typeof rangeInput === 'string' ? parseRange(rangeInput, policy) : rangeInput;
  if (!validParsedRange(range)) {
    throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_INPUT, 'range must be a range string or parsed range object');
  }
  const includePrerelease = options.includePrerelease === true;
  for (const union of range.unions) {
    let unionMatches = true;
    for (const comparator of union.comparators) {
      if (comparator.operator === 'none') {
        unionMatches = false;
        break;
      }
      if (comparator.operator === 'any') continue;
      if (!compareForOperator(comparator.operator, version, comparator.version)) {
        unionMatches = false;
        break;
      }
    }
    if (!unionMatches) continue;
    if (includePrerelease || version.prerelease.length === 0) return true;
    if (union.comparators.some((comparator) => comparatorAllowsPrerelease(comparator, version))) return true;
  }
  return false;
}

export function isValidRange(input, options = {}) {
  try {
    parseRange(input, options);
    return true;
  } catch (error) {
    if (error instanceof SemverCageError) return false;
    throw error;
  }
}
