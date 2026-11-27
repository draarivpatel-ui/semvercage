import { SEMVERCAGE_ERROR_CODES, SEVERITY_RANK } from './constants.mjs';
import { SemverCageError } from './errors.mjs';
import { deepFreeze } from './utils.mjs';

const DEFAULT_REGISTRIES = Object.freeze(['registry.npmjs.org']);
const DEFAULT_PRIVATE_PREFIXES = Object.freeze([
  'internal-',
  'corp-',
  'private-',
  'company-',
  'local-',
  'infra-'
]);

export const SEMVERCAGE_POLICY_PRESETS = deepFreeze({
  strict: {
    name: 'strict',
    failOn: 'low',
    maxInputLength: 4096,
    maxRangeLength: 768,
    maxUnions: 8,
    maxComparatorsPerUnion: 12,
    maxTotalComparators: 48,
    maxObjectDepth: 12,
    maxObjectKeys: 2000,
    maxIdentifierLength: 48,
    maxVersionLength: 192,
    maxVersionIdentifiers: 24,
    trustedRegistries: DEFAULT_REGISTRIES,
    privateNamePrefixes: DEFAULT_PRIVATE_PREFIXES,
    allowPrerelease: false,
    requireHttps: true,
    requireIntegrity: true,
    maxMajorJump: 0
  },
  balanced: {
    name: 'balanced',
    failOn: 'medium',
    maxInputLength: 8192,
    maxRangeLength: 1024,
    maxUnions: 16,
    maxComparatorsPerUnion: 16,
    maxTotalComparators: 64,
    maxObjectDepth: 16,
    maxObjectKeys: 5000,
    maxIdentifierLength: 64,
    maxVersionLength: 256,
    maxVersionIdentifiers: 32,
    trustedRegistries: DEFAULT_REGISTRIES,
    privateNamePrefixes: DEFAULT_PRIVATE_PREFIXES,
    allowPrerelease: false,
    requireHttps: true,
    requireIntegrity: true,
    maxMajorJump: 1
  },
  ci: {
    name: 'ci',
    failOn: 'high',
    maxInputLength: 8192,
    maxRangeLength: 1024,
    maxUnions: 12,
    maxComparatorsPerUnion: 16,
    maxTotalComparators: 64,
    maxObjectDepth: 16,
    maxObjectKeys: 8000,
    maxIdentifierLength: 64,
    maxVersionLength: 256,
    maxVersionIdentifiers: 32,
    trustedRegistries: DEFAULT_REGISTRIES,
    privateNamePrefixes: DEFAULT_PRIVATE_PREFIXES,
    allowPrerelease: false,
    requireHttps: true,
    requireIntegrity: true,
    maxMajorJump: 1
  }
});

export const SEMVERCAGE_DEFAULT_POLICY = SEMVERCAGE_POLICY_PRESETS.balanced;

const NUMERIC_KEYS = Object.freeze([
  'maxInputLength',
  'maxRangeLength',
  'maxUnions',
  'maxComparatorsPerUnion',
  'maxTotalComparators',
  'maxObjectDepth',
  'maxObjectKeys',
  'maxIdentifierLength',
  'maxVersionLength',
  'maxVersionIdentifiers',
  'maxMajorJump'
]);

const BOOLEAN_KEYS = Object.freeze([
  'allowPrerelease',
  'requireHttps',
  'requireIntegrity'
]);

function validHostName(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 253) return false;
  if (value !== value.toLowerCase()) return false;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    const digit = code >= 48 && code <= 57;
    const letter = code >= 97 && code <= 122;
    if (!digit && !letter && value[index] !== '.' && value[index] !== '-') return false;
  }
  return true;
}

function validatePositiveInteger(policy, key) {
  const value = policy[key];
  if (!Number.isSafeInteger(value) || value < 0 || value > 1000000) {
    throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_POLICY, 'policy numeric bound is invalid', { key });
  }
}

export function createPolicy(base = 'balanced', overrides = {}) {
  let baseName = base;
  let overrideSource = overrides;
  if (base && typeof base === 'object') {
    overrideSource = base;
    baseName = typeof base.name === 'string' && SEMVERCAGE_POLICY_PRESETS[base.name] ? base.name : 'balanced';
  }
  if (typeof baseName !== 'string' || !SEMVERCAGE_POLICY_PRESETS[baseName]) {
    throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_POLICY, 'unknown semvercage policy', { policy: String(baseName) });
  }
  if (!overrideSource || typeof overrideSource !== 'object' || Array.isArray(overrideSource)) {
    throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_POLICY, 'policy overrides must be an object');
  }
  const merged = { ...SEMVERCAGE_POLICY_PRESETS[baseName], name: baseName };
  for (const key of NUMERIC_KEYS) {
    if (overrideSource[key] !== undefined) merged[key] = overrideSource[key];
  }
  for (const key of BOOLEAN_KEYS) {
    if (overrideSource[key] !== undefined) merged[key] = overrideSource[key];
  }
  if (overrideSource.failOn !== undefined) merged.failOn = overrideSource.failOn;
  if (overrideSource.trustedRegistries !== undefined) merged.trustedRegistries = overrideSource.trustedRegistries;
  if (overrideSource.privateNamePrefixes !== undefined) merged.privateNamePrefixes = overrideSource.privateNamePrefixes;

  for (const key of NUMERIC_KEYS) validatePositiveInteger(merged, key);
  for (const key of BOOLEAN_KEYS) {
    if (typeof merged[key] !== 'boolean') {
      throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_POLICY, 'policy boolean bound is invalid', { key });
    }
  }
  if (SEVERITY_RANK[merged.failOn] === undefined || merged.failOn === 'info') {
    throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_POLICY, 'policy failOn severity is invalid', { failOn: String(merged.failOn) });
  }
  if (!Array.isArray(merged.trustedRegistries) || merged.trustedRegistries.length === 0 || merged.trustedRegistries.length > 32) {
    throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_POLICY, 'trusted registry list is invalid');
  }
  const registries = [];
  for (const host of merged.trustedRegistries) {
    if (!validHostName(host)) {
      throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_POLICY, 'trusted registry host is invalid', { host: String(host) });
    }
    if (!registries.includes(host)) registries.push(host);
  }
  if (!Array.isArray(merged.privateNamePrefixes) || merged.privateNamePrefixes.length > 64) {
    throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_POLICY, 'private package prefix list is invalid');
  }
  const prefixes = [];
  for (const prefix of merged.privateNamePrefixes) {
    if (typeof prefix !== 'string' || prefix.length === 0 || prefix.length > 64 || prefix !== prefix.toLowerCase()) {
      throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_POLICY, 'private package prefix is invalid');
    }
    if (!prefixes.includes(prefix)) prefixes.push(prefix);
  }
  merged.trustedRegistries = Object.freeze(registries);
  merged.privateNamePrefixes = Object.freeze(prefixes);
  if (merged.maxComparatorsPerUnion > merged.maxTotalComparators) {
    throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_POLICY, 'comparator bounds are inconsistent');
  }
  return deepFreeze(merged);
}

export function getPolicy(name = 'balanced') {
  return createPolicy(name);
}

export function resolvePolicy(options = {}) {
  if (typeof options === 'string') return createPolicy(options);
  if (!options || typeof options !== 'object') return createPolicy('balanced');
  const policyName = typeof options.policy === 'string' ? options.policy : 'balanced';
  return createPolicy(policyName, options);
}
