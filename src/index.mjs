import { DEPENDENCY_FIELDS, LIFECYCLE_SCRIPTS, OVERRIDE_FIELDS, POLLUTION_KEYS, SEMVERCAGE_ERROR_CODES, SEMVERCAGE_FINDING_CODES, SEMVERCAGE_SEVERITY, SEMVERCAGE_VERSION, SEVERITY_RANK } from './constants.mjs';
import { SemverCageError, isSemverCageError, semvercageError } from './errors.mjs';
import { SEMVERCAGE_DEFAULT_POLICY, SEMVERCAGE_POLICY_PRESETS, createPolicy, getPolicy, resolvePolicy } from './policy.mjs';
import { compareSemver, isValidSemver, parseSemver, tryParseSemver } from './semver.mjs';
import { isValidRange, parseRange, satisfies } from './range.mjs';
import { auditSpecifier } from './specifier.mjs';
import { auditPackageJson } from './manifest.mjs';
import { auditLockfile } from './lockfile.mjs';
import { auditUpgrade } from './upgrade.mjs';
import { deepFreeze } from './utils.mjs';

export {
  DEPENDENCY_FIELDS,
  LIFECYCLE_SCRIPTS,
  OVERRIDE_FIELDS,
  POLLUTION_KEYS,
  SEMVERCAGE_ERROR_CODES,
  SEMVERCAGE_FINDING_CODES,
  SEMVERCAGE_SEVERITY,
  SEMVERCAGE_VERSION,
  SEVERITY_RANK,
  SemverCageError,
  isSemverCageError,
  semvercageError,
  SEMVERCAGE_DEFAULT_POLICY,
  SEMVERCAGE_POLICY_PRESETS,
  createPolicy,
  getPolicy,
  resolvePolicy,
  compareSemver,
  isValidSemver,
  parseSemver,
  tryParseSemver,
  isValidRange,
  parseRange,
  satisfies,
  auditSpecifier,
  auditPackageJson,
  auditLockfile,
  auditUpgrade
};

const api = deepFreeze({
  SEMVERCAGE_VERSION,
  SEMVERCAGE_ERROR_CODES,
  SEMVERCAGE_FINDING_CODES,
  SEMVERCAGE_SEVERITY,
  SEVERITY_RANK,
  SEMVERCAGE_DEFAULT_POLICY,
  SEMVERCAGE_POLICY_PRESETS,
  SemverCageError,
  semvercageError,
  isSemverCageError,
  createPolicy,
  getPolicy,
  resolvePolicy,
  parseSemver,
  tryParseSemver,
  isValidSemver,
  compareSemver,
  parseRange,
  isValidRange,
  satisfies,
  auditSpecifier,
  auditPackageJson,
  auditLockfile,
  auditUpgrade
});

export default api;
