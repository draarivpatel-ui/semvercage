import { SEMVERCAGE_ERROR_CODES, SEMVERCAGE_FINDING_CODES } from './constants.mjs';
import { SemverCageError } from './errors.mjs';
import { resolvePolicy } from './policy.mjs';
import { parseRange } from './range.mjs';
import { buildReport, hasControlOrNonAscii, hasCredentialAuthority, makeFinding, redactCredentialAuthority } from './utils.mjs';

const REMOTE_GIT_PREFIXES = Object.freeze(['git+http://', 'git+https://', 'git+ssh://', 'git://', 'ssh://']);
const HOSTING_PREFIXES = Object.freeze(['github:', 'bitbucket:', 'gitlab:', 'gist:']);
const LOCAL_PREFIXES = Object.freeze(['file:', 'link:', 'portal:']);
const UNSTABLE_TAGS = Object.freeze(['alpha', 'canary', 'next', 'dev', 'snapshot', 'nightly']);
const PRERELEASE_TAGS = Object.freeze(['alpha', 'canary', 'beta', 'rc', 'next', 'dev', 'snapshot', 'nightly', 'pre']);

function packageNameForReport(packageName) {
  if (typeof packageName !== 'string') return packageName;
  if (packageName.includes(':') || hasControlOrNonAscii(packageName)) return '<invalid>';
  return packageName;
}

function findingContext(path, packageName, specifier, dependencyType) {
  return { path, packageName: packageNameForReport(packageName), specifier: typeof specifier === 'string' ? redactCredentialAuthority(specifier) : specifier, dependencyType };
}

function validNameCharacter(code) {
  return (code >= 97 && code <= 122) || (code >= 48 && code <= 57) || code === 45 || code === 46 || code === 95;
}

function inspectNamePart(part) {
  let uppercase = false;
  let invalid = false;
  let nonAscii = false;
  let control = false;
  for (let index = 0; index < part.length; index += 1) {
    const code = part.charCodeAt(index);
    if (code >= 65 && code <= 90) uppercase = true;
    else if (code > 126) nonAscii = true;
    else if (code < 32) control = true;
    else if (!validNameCharacter(code)) invalid = true;
  }
  return { uppercase, invalid, nonAscii, control };
}

function countSeparatorKinds(text) {
  const kinds = new Set();
  if (text.includes('-')) kinds.add('hyphen');
  if (text.includes('_')) kinds.add('underscore');
  if (text.includes('.')) kinds.add('dot');
  return kinds.size;
}

function hasRepeatedOrEdgeSeparator(text) {
  if (text.length === 0) return false;
  const separators = '-_.';
  if (separators.includes(text[0]) || separators.includes(text[text.length - 1])) return true;
  for (let index = 1; index < text.length; index += 1) {
    if (separators.includes(text[index]) && separators.includes(text[index - 1])) return true;
  }
  return false;
}

export function collectPackageNameFindings(packageName, path, policy, dependencyType = undefined) {
  const findings = [];
  const context = { path, packageName: packageNameForReport(packageName), dependencyType };
  if (typeof packageName !== 'string' || packageName.length === 0) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_INVALID_PACKAGE_NAME,
      'high',
      'dependency package name is empty or not a string',
      'use a valid lowercase npm package name',
      { ...context, actual: typeof packageName }
    ));
    return findings;
  }
  if (packageName.length > 214) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_INVALID_PACKAGE_NAME,
      'high',
      'dependency package name exceeds the npm length limit',
      'use a package name of at most 214 characters',
      { ...context, length: packageName.length }
    ));
  }
  if (hasControlOrNonAscii(packageName)) {
    const nonAsciiOnly = !/[\x00-\x20]/.test(packageName);
    findings.push(makeFinding(
      nonAsciiOnly ? SEMVERCAGE_FINDING_CODES.SPEC_HOMOGLYPH_NAME : SEMVERCAGE_FINDING_CODES.SPEC_CONTROL_CHARACTERS,
      nonAsciiOnly ? 'high' : 'critical',
      nonAsciiOnly ? 'dependency package name contains non ASCII or homoglyph characters' : 'dependency package name contains control characters',
      'use the canonical ASCII npm package name',
      context
    ));
  }
  const scoped = packageName.startsWith('@');
  const slashCount = packageName.split('/').length - 1;
  let parts;
  if (scoped) {
    if (slashCount !== 1 || packageName.length === 1) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.SPEC_INVALID_PACKAGE_NAME,
        'high',
        'scoped package name must contain exactly one scope and one name segment',
        'use the form @scope/name with lowercase URL-safe characters',
        context
      ));
      parts = [];
    } else {
      const withoutAt = packageName.slice(1);
      parts = withoutAt.split('/');
    }
  } else {
    if (slashCount !== 0) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.SPEC_INVALID_PACKAGE_NAME,
        'high',
        'unscoped package name cannot contain a slash',
        'use a valid unscoped npm package name or a correctly scoped name',
        context
      ));
    }
    parts = [packageName];
  }
  let hasUppercase = false;
  let hasInvalidCharacter = false;
  for (const part of parts) {
    if (!part || part.length === 0) {
      hasInvalidCharacter = true;
      continue;
    }
    const inspection = inspectNamePart(part);
    hasUppercase = hasUppercase || inspection.uppercase;
    hasInvalidCharacter = hasInvalidCharacter || inspection.invalid || inspection.control || inspection.nonAscii;
  }
  const segmentStartsInvalid = parts.some((part) => part && (part[0] === '.' || part[0] === '_'));
  if (hasUppercase || hasInvalidCharacter || segmentStartsInvalid) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_INVALID_PACKAGE_NAME,
      'high',
      'dependency package name violates npm naming rules',
      'use lowercase letters, digits, hyphens, dots, and underscores without a leading dot or underscore',
      context
    ));
  }
  if (hasUppercase) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_SEPARATOR_CONFUSION,
      'medium',
      'dependency package name uses case that can be confused with the canonical lowercase name',
      'pin the exact lowercase npm package name',
      context
    ));
  }
  const unscopedName = scoped && parts.length === 2 ? parts[1] : parts[0] || packageName;
  if (!scoped) {
    for (const prefix of policy.privateNamePrefixes) {
      if (packageName.toLowerCase().startsWith(prefix)) {
        findings.push(makeFinding(
          SEMVERCAGE_FINDING_CODES.SPEC_PRIVATE_NAME_CONFUSION,
          'medium',
          'unscoped dependency name looks private and is exposed to dependency confusion',
          'scope private packages or configure an internal registry with explicit pinning',
          context
        ));
        break;
      }
    }
  }
  if (countSeparatorKinds(unscopedName) > 1 || hasRepeatedOrEdgeSeparator(unscopedName)) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_SEPARATOR_CONFUSION,
      'low',
      'dependency package name has separator patterns often used in typosquatting confusion',
      'verify the exact package spelling and separator placement against the intended registry package',
      context
    ));
  }
  return findings;
}

function unionRisk(union) {
  let lower = false;
  let upper = false;
  let exact = false;
  let any = false;
  for (const comparator of union.comparators) {
    if (comparator.operator === 'any') any = true;
    if (comparator.operator === 'eq') exact = true;
    if (comparator.operator === 'gt' || comparator.operator === 'gte') lower = true;
    if (comparator.operator === 'lt' || comparator.operator === 'lte') upper = true;
  }
  return { any, broad: lower && !upper && !exact };
}

function prereleaseIdentifiers(range) {
  const output = [];
  for (const union of range.unions) {
    for (const comparator of union.comparators) {
      if (comparator.version && comparator.version.prerelease.length > 0) output.push(comparator.version.prerelease.join('.'));
    }
  }
  return output;
}

function splitNpmAliasTarget(text) {
  if (text.length === 0) return { name: '', specifier: '' };
  let at = -1;
  if (text[0] === '@') {
    const slash = text.indexOf('/');
    if (slash !== -1) at = text.indexOf('@', slash + 1);
  } else {
    at = text.lastIndexOf('@');
  }
  if (at <= 0) return { name: text, specifier: '' };
  return { name: text.slice(0, at), specifier: text.slice(at + 1) };
}

function rawPrereleaseDrift(specifier) {
  const lower = specifier.toLowerCase();
  if (lower.includes('0.0.0-')) return true;
  for (const tag of PRERELEASE_TAGS) {
    if (lower.includes('-' + tag)) return true;
  }
  return false;
}

export function collectSpecifierFindings(packageName, specifier, path, dependencyType, policy, depth = 0) {
  const findings = [];
  const context = findingContext(path, packageName, specifier, dependencyType);
  findings.push(...collectPackageNameFindings(packageName, path + '.packageName', policy, dependencyType));
  if (typeof specifier !== 'string' || specifier.length === 0) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_INVALID_RANGE,
      'high',
      'dependency specifier is empty or not a string',
      'pin a strict semver version or bounded range',
      { ...context, actual: typeof specifier }
    ));
    return findings;
  }
  if (specifier.length > policy.maxInputLength) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_INVALID_RANGE,
      'high',
      'dependency specifier exceeds the input length bound',
      'use a bounded registry semver specifier',
      { ...context, length: specifier.length, bound: policy.maxInputLength }
    ));
    return findings;
  }
  if (hasControlOrNonAscii(specifier, true)) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_CONTROL_CHARACTERS,
      'critical',
      'dependency specifier contains control, bidirectional, or non ASCII characters',
      'remove hidden characters and use a plain ASCII semver specifier',
      context
    ));
  }
  if (hasCredentialAuthority(specifier)) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_CREDENTIALS,
      'critical',
      'dependency specifier embeds credentials in a URL',
      'remove credentials and use registry authentication configuration instead',
      context
    ));
  }
  const lower = specifier.toLowerCase();
  if (REMOTE_GIT_PREFIXES.some((prefix) => lower.startsWith(prefix))) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_GIT_TRANSPORT,
      'critical',
      'dependency specifier installs directly from a git transport',
      'publish a pinned immutable release to the registry and depend on that version',
      context
    ));
    return findings;
  }
  const bareHostingShorthand = !lower.includes('://') && !lower.startsWith('@') && lower.indexOf(':') === -1 && lower.includes('/');
  if (HOSTING_PREFIXES.some((prefix) => lower.startsWith(prefix)) || lower.startsWith('git@') || bareHostingShorthand) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_HOSTING_SHORTHAND,
      'critical',
      'dependency specifier uses hosting shorthand that resolves outside the registry',
      'replace hosting shorthand with a pinned registry release',
      context
    ));
    return findings;
  }
  if (lower.startsWith('http://') || lower.startsWith('https://')) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_REMOTE_TARBALL,
      lower.startsWith('http://') ? 'critical' : 'high',
      'dependency specifier downloads a remote tarball outside normal registry resolution',
      'use a pinned registry version with lockfile integrity instead',
      context
    ));
    return findings;
  }
  if (LOCAL_PREFIXES.some((prefix) => lower.startsWith(prefix))) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_LOCAL_PATH,
      'high',
      'dependency specifier uses a local filesystem link that is not reproducible for consumers',
      'publish the dependency or vendor it through a controlled workspace release process',
      context
    ));
    return findings;
  }
  if (lower.startsWith('workspace:')) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_WORKSPACE_PROTOCOL,
      'high',
      'dependency specifier uses workspace protocol that npm consumers cannot resolve as published',
      'replace workspace protocol with a pinned registry range before publishing',
      context
    ));
    return findings;
  }
  if (lower.startsWith('npm:')) {
    const alias = splitNpmAliasTarget(specifier.slice(4));
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_NPM_ALIAS,
      'high',
      'dependency specifier uses npm alias indirection that can hide the real package being installed',
      'depend on the intended package name directly unless the alias is explicitly reviewed',
      { ...context, aliasTarget: packageNameForReport(alias.name) }
    ));
    if (alias.name && packageName.toLowerCase() !== alias.name.toLowerCase()) {
      findings.push(...collectPackageNameFindings(alias.name, path + '.npmAliasTarget', policy, dependencyType));
    }
    if (depth < 2 && alias.specifier) {
      findings.push(...collectSpecifierFindings(alias.name || packageName, alias.specifier, path + '.npmAliasSpecifier', dependencyType, policy, depth + 1));
    } else if (!alias.specifier) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.SPEC_UNPINNED_DIST_TAG,
        'high',
        'npm alias does not pin a target version',
        'pin the alias target to an exact reviewed version',
        context
      ));
    }
    return findings;
  }
  if (lower === '*' || lower === 'x') {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_UNPINNED_WILDCARD,
      'critical',
      'dependency specifier is an unpinned wildcard',
      'pin an exact version or a bounded semver range',
      context
    ));
    return findings;
  }
  if (lower === 'latest' || lower === 'next') {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_UNPINNED_DIST_TAG,
      'high',
      'dependency specifier uses a mutable distribution tag',
      'pin an immutable semver version instead of a moving tag',
      { ...context, tag: lower }
    ));
    return findings;
  }

  let range;
  try {
    range = parseRange(specifier, policy);
  } catch (error) {
    if (!(error instanceof SemverCageError)) throw error;
    if (rawPrereleaseDrift(specifier)) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.SPEC_PRERELEASE_DRIFT,
        'high',
        'dependency specifier drifts into prerelease or zero-version artifacts',
        'pin a stable reviewed release instead of a prerelease channel',
        context
      ));
    }
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_INVALID_RANGE,
      'high',
      'dependency specifier is not a valid bounded semver range',
      'correct the specifier or pin an exact strict semver release',
      { ...context, errorCode: error.code }
    ));
    return findings;
  }

  if (specifier.includes('+')) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_BUILD_METADATA,
      'high',
      'dependency specifier contains build metadata that semver range matching ignores during artifact selection',
      'pin the canonical registry version without build metadata and verify the artifact through lockfile integrity',
      context
    ));
  }
  for (const union of range.unions) {
    const risk = unionRisk(union);
    if (risk.any) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.SPEC_UNPINNED_WILDCARD,
        'critical',
        'dependency range contains an unrestricted wildcard union',
        'pin an exact version or bounded range',
        context
      ));
    } else if (risk.broad) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.SPEC_BROAD_UNBOUNDED_RANGE,
        'high',
        'dependency range has a lower bound but no upper bound',
        'add an upper bound or pin an exact version to prevent unreviewed major upgrades',
        context
      ));
    }
  }
  for (const prerelease of prereleaseIdentifiers(range)) {
    const lowerPrerelease = prerelease.toLowerCase();
    const unstable = UNSTABLE_TAGS.some((tag) => lowerPrerelease === tag || lowerPrerelease.startsWith(tag + '.') || lowerPrerelease.includes('-' + tag));
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.SPEC_PRERELEASE_DRIFT,
      unstable || !policy.allowPrerelease ? 'high' : 'medium',
      'dependency range admits prerelease artifacts',
      'pin a stable reviewed release unless the prerelease is explicitly approved',
      { ...context, prerelease }
    ));
  }
  return findings;
}

export function auditSpecifier(packageName, specifier, options = {}) {
  const policy = resolvePolicy(options);
  if (typeof packageName !== 'string' || typeof specifier !== 'string') {
    throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INVALID_INPUT, 'package name and specifier must be strings');
  }
  const dependencyType = typeof options.dependencyType === 'string' ? options.dependencyType : 'dependencies';
  const findings = collectSpecifierFindings(packageName, specifier, 'specifier', dependencyType, policy);
  return buildReport('specifier', policy, findings, { packageName: packageNameForReport(packageName), specifier: redactCredentialAuthority(specifier), dependencyType });
}
