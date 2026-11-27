import { SEMVERCAGE_ERROR_CODES, SEMVERCAGE_FINDING_CODES } from './constants.mjs';
import { parseJsonObjectInput, scanObjectTree } from './guards.mjs';
import { resolvePolicy } from './policy.mjs';
import { compareSemver, tryParseSemver } from './semver.mjs';
import { collectPackageNameFindings } from './specifier.mjs';
import { buildReport, hasControlOrNonAscii, hasCredentialAuthority, makeFinding, redactCredentialAuthority } from './utils.mjs';

const INTEGRITY_PROFILES = Object.freeze({
  sha512: { length: 88, weakness: null },
  sha384: { length: 64, weakness: 'medium' },
  sha256: { length: 44, weakness: 'medium' },
  sha1: { length: 28, weakness: 'high' }
});

function packageNameFromPath(packagePath) {
  const parts = packagePath.split('/');
  let index = -1;
  for (let position = 0; position < parts.length; position += 1) {
    if (parts[position] === 'node_modules') index = position;
  }
  if (index === -1 || index + 1 >= parts.length) return '';
  const first = parts[index + 1];
  if (first.startsWith('@') && index + 2 < parts.length) return first + '/' + parts[index + 2];
  return first;
}

function validBase64(text) {
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    const alpha = (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
    const digit = code >= 48 && code <= 57;
    if (!alpha && !digit && text[index] !== '+' && text[index] !== '/' && text[index] !== '=') return false;
  }
  const firstPadding = text.indexOf('=');
  if (firstPadding !== -1) {
    for (let index = firstPadding; index < text.length; index += 1) {
      if (text[index] !== '=') return false;
    }
    if (text.length - firstPadding > 2) return false;
  }
  return true;
}

function classifyIntegrity(value) {
  if (typeof value !== 'string' || value.length === 0) return { state: 'malformed' };
  const tokens = value.split(' ');
  let sawSha512 = false;
  let weakest = null;
  for (const token of tokens) {
    const dash = token.indexOf('-');
    if (dash <= 0) return { state: 'malformed' };
    const algorithm = token.slice(0, dash);
    const digest = token.slice(dash + 1);
    const profile = INTEGRITY_PROFILES[algorithm];
    if (!profile || digest.length !== profile.length || !validBase64(digest)) return { state: 'malformed' };
    if (algorithm === 'sha512') sawSha512 = true;
    if (profile.weakness === 'high') weakest = 'high';
    else if (profile.weakness === 'medium' && weakest !== 'high') weakest = 'medium';
  }
  if (!sawSha512) return { state: 'weak', severity: weakest || 'medium' };
  if (weakest) return { state: 'weak', severity: weakest };
  return { state: 'strong' };
}

function isIpv4Literal(host) {
  const parts = host.split('.');
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (part.length === 0 || part.length > 3) return false;
    for (let index = 0; index < part.length; index += 1) {
      const code = part.charCodeAt(index);
      if (code < 48 || code > 57) return false;
    }
    if (Number(part) > 255) return false;
  }
  return true;
}

function isIpLiteral(host) {
  return isIpv4Literal(host) || host.includes(':');
}

function auditResolvedUrl(resolved, packagePath, policy, findings) {
  const context = { path: 'packages.' + packagePath + '.resolved', packagePath, resolved: redactCredentialAuthority(resolved) };
  if (hasControlOrNonAscii(resolved)) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_UNTRUSTED_REGISTRY,
      'critical',
      'lockfile resolved URL contains hidden or non ASCII characters',
      'regenerate the lockfile with a plain ASCII trusted registry URL',
      context
    ));
    return;
  }
  if (hasCredentialAuthority(resolved)) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_CREDENTIALS_RESOLVED,
      'critical',
      'lockfile resolved URL embeds credentials',
      'remove credentials and use registry authentication configuration outside the lockfile',
      context
    ));
  }
  if (!resolved.toLowerCase().startsWith('https://')) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_NON_HTTPS_RESOLVED,
      'critical',
      'lockfile resolved URL does not use HTTPS',
      'regenerate the lockfile against an HTTPS registry endpoint',
      context
    ));
    return;
  }
  let url;
  try {
    url = new URL(resolved);
  } catch {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_UNTRUSTED_REGISTRY,
      'high',
      'lockfile resolved URL cannot be parsed',
      'regenerate the lockfile with a valid trusted registry URL',
      context
    ));
    return;
  }
  const host = url.hostname.toLowerCase();
  if (isIpLiteral(host)) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_IP_LITERAL_RESOLVED,
      'critical',
      'lockfile resolved URL uses an IP literal instead of a trusted registry hostname',
      'use a trusted registry hostname so registry hijacking and SSRF redirection are visible',
      context
    ));
  }
  if (!policy.trustedRegistries.includes(host) || url.port !== '') {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_UNTRUSTED_REGISTRY,
      'high',
      'lockfile resolved URL points outside the trusted registry set',
      'pin the registry to an approved host and regenerate the lockfile',
      { ...context, host }
    ));
  }
  return url;
}

function tarballVersion(url, packageName) {
  if (!url) return null;
  const baseName = packageName.includes('/') ? packageName.slice(packageName.indexOf('/') + 1) : packageName;
  const marker = '/-/';
  const markerIndex = url.pathname.lastIndexOf(marker);
  if (markerIndex === -1) return null;
  const fileName = url.pathname.slice(markerIndex + marker.length);
  const prefix = baseName + '-';
  if (!fileName.startsWith(prefix) || !fileName.endsWith('.tgz')) return null;
  const version = fileName.slice(prefix.length, fileName.length - 4);
  return tryParseSemver(version);
}

function collectLegacyDependencies(dependencies, output, basePath = '', depth = 0) {
  if (!dependencies || typeof dependencies !== 'object' || Array.isArray(dependencies) || depth > 12) return;
  for (const name of Object.keys(dependencies)) {
    const entry = dependencies[name];
    if (!entry || typeof entry !== 'object') continue;
    const packagePath = basePath + (basePath ? '/node_modules/' : 'node_modules/') + name;
    output.set(packagePath, { name, entry, packagePath });
    collectLegacyDependencies(entry.dependencies, output, packagePath, depth + 1);
  }
}

function auditLegacyConsistency(lockfile, packages, findings) {
  if (!lockfile.dependencies || typeof lockfile.dependencies !== 'object' || Array.isArray(lockfile.dependencies)) return;
  const legacy = new Map();
  collectLegacyDependencies(lockfile.dependencies, legacy);
  for (const item of legacy.values()) {
    const current = packages[item.packagePath];
    if (!current || typeof current !== 'object') continue;
    if (typeof item.entry.version === 'string' && typeof current.version === 'string' && item.entry.version !== current.version) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.LOCKFILE_VERSION_MISMATCH,
        'high',
        'lockfile dependency summary version differs from the packages snapshot',
        'regenerate the lockfile with one package manager version',
        { path: 'dependencies.' + item.name + '.version', packagePath: item.packagePath, summaryVersion: item.entry.version, packagesVersion: current.version }
      ));
    }
    if (typeof item.entry.integrity === 'string' && typeof current.integrity === 'string' && item.entry.integrity !== current.integrity) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.LOCKFILE_INTEGRITY_MISMATCH,
        'high',
        'lockfile dependency summary integrity differs from the packages snapshot',
        'regenerate the lockfile and investigate tampering before installing',
        { path: 'dependencies.' + item.name + '.integrity', packagePath: item.packagePath }
      ));
    }
    if (item.entry.hasInstallScript === true && current.hasInstallScript !== true) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.LOCKFILE_UNDECLARED_INSTALL_SCRIPT,
        'critical',
        'legacy lockfile dependency declares an install script missing from the packages snapshot',
        'regenerate the lockfile and inspect the dependency lifecycle script before installing',
        { path: 'dependencies.' + item.name + '.hasInstallScript', packagePath: item.packagePath }
      ));
    }
  }
}

function auditIntegrity(entry, packagePath, findings) {
  const context = { path: 'packages.' + packagePath + '.integrity', packagePath };
  if (entry.integrity === undefined) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_MISSING_INTEGRITY,
      'high',
      'lockfile package entry is missing an integrity hash',
      'regenerate the lockfile with registry integrity metadata',
      context
    ));
    return;
  }
  const integrity = classifyIntegrity(entry.integrity);
  if (integrity.state === 'malformed') {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_MALFORMED_INTEGRITY,
      'high',
      'lockfile package integrity value is malformed',
      'regenerate the lockfile and verify the package metadata was not tampered with',
      context
    ));
  } else if (integrity.state === 'weak') {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_WEAK_INTEGRITY,
      integrity.severity,
      'lockfile package integrity does not provide a sha512 subresource integrity hash',
      'regenerate the lockfile with sha512 integrity hashes',
      context
    ));
  }
}

export function auditLockfile(input, options = {}) {
  const policy = resolvePolicy(options);
  const lockfile = parseJsonObjectInput(input, SEMVERCAGE_ERROR_CODES.INVALID_LOCKFILE, 'package-lock.json', policy);
  const findings = [];
  scanObjectTree(lockfile, policy, findings, '$');
  if (lockfile.lockfileVersion !== 2 && lockfile.lockfileVersion !== 3) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_UNSUPPORTED_VERSION,
      'critical',
      'lockfile version is not package-lock format v2 or v3',
      'regenerate a package-lock.json with a supported npm version before auditing',
      { path: 'lockfileVersion', value: lockfile.lockfileVersion }
    ));
  }
  if (!lockfile.packages || typeof lockfile.packages !== 'object' || Array.isArray(lockfile.packages)) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_MISSING_PACKAGES,
      'critical',
      'lockfile does not contain a packages snapshot object',
      'regenerate the lockfile with npm v7 or newer',
      { path: 'packages' }
    ));
    return buildReport('lockfile', policy, findings, { packageCount: 0, installScriptCount: 0 });
  }

  const packages = lockfile.packages;
  let packageCount = 0;
  const installScriptPaths = [];
  for (const packagePath of Object.keys(packages)) {
    const entry = packages[packagePath];
    if (packagePath === '') continue;
    packageCount += 1;
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.LOCKFILE_INVALID_PACKAGE_ENTRY,
        'high',
        'lockfile package entry is not an object',
        'regenerate the lockfile with valid package entries',
        { path: 'packages.' + packagePath, packagePath }
      ));
      continue;
    }
    const packageName = packageNameFromPath(packagePath);
    if (packageName) {
      findings.push(...collectPackageNameFindings(packageName, 'packages.' + packagePath + '.packageName', policy));
    }
    if (typeof entry.name === 'string' && packageName && entry.name !== packageName) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.LOCKFILE_PACKAGE_NAME_MISMATCH,
        'high',
        'lockfile package entry name differs from its node_modules path',
        'regenerate the lockfile and inspect for package substitution',
        { path: 'packages.' + packagePath + '.name', packagePath, entryName: entry.name, inferredName: packageName }
      ));
    }
    if (typeof entry.version !== 'string' || !tryParseSemver(entry.version)) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.LOCKFILE_INVALID_VERSION,
        'high',
        'lockfile package version is missing or is not strict semver',
        'regenerate the lockfile with strict semver package versions',
        { path: 'packages.' + packagePath + '.version', packagePath, value: entry.version }
      ));
    }
    if (entry.hasInstallScript === true) {
      installScriptPaths.push(packagePath);
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.LOCKFILE_INSTALL_SCRIPT,
        'high',
        'transitive dependency is flagged as running an install lifecycle script',
        'inspect the package lifecycle script and replace the dependency when execution is not necessary',
        { path: 'packages.' + packagePath + '.hasInstallScript', packagePath }
      ));
    }
    const localEntry = entry.link === true || (typeof entry.resolved === 'string' && entry.resolved.startsWith('file:'));
    let parsedUrl = null;
    if (typeof entry.resolved === 'string' && entry.resolved.length > 0) {
      if (!entry.resolved.startsWith('file:')) parsedUrl = auditResolvedUrl(entry.resolved, packagePath, policy, findings);
    } else if (!localEntry) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.LOCKFILE_MISSING_RESOLVED,
        'medium',
        'lockfile package entry is missing a resolved URL',
        'regenerate the lockfile so every registry package has an auditable resolved URL',
        { path: 'packages.' + packagePath + '.resolved', packagePath }
      ));
    }
    if (!localEntry) auditIntegrity(entry, packagePath, findings);
    const archiveVersion = tarballVersion(parsedUrl, packageName);
    if (archiveVersion && typeof entry.version === 'string' && tryParseSemver(entry.version) && compareSemver(archiveVersion, entry.version) !== 0) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.LOCKFILE_VERSION_MISMATCH,
        'high',
        'lockfile package version does not match the version encoded in its resolved tarball URL',
        'regenerate the lockfile and investigate registry response substitution',
        { path: 'packages.' + packagePath + '.resolved', packagePath, entryVersion: entry.version, tarballVersion: archiveVersion.version }
      ));
    }
  }
  if (installScriptPaths.length > 1) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_DUPLICATE_INSTALL_SCRIPT,
      'high',
      'multiple transitive dependencies request install lifecycle execution',
      'review every lifecycle script together and remove unnecessary install hooks',
      { path: 'packages', count: installScriptPaths.length, packagePaths: installScriptPaths.slice(0, 16) }
    ));
  }
  auditLegacyConsistency(lockfile, packages, findings);
  return buildReport('lockfile', policy, findings, {
    packageCount,
    installScriptCount: installScriptPaths.length
  });
}
