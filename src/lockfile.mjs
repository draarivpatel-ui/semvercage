import { SEMVERCAGE_ERROR_CODES, SEMVERCAGE_FINDING_CODES } from './constants.mjs';
import { parseJsonObjectInput, sanitizeObjectTree } from './guards.mjs';
import { resolvePolicy } from './policy.mjs';
import { tryParseSemver } from './semver.mjs';
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

function auditResolvedUrl(resolved, packagePath, policy, findings, propertyPath = 'packages.' + packagePath + '.resolved') {
  const context = { path: propertyPath, packagePath, resolved: redactCredentialAuthority(resolved) };
  if (hasControlOrNonAscii(resolved)) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_UNTRUSTED_REGISTRY,
      'critical',
      'lockfile resolved URL contains hidden or non ASCII characters',
      'regenerate the lockfile with a plain ASCII trusted registry URL',
      context
    ));
    return null;
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
  if (!resolved.toLowerCase().startsWith('https://') && policy.requireHttps) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_NON_HTTPS_RESOLVED,
      'critical',
      'lockfile resolved URL does not use HTTPS',
      'regenerate the lockfile against an HTTPS registry endpoint',
      context
    ));
    return null;
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
    return null;
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

function inspectTarballUrl(url, packageName) {
  if (!url || !packageName) return { recognized: false };
  const baseName = packageName.includes('/') ? packageName.slice(packageName.indexOf('/') + 1) : packageName;
  const marker = '/-/';
  const markerIndex = url.pathname.lastIndexOf(marker);
  if (markerIndex === -1) return { recognized: false };
  const fileName = url.pathname.slice(markerIndex + marker.length);
  const prefix = baseName + '-';
  if (!fileName.startsWith(prefix) || !fileName.endsWith('.tgz')) {
    return { recognized: true, packageMismatch: true, fileName, expectedPrefix: prefix };
  }
  const versionText = fileName.slice(prefix.length, fileName.length - 4);
  return { recognized: true, packageMismatch: false, versionText, version: tryParseSemver(versionText) };
}

function isLocalEntry(entry) {
  return entry.link === true || (typeof entry.resolved === 'string' && entry.resolved.startsWith('file:'));
}

function collectLegacyDependencies(dependencies, output, policy) {
  if (!dependencies || typeof dependencies !== 'object' || Array.isArray(dependencies)) return;
  const stack = [{ dependencies, basePath: '', depth: 0 }];
  while (stack.length > 0) {
    const item = stack.pop();
    if (item.depth > policy.maxObjectDepth) continue;
    for (const name of Object.keys(item.dependencies)) {
      const entry = item.dependencies[name];
      const packagePath = item.basePath + (item.basePath ? '/node_modules/' : 'node_modules/') + name;
      output.set(packagePath, { name, entry, packagePath });
      if (entry && typeof entry === 'object' && !Array.isArray(entry) && entry.dependencies && typeof entry.dependencies === 'object' && !Array.isArray(entry.dependencies)) {
        stack.push({ dependencies: entry.dependencies, basePath: packagePath, depth: item.depth + 1 });
      }
    }
  }
}

function auditIntegrity(entry, packagePath, findings, policy, propertyPath = 'packages.' + packagePath + '.integrity') {
  const context = { path: propertyPath, packagePath };
  if (entry.integrity === undefined) {
    if (policy.requireIntegrity) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.LOCKFILE_MISSING_INTEGRITY,
        'high',
        'lockfile package entry is missing an integrity hash',
        'regenerate the lockfile with registry integrity metadata',
        context
      ));
    }
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
  } else if (integrity.state === 'weak' && policy.requireIntegrity) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_WEAK_INTEGRITY,
      integrity.severity,
      'lockfile package integrity does not provide a sha512 subresource integrity hash',
      'regenerate the lockfile with sha512 integrity hashes',
      context
    ));
  }
}

function compareLegacyConsistency(item, entry, current, findings) {
  const context = { path: 'dependencies.' + item.name, packagePath: item.packagePath };
  if (typeof entry.version === 'string' || typeof current.version === 'string') {
    if (entry.version !== current.version) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.LOCKFILE_VERSION_MISMATCH,
        'high',
        'lockfile dependency summary version differs from the packages snapshot',
        'regenerate the lockfile with one package manager version',
        { ...context, summaryVersion: entry.version, packagesVersion: current.version }
      ));
    }
  }
  if (!isLocalEntry(entry) && !isLocalEntry(current) && (entry.integrity !== undefined || current.integrity !== undefined) && entry.integrity !== current.integrity) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_INTEGRITY_MISMATCH,
      'high',
      'lockfile dependency summary integrity differs from the packages snapshot',
      'regenerate the lockfile and investigate tampering before installing',
      context
    ));
  }
  if (!isLocalEntry(entry) && !isLocalEntry(current) && (entry.resolved !== undefined || current.resolved !== undefined) && entry.resolved !== current.resolved) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_RESOLVED_MISMATCH,
      'high',
      'lockfile dependency summary resolved URL differs from the packages snapshot',
      'regenerate the lockfile and investigate registry response substitution before installing',
      context
    ));
  }
  if (entry.hasInstallScript === true && current.hasInstallScript !== true) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_UNDECLARED_INSTALL_SCRIPT,
      'critical',
      'legacy lockfile dependency declares an install script missing from the packages snapshot',
      'regenerate the lockfile and inspect the dependency lifecycle script before installing',
      context
    ));
  }
}

function auditLegacyEntries(lockfile, packages, policy, findings, installScriptPaths) {
  if (lockfile.dependencies === undefined) return;
  if (!lockfile.dependencies || typeof lockfile.dependencies !== 'object' || Array.isArray(lockfile.dependencies)) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_INVALID_PACKAGE_ENTRY,
      'high',
      'legacy lockfile dependencies field is not an object',
      'regenerate the lockfile with a valid dependency summary object',
      { path: 'dependencies' }
    ));
    return;
  }
  const legacy = new Map();
  collectLegacyDependencies(lockfile.dependencies, legacy, policy);
  for (const item of legacy.values()) {
    const entry = item.entry;
    const legacyPath = 'dependencies.' + item.packagePath;
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.LOCKFILE_INVALID_PACKAGE_ENTRY,
        'high',
        'legacy lockfile dependency entry is not an object',
        'regenerate the lockfile with valid dependency entries',
        { path: legacyPath, packagePath: item.packagePath }
      ));
      continue;
    }
    findings.push(...collectPackageNameFindings(item.name, legacyPath + '.packageName', policy));
    if (typeof entry.version !== 'string' || !tryParseSemver(entry.version)) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.LOCKFILE_INVALID_VERSION,
        'high',
        'legacy lockfile dependency version is missing or is not strict semver',
        'regenerate the lockfile with strict semver package versions',
        { path: legacyPath + '.version', packagePath: item.packagePath, value: entry.version }
      ));
    }
    if (entry.hasInstallScript === true) {
      installScriptPaths.add(item.packagePath);
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.LOCKFILE_INSTALL_SCRIPT,
        'high',
        'legacy dependency summary is flagged as running an install lifecycle script',
        'inspect the package lifecycle script and replace the dependency when execution is not necessary',
        { path: legacyPath + '.hasInstallScript', packagePath: item.packagePath }
      ));
    }
    const localEntry = isLocalEntry(entry);
    if (typeof entry.resolved === 'string' && entry.resolved.length > 0) {
      if (!entry.resolved.startsWith('file:')) auditResolvedUrl(entry.resolved, item.packagePath, policy, findings, legacyPath + '.resolved');
    } else if (!localEntry) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.LOCKFILE_MISSING_RESOLVED,
        'medium',
        'legacy dependency summary is missing a resolved URL',
        'regenerate the lockfile so every registry package has an auditable resolved URL',
        { path: legacyPath + '.resolved', packagePath: item.packagePath }
      ));
    }
    if (!localEntry) auditIntegrity(entry, item.packagePath, findings, policy, legacyPath + '.integrity');
    const current = packages[item.packagePath];
    if (current && typeof current === 'object' && !Array.isArray(current)) compareLegacyConsistency(item, entry, current, findings);
  }
}

export function auditLockfile(input, options = {}) {
  const policy = resolvePolicy(options);
  const inputObject = parseJsonObjectInput(input, SEMVERCAGE_ERROR_CODES.INVALID_LOCKFILE, 'package-lock.json', policy);
  const findings = [];
  const lockfile = sanitizeObjectTree(inputObject, policy, findings, '$');
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
  const installScriptPaths = new Set();
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
    const parsedEntryVersion = typeof entry.version === 'string' ? tryParseSemver(entry.version) : null;
    if (!parsedEntryVersion) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.LOCKFILE_INVALID_VERSION,
        'high',
        'lockfile package version is missing or is not strict semver',
        'regenerate the lockfile with strict semver package versions',
        { path: 'packages.' + packagePath + '.version', packagePath, value: entry.version }
      ));
    }
    if (entry.hasInstallScript === true) {
      installScriptPaths.add(packagePath);
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.LOCKFILE_INSTALL_SCRIPT,
        'high',
        'transitive dependency is flagged as running an install lifecycle script',
        'inspect the package lifecycle script and replace the dependency when execution is not necessary',
        { path: 'packages.' + packagePath + '.hasInstallScript', packagePath }
      ));
    }
    const localEntry = isLocalEntry(entry);
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
    if (!localEntry) auditIntegrity(entry, packagePath, findings, policy);
    const archive = inspectTarballUrl(parsedUrl, packageName);
    if (archive.recognized && archive.packageMismatch) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.LOCKFILE_PACKAGE_NAME_MISMATCH,
        'high',
        'lockfile resolved tarball filename belongs to a different package than the node_modules path',
        'regenerate the lockfile and investigate package substitution before installing',
        { path: 'packages.' + packagePath + '.resolved', packagePath, inferredName: packageName, tarballFile: archive.fileName }
      ));
    } else if (archive.recognized && parsedEntryVersion) {
      if (!archive.version || archive.version.version !== parsedEntryVersion.version) {
        findings.push(makeFinding(
          SEMVERCAGE_FINDING_CODES.LOCKFILE_VERSION_MISMATCH,
          'high',
          'lockfile package version does not exactly match the version encoded in its resolved tarball URL',
          'regenerate the lockfile and investigate registry response substitution',
          { path: 'packages.' + packagePath + '.resolved', packagePath, entryVersion: entry.version, tarballVersion: archive.version ? archive.version.version : archive.versionText }
        ));
      }
    }
  }
  auditLegacyEntries(lockfile, packages, policy, findings, installScriptPaths);
  const installScripts = Array.from(installScriptPaths);
  if (installScripts.length > 1) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.LOCKFILE_DUPLICATE_INSTALL_SCRIPT,
      'high',
      'multiple transitive dependencies request install lifecycle execution',
      'review every lifecycle script together and remove unnecessary install hooks',
      { path: 'packages', count: installScripts.length, packagePaths: installScripts.slice(0, 16) }
    ));
  }
  return buildReport('lockfile', policy, findings, {
    packageCount,
    installScriptCount: installScripts.length
  });
}
