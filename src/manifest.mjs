import { DEPENDENCY_FIELDS, LIFECYCLE_SCRIPTS, OVERRIDE_FIELDS, SEMVERCAGE_ERROR_CODES, SEMVERCAGE_FINDING_CODES } from './constants.mjs';
import { parseJsonObjectInput, scanObjectTree } from './guards.mjs';
import { resolvePolicy } from './policy.mjs';
import { collectPackageNameFindings, collectSpecifierFindings } from './specifier.mjs';
import { buildReport, makeFinding } from './utils.mjs';

function auditDependencyField(manifest, field, policy, findings) {
  const value = manifest[field];
  if (value === undefined) return 0;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.MANIFEST_INVALID_DEPENDENCY_FIELD,
      'high',
      'dependency field must be an object mapping package names to specifiers',
      'correct the manifest dependency field before auditing or publishing',
      { path: field }
    ));
    return 0;
  }
  let count = 0;
  for (const packageName of Object.keys(value)) {
    count += 1;
    findings.push(...collectSpecifierFindings(packageName, value[packageName], field + '.' + packageName, field, policy));
  }
  return count;
}

function auditOverrideValue(packageName, value, path, field, policy, findings, depth) {
  if (depth > 6) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.MANIFEST_INVALID_DEPENDENCY_FIELD,
      'medium',
      'override nesting exceeds the audit bound',
      'flatten override rules or reduce nested override depth',
      { path }
    ));
    return;
  }
  if (typeof value === 'string') {
    findings.push(...collectSpecifierFindings(packageName, value, path, field, policy));
    return;
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    for (const key of Object.keys(value)) {
      auditOverrideValue(key, value[key], path + '.' + key, field, policy, findings, depth + 1);
    }
    return;
  }
  findings.push(makeFinding(
    SEMVERCAGE_FINDING_CODES.MANIFEST_INVALID_DEPENDENCY_FIELD,
    'medium',
    'override or resolution value is not a specifier string or nested override object',
    'use a semver specifier string at each override leaf',
    { path, actual: Array.isArray(value) ? 'array' : typeof value }
  ));
}

function auditOverrideField(manifest, field, policy, findings) {
  const value = manifest[field];
  if (value === undefined) return 0;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.MANIFEST_INVALID_DEPENDENCY_FIELD,
      'high',
      'override field must be an object',
      'correct the override field before auditing or publishing',
      { path: field }
    ));
    return 0;
  }
  let count = 0;
  for (const key of Object.keys(value)) {
    count += 1;
    auditOverrideValue(key, value[key], field + '.' + key, field, policy, findings, 0);
  }
  return count;
}

function auditLifecycleScripts(manifest, findings) {
  if (!manifest.scripts || typeof manifest.scripts !== 'object' || Array.isArray(manifest.scripts)) return 0;
  let count = 0;
  for (const hook of LIFECYCLE_SCRIPTS) {
    const command = manifest.scripts[hook];
    if (typeof command === 'string' && command.length > 0) {
      count += 1;
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.MANIFEST_LIFECYCLE_SCRIPT,
        hook === 'prepare' ? 'medium' : 'high',
        'manifest contains an install lifecycle script that executes during dependency installation',
        'remove the lifecycle hook or replace it with an explicit reviewed build step',
        { path: 'scripts.' + hook, hook }
      ));
    }
  }
  return count;
}

function auditBundledDependencies(manifest, findings) {
  for (const field of ['bundledDependencies', 'bundleDependencies']) {
    const value = manifest[field];
    if (value === undefined) continue;
    const nonempty = Array.isArray(value) ? value.length > 0 : Boolean(value);
    if (nonempty) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.MANIFEST_BUNDLED_DEPENDENCIES,
        'medium',
        'manifest bundles dependency artifacts that can obscure transitive versions and integrity',
        'unbundle dependencies and pin them through the registry and lockfile',
        { path: field }
      ));
    }
  }
}

export function auditPackageJson(input, options = {}) {
  const policy = resolvePolicy(options);
  const manifest = parseJsonObjectInput(input, SEMVERCAGE_ERROR_CODES.INVALID_MANIFEST, 'package.json', policy);
  const findings = [];
  scanObjectTree(manifest, policy, findings, '$');
  if (typeof manifest.name === 'string') {
    findings.push(...collectPackageNameFindings(manifest.name, 'name', policy));
  }
  let dependencyCount = 0;
  for (const field of DEPENDENCY_FIELDS) dependencyCount += auditDependencyField(manifest, field, policy, findings);
  for (const field of OVERRIDE_FIELDS) dependencyCount += auditOverrideField(manifest, field, policy, findings);
  const lifecycleScriptCount = auditLifecycleScripts(manifest, findings);
  auditBundledDependencies(manifest, findings);
  return buildReport('manifest', policy, findings, {
    dependencyCount,
    lifecycleScriptCount,
    packageName: typeof manifest.name === 'string' ? manifest.name : undefined
  });
}
