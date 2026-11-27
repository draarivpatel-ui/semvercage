import { SEMVERCAGE_FINDING_CODES } from './constants.mjs';
import { resolvePolicy } from './policy.mjs';
import { compareSemver, parseSemver } from './semver.mjs';
import { buildReport, makeFinding } from './utils.mjs';

function sameIdentifiers(left, right) {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

export function auditUpgrade(fromVersion, toVersion, options = {}) {
  const policy = resolvePolicy(options);
  const from = parseSemver(fromVersion, policy);
  const to = parseSemver(toVersion, policy);
  const findings = [];
  const comparison = compareSemver(from, to);
  const context = { fromVersion: from.version, toVersion: to.version };
  if (comparison > 0) {
    findings.push(makeFinding(
      SEMVERCAGE_FINDING_CODES.UPGRADE_DOWNGRADE,
      'critical',
      'requested upgrade moves to an older semver release',
      'block the downgrade unless a signed incident response decision explicitly requires a rollback',
      context
    ));
  } else if (comparison === 0) {
    if (!sameIdentifiers(from.build, to.build)) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.UPGRADE_BUILD_METADATA_ONLY,
        'critical',
        'requested upgrade changes only build metadata while semver precedence remains unchanged',
        'block the artifact because build metadata can disguise a substituted payload as the same version',
        context
      ));
    } else {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.UPGRADE_NO_CHANGE,
        'info',
        'requested upgrade is the same semantic version',
        'no version upgrade is necessary',
        context
      ));
    }
  } else {
    const majorJump = to.major - from.major;
    if (majorJump > policy.maxMajorJump) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.UPGRADE_MAJOR_JUMP,
        majorJump > 1 ? 'high' : 'medium',
        'requested upgrade crosses an unexpected major version boundary',
        'review breaking changes explicitly or configure a larger approved major jump',
        { ...context, majorJump, allowedMajorJump: policy.maxMajorJump }
      ));
    }
    if (from.prerelease.length === 0 && to.prerelease.length > 0) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.UPGRADE_PRERELEASE_TRANSITION,
        'high',
        'requested upgrade moves from a stable release to a prerelease',
        'block the transition unless the prerelease channel was explicitly approved',
        { ...context, toPrerelease: to.prerelease.join('.') }
      ));
    } else if (from.prerelease.length > 0 && to.prerelease.length > 0 && !sameIdentifiers(from.prerelease, to.prerelease)) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.UPGRADE_PRERELEASE_TRANSITION,
        'medium',
        'requested upgrade moves between prerelease identifiers',
        'verify the prerelease channel and promotion ordering before installing',
        { ...context, fromPrerelease: from.prerelease.join('.'), toPrerelease: to.prerelease.join('.') }
      ));
    }
  }
  return buildReport('upgrade', policy, findings, {
    fromVersion: from.version,
    toVersion: to.version,
    comparison
  });
}
