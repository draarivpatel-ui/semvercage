import { SEMVERCAGE_SEVERITY, SEVERITY_RANK } from './constants.mjs';

export function deepFreeze(value, seen = new WeakSet()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  if (Array.isArray(value)) {
    for (const item of value) deepFreeze(item, seen);
  } else {
    for (const key of Object.keys(value)) deepFreeze(value[key], seen);
  }
  return Object.freeze(value);
}

export function makeFinding(code, severity, message, remediation, context = {}) {
  const finding = {
    code,
    severity,
    message: String(message),
    remediation: String(remediation)
  };
  for (const key of Object.keys(context)) {
    if (context[key] !== undefined) finding[key] = context[key];
  }
  return deepFreeze(finding);
}

export function countFindings(findings) {
  const counts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  for (const finding of findings) {
    if (Object.prototype.hasOwnProperty.call(counts, finding.severity)) {
      counts[finding.severity] += 1;
    }
  }
  return counts;
}

export function buildReport(target, policy, findings, extra = {}) {
  const frozenFindings = deepFreeze(findings.slice());
  const counts = countFindings(frozenFindings);
  const threshold = SEVERITY_RANK[policy.failOn] === undefined ? SEVERITY_RANK.medium : SEVERITY_RANK[policy.failOn];
  let ok = true;
  for (const finding of frozenFindings) {
    const rank = SEVERITY_RANK[finding.severity];
    if (rank !== undefined && rank >= threshold) {
      ok = false;
      break;
    }
  }
  const report = {
    ok,
    target,
    policy: policy.name,
    findings: frozenFindings,
    counts
  };
  for (const key of Object.keys(extra)) {
    if (extra[key] !== undefined) report[key] = extra[key];
  }
  return deepFreeze(report);
}

export function isAsciiDigit(code) {
  return code >= 48 && code <= 57;
}

export function isAsciiAlpha(code) {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122);
}

export function isAsciiAlphanumeric(code) {
  return isAsciiDigit(code) || isAsciiAlpha(code);
}

export function hasOnlyAsciiDigits(text) {
  if (text.length === 0) return false;
  for (let index = 0; index < text.length; index += 1) {
    if (!isAsciiDigit(text.charCodeAt(index))) return false;
  }
  return true;
}

export function hasControlOrNonAscii(text, allowSpace = false) {
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code === 32 && allowSpace) continue;
    if (code < 33 || code > 126) return true;
  }
  return false;
}


export function hasCredentialAuthority(text) {
  const value = String(text);
  let cursor = 0;
  while (cursor < value.length) {
    const schemeEnd = value.indexOf('://', cursor);
    if (schemeEnd === -1) return false;
    const authorityStart = schemeEnd + 3;
    let authorityEnd = value.indexOf('/', authorityStart);
    if (authorityEnd === -1) authorityEnd = value.length;
    const authority = value.slice(authorityStart, authorityEnd);
    const at = authority.lastIndexOf('@');
    if (at > 0 && authority.slice(0, at).includes(':')) return true;
    cursor = Math.max(authorityEnd, authorityStart);
  }
  return false;
}

export function redactCredentialAuthority(text) {
  const value = String(text);
  let output = '';
  let cursor = 0;
  while (cursor < value.length) {
    const schemeEnd = value.indexOf('://', cursor);
    if (schemeEnd === -1) {
      output += value.slice(cursor);
      break;
    }
    const authorityStart = schemeEnd + 3;
    let authorityEnd = value.indexOf('/', authorityStart);
    if (authorityEnd === -1) authorityEnd = value.length;
    const authority = value.slice(authorityStart, authorityEnd);
    const at = authority.lastIndexOf('@');
    if (at <= 0) {
      output += value.slice(cursor, authorityEnd);
    } else {
      output += value.slice(cursor, authorityStart) + '<redacted>@' + authority.slice(at + 1);
    }
    cursor = Math.max(authorityEnd, authorityStart);
  }
  return output;
}

export function severityName(value) {
  for (const key of Object.keys(SEMVERCAGE_SEVERITY)) {
    if (SEMVERCAGE_SEVERITY[key] === value) return value;
  }
  return undefined;
}
