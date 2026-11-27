import { POLLUTION_KEYS, SEMVERCAGE_ERROR_CODES, SEMVERCAGE_FINDING_CODES } from './constants.mjs';
import { SemverCageError } from './errors.mjs';
import { makeFinding } from './utils.mjs';

export function parseJsonObjectInput(input, errorCode, label, policy) {
  let value = input;
  if (typeof input === 'string') {
    if (input.length > policy.maxInputLength) {
      throw new SemverCageError(SEMVERCAGE_ERROR_CODES.INPUT_TOO_LONG, label + ' exceeds the input length bound', { length: input.length, bound: policy.maxInputLength });
    }
    try {
      value = JSON.parse(input);
    } catch (error) {
      throw new SemverCageError(errorCode, label + ' is not valid JSON', { reason: error.message });
    }
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new SemverCageError(errorCode, label + ' must be a JSON object', { actual: Array.isArray(value) ? 'array' : typeof value });
  }
  return value;
}

function objectContainer(value) {
  if (!Array.isArray(value)) return Object.create(null);
  const output = [];
  output.length = value.length;
  return output;
}

function defineDataProperty(target, key, value) {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    configurable: true,
    writable: true
  });
}

export function sanitizeObjectTree(root, policy, findings, rootPath = '$') {
  const rootClone = objectContainer(root);
  const stack = [{ value: root, clone: rootClone, path: rootPath, depth: 0, ancestors: [] }];
  let totalKeys = 0;
  let depthReported = false;
  let breadthReported = false;
  while (stack.length > 0) {
    const item = stack.pop();
    const value = item.value;
    if (!value || typeof value !== 'object') continue;
    if (item.ancestors.includes(value)) {
      findings.push(makeFinding(
        SEMVERCAGE_FINDING_CODES.OBJECT_CYCLE,
        'high',
        'input object contains a cyclic reference',
        'parse input from JSON or remove cyclic references before auditing',
        { path: item.path }
      ));
      continue;
    }
    const childAncestors = item.ancestors.concat([value]);
    if (item.depth > policy.maxObjectDepth) {
      if (!depthReported) {
        depthReported = true;
        findings.push(makeFinding(
          SEMVERCAGE_FINDING_CODES.OBJECT_DEPTH_EXCEEDED,
          'high',
          'input object nesting exceeds the audit bound',
          'reduce manifest or lockfile nesting before auditing',
          { path: item.path, depth: item.depth, bound: policy.maxObjectDepth }
        ));
      }
      continue;
    }
    const keys = Object.getOwnPropertyNames(value).filter((key) => !(Array.isArray(value) && key === 'length'));
    totalKeys += keys.length;
    if (totalKeys > policy.maxObjectKeys) {
      if (!breadthReported) {
        breadthReported = true;
        findings.push(makeFinding(
          SEMVERCAGE_FINDING_CODES.OBJECT_BREADTH_EXCEEDED,
          'high',
          'input object key count exceeds the audit bound',
          'split or reduce the input object before auditing',
          { path: item.path, count: totalKeys, bound: policy.maxObjectKeys }
        ));
      }
      break;
    }
    for (const key of keys) {
      const childPath = item.path + '.' + key;
      if (POLLUTION_KEYS.includes(key)) {
        findings.push(makeFinding(
          SEMVERCAGE_FINDING_CODES.PROTOTYPE_POLLUTION_KEY,
          'critical',
          'input contains a prototype pollution key',
          'remove the pollution key and regenerate the manifest or lockfile',
          { path: childPath, key }
        ));
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor) continue;
      if (Object.prototype.hasOwnProperty.call(descriptor, 'get') || Object.prototype.hasOwnProperty.call(descriptor, 'set')) {
        findings.push(makeFinding(
          SEMVERCAGE_FINDING_CODES.OBJECT_ACCESSOR,
          'high',
          'input object contains an accessor property that cannot be audited without executing code',
          'parse input from JSON or replace accessor properties with plain data values',
          { path: childPath, key }
        ));
        continue;
      }
      if (!Object.prototype.hasOwnProperty.call(descriptor, 'value')) continue;
      const child = descriptor.value;
      if (child && typeof child === 'object') {
        if (childAncestors.includes(child)) {
          findings.push(makeFinding(
            SEMVERCAGE_FINDING_CODES.OBJECT_CYCLE,
            'high',
            'input object contains a cyclic reference',
            'parse input from JSON or remove cyclic references before auditing',
            { path: childPath }
          ));
          continue;
        }
        const childClone = objectContainer(child);
        defineDataProperty(item.clone, key, childClone);
        stack.push({ value: child, clone: childClone, path: childPath, depth: item.depth + 1, ancestors: childAncestors });
      } else {
        defineDataProperty(item.clone, key, child);
      }
    }
  }
  return rootClone;
}
