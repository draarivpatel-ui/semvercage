import { SEMVERCAGE_ERROR_CODES } from './constants.mjs';
import { deepFreeze } from './utils.mjs';

export class SemverCageError extends Error {
  constructor(code, message, details = {}) {
    super(String(message));
    this.name = 'SemverCageError';
    this.code = typeof code === 'string' && code.startsWith('SEMVERCAGE_')
      ? code
      : SEMVERCAGE_ERROR_CODES.INVALID_INPUT;
    this.details = deepFreeze(details && typeof details === 'object' ? { ...details } : {});
  }
}

export function semvercageError(code, message, details = {}) {
  return new SemverCageError(code, message, details);
}

export function isSemverCageError(value) {
  return value instanceof SemverCageError || Boolean(
    value &&
    typeof value === 'object' &&
    value.name === 'SemverCageError' &&
    typeof value.code === 'string' &&
    value.code.startsWith('SEMVERCAGE_')
  );
}
