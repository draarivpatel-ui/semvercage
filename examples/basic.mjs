import { auditUpgrade, compareSemver, parseRange, parseSemver, satisfies } from '../src/index.mjs';

const version = parseSemver('1.4.2');
const range = parseRange('^1.2.0');

console.log('version', version.version);
console.log('range comparator count', range.comparatorCount);
console.log('satisfies', satisfies('1.4.3', range));
console.log('compare', compareSemver('1.4.2', '1.4.3'));
console.log('upgrade findings', auditUpgrade('1.4.2', '1.5.0').findings.length);
