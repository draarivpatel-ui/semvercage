#!/usr/bin/env node
import fs from 'node:fs';
import {
  SEMVERCAGE_VERSION,
  auditLockfile,
  auditPackageJson,
  auditSpecifier,
  auditUpgrade,
  isSemverCageError,
  parseSemver,
  resolvePolicy,
  satisfies
} from '../src/index.mjs';

function sanitize(text) {
  let output = '';
  for (const character of String(text)) {
    const code = character.codePointAt(0);
    output += code >= 32 && code <= 126 ? character : '?';
  }
  return output;
}

function usage() {
  return [
    'semvercage ' + SEMVERCAGE_VERSION,
    'usage:',
    '  semvercage parse <version> [--json] [--strict|--ci]',
    '  semvercage satisfies <version> <range> [--json] [--include-prerelease] [--strict|--ci]',
    '  semvercage audit-spec <package> <specifier> [--json] [--dependency-type <field>] [--strict|--ci]',
    '  semvercage audit-manifest <package.json> [--json] [--strict|--ci]',
    '  semvercage audit-lockfile <package-lock.json> [--json] [--strict|--ci]',
    '  semvercage audit-upgrade <from-version> <to-version> [--json] [--strict|--ci]'
  ].join('\n');
}

function splitArguments(argv) {
  const positional = [];
  const flags = {
    json: false,
    strict: false,
    ci: false,
    includePrerelease: false,
    dependencyType: 'dependencies',
    policy: undefined
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--json') flags.json = true;
    else if (argument === '--strict') flags.strict = true;
    else if (argument === '--ci') flags.ci = true;
    else if (argument === '--include-prerelease') flags.includePrerelease = true;
    else if (argument === '--dependency-type') {
      index += 1;
      if (index >= argv.length) throw new Error('--dependency-type requires a value');
      flags.dependencyType = argv[index];
    } else if (argument === '--policy') {
      index += 1;
      if (index >= argv.length) throw new Error('--policy requires a value');
      flags.policy = argv[index];
    } else if (argument.startsWith('-')) {
      throw new Error('unknown option: ' + sanitize(argument));
    } else {
      positional.push(argument);
    }
  }
  if (flags.strict && flags.ci) throw new Error('--strict and --ci cannot be combined');
  if (flags.strict) flags.policy = 'strict';
  else if (flags.ci) flags.policy = 'ci';
  else if (!flags.policy) flags.policy = 'balanced';
  return { positional, flags };
}

function policyOptions(flags) {
  return {
    policy: flags.policy,
    dependencyType: flags.dependencyType,
    includePrerelease: flags.includePrerelease
  };
}

function printJson(value) {
  process.stdout.write(JSON.stringify(value, null, 2) + '\n');
}

function printReport(report, json) {
  if (json) {
    printJson(report);
    return;
  }
  const state = report.ok ? 'pass' : 'block';
  process.stdout.write(state + ' ' + sanitize(report.target) + ' policy=' + sanitize(report.policy) + ' findings=' + String(report.findings.length) + '\n');
  for (const finding of report.findings) {
    process.stdout.write(sanitize(finding.severity) + ' ' + sanitize(finding.code) + ' ' + sanitize(finding.path || report.target) + ' ' + sanitize(finding.message) + '\n');
  }
}

function readInputFile(path) {
  return fs.readFileSync(path, 'utf8');
}

function expectArity(command, positional, count) {
  if (positional.length !== count) throw new Error(command + ' expects ' + String(count) + ' positional argument' + (count === 1 ? '' : 's'));
}

function main(argv) {
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') {
    process.stdout.write(usage() + '\n');
    return argv.length === 0 ? 2 : 0;
  }
  if (argv[0] === '--version' || argv[0] === '-v') {
    process.stdout.write('semvercage ' + SEMVERCAGE_VERSION + '\n');
    return 0;
  }
  const command = argv[0];
  const { positional, flags } = splitArguments(argv.slice(1));
  const options = policyOptions(flags);
  if (command === 'parse') {
    expectArity(command, positional, 1);
    const parsed = parseSemver(positional[0], resolvePolicy(options));
    if (flags.json) printJson(parsed);
    else process.stdout.write(parsed.version + '\n');
    return 0;
  }
  if (command === 'satisfies') {
    expectArity(command, positional, 2);
    const matched = satisfies(positional[0], positional[1], options);
    if (flags.json) printJson({ version: parseSemver(positional[0], resolvePolicy(options)).version, range: positional[1], satisfies: matched });
    else process.stdout.write((matched ? 'true' : 'false') + '\n');
    return matched ? 0 : 1;
  }
  if (command === 'audit-spec') {
    expectArity(command, positional, 2);
    const report = auditSpecifier(positional[0], positional[1], options);
    printReport(report, flags.json);
    return report.ok ? 0 : 1;
  }
  if (command === 'audit-manifest') {
    expectArity(command, positional, 1);
    const report = auditPackageJson(readInputFile(positional[0]), options);
    printReport(report, flags.json);
    return report.ok ? 0 : 1;
  }
  if (command === 'audit-lockfile') {
    expectArity(command, positional, 1);
    const report = auditLockfile(readInputFile(positional[0]), options);
    printReport(report, flags.json);
    return report.ok ? 0 : 1;
  }
  if (command === 'audit-upgrade') {
    expectArity(command, positional, 2);
    const report = auditUpgrade(positional[0], positional[1], options);
    printReport(report, flags.json);
    return report.ok ? 0 : 1;
  }
  throw new Error('unknown command: ' + sanitize(command));
}

try {
  process.exitCode = main(process.argv.slice(2));
} catch (error) {
  if (isSemverCageError(error)) {
    process.stderr.write('error ' + sanitize(error.code) + ' ' + sanitize(error.message) + '\n');
  } else if (error && typeof error === 'object' && typeof error.message === 'string') {
    process.stderr.write('error SEMVERCAGE_CLI ' + sanitize(error.message) + '\n');
  } else {
    process.stderr.write('error SEMVERCAGE_CLI unknown failure\n');
  }
  process.exitCode = 2;
}
