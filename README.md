# semvercage

`semvercage` is a zero-dependency supply-chain firewall for npm packages. It combines a strict bounded SemVer 2.0.0 parser, a safe range evaluator, dependency specifier auditing, `package.json` lifecycle checks, `package-lock.json` integrity checks, and version upgrade guards.

The library is designed for security automation, CI gates, package manager wrappers, registry proxies, and maintainer tooling that must treat dependency input as hostile.

## Security properties

- Strict SemVer 2.0.0 parsing with explicit input, token, identifier, and integer bounds.
- Linear scanner design with no dynamically constructed regular expressions and no nested quantifier parsing pattern.
- Rejects leading zeros, integer overflow, malformed identifiers, hidden control characters, bidirectional text, non ASCII smuggling, and malformed ranges.
- Range support for exact versions, caret, tilde, comparison operators, hyphen ranges, X ranges, and union expressions.
- Comparator, union, input length, object depth, and object breadth limits.
- Prerelease isolation that does not match a prerelease across a different major, minor, patch tuple unless explicitly requested.
- Detection for mutable tags, wildcard specifiers, unbounded lower-only ranges, prerelease drift, build metadata substitution risk, git and hosting shorthand specifiers, remote tarballs, local path specifiers, workspace protocol misuse, npm alias indirection, and credential-bearing URLs.
- Dependency confusion and typosquatting signals for private-looking unscoped names, invalid names, non ASCII names, case confusion, and suspicious separator patterns.
- Manifest auditing for dependency fields, overrides, resolutions, install lifecycle hooks, bundled dependencies, prototype pollution keys, cyclic input, deep or broad object graphs, and accessor properties that cannot be audited without executing code.
- Lockfile auditing for missing or weak integrity, malformed SRI, non HTTPS resolution, unexpected registries, IP literals, credentials, exact tarball package and version mismatch, legacy dependency snapshot mismatch, transitive install scripts, and prototype pollution keys.
- Upgrade auditing for downgrades, unexpected major jumps, stable to prerelease transitions, prerelease channel movement, and build-metadata-only substitution.
- Structured findings with stable `SEMVERCAGE_*` codes, severity, explanation, and remediation.
- Dual ESM and CommonJS entry points with hand-authored strict TypeScript declarations.
- Zero runtime dependencies and zero development dependencies.

## Install

```sh
npm install semvercage
```

## Quick start

```js
import {
  auditLockfile,
  auditPackageJson,
  auditSpecifier,
  auditUpgrade,
  parseSemver,
  satisfies
} from 'semvercage';

const version = parseSemver('1.4.2');
console.log(version.major, version.minor, version.patch);

console.log(satisfies('1.4.3', '^1.2.0'));

const specifierReport = auditSpecifier('example-package', '>=1.0.0');
if (!specifierReport.ok) {
  for (const finding of specifierReport.findings) {
    console.error(finding.code, finding.severity, finding.remediation);
  }
}

const upgradeReport = auditUpgrade('2.1.0', '1.9.0', 'strict');
console.log(upgradeReport.ok);
```

CommonJS is supported:

```js
const { satisfies, auditSpecifier } = require('semvercage');
```

## SemVer parsing and comparison

```js
import { compareSemver, parseSemver } from 'semvercage';

const parsed = parseSemver('1.2.3-rc.1+build.9');
console.log(parsed.prerelease);
console.log(compareSemver('1.2.3-rc.1', '1.2.3'));
```

`parseSemver` throws a `SemverCageError` for invalid input. Numeric core identifiers and numeric prerelease identifiers must not have leading zeros and must remain at or below `Number.MAX_SAFE_INTEGER`. Build metadata is preserved but ignored for precedence as required by SemVer 2.0.0.

## Range evaluation

```js
import { parseRange, satisfies } from 'semvercage';

const range = parseRange('>=1.2.0 <2.0.0 || ^3.1.0');
console.log(satisfies('3.2.0', range));
```

Supported forms:

- `1.2.3` and `=1.2.3`
- `^1.2.3` and `~1.2.3`
- `>=1.2.0 <2.0.0`
- `1.2.x`, `1.x`, and `*`
- `1.2.3 - 2.4.0`
- `||` unions

Ranges are intentionally bounded. Excess unions, expanded comparators, input length, repeated empty comparators, and non ASCII or control characters are rejected before evaluation.

## Dependency specifier auditing

```js
import { auditSpecifier } from 'semvercage';

const report = auditSpecifier('safe-name', 'npm:other-name@1.0.0', {
  policy: 'balanced',
  dependencyType: 'dependencies'
});
```

The auditor flags non registry specifiers and mutable or unbounded dependency behavior. Exact registry versions and bounded ranges are the safest form. Reports are frozen and machine-readable:

```js
{
  ok: false,
  target: 'specifier',
  policy: 'balanced',
  findings: [
    {
      code: 'SEMVERCAGE_SPEC_NPM_ALIAS',
      severity: 'high',
      message: '...',
      remediation: '...'
    }
  ]
}
```

## Manifest auditing

```js
import fs from 'node:fs';
import { auditPackageJson } from 'semvercage';

const report = auditPackageJson(fs.readFileSync('package.json', 'utf8'), {
  policy: 'strict'
});
```

`auditPackageJson` audits `dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`, `overrides`, and `resolutions`. It also flags `preinstall`, `install`, `postinstall`, and `prepare` lifecycle execution, bundled dependencies, invalid package names, and prototype pollution keys anywhere in the manifest object.

## Lockfile auditing

```js
import fs from 'node:fs';
import { auditLockfile } from 'semvercage';

const report = auditLockfile(fs.readFileSync('package-lock.json', 'utf8'), {
  policy: 'ci',
  trustedRegistries: ['registry.npmjs.org']
});
```

`auditLockfile` supports npm `package-lock.json` v2 and v3. It checks package versions, tarball URL consistency, integrity strength, registry host trust, HTTPS use, credentials, IP literals, transitive install script flags, duplicate install script flags, legacy dependency snapshot consistency, and prototype pollution keys.

## Upgrade guard

```js
import { auditUpgrade } from 'semvercage';

const report = auditUpgrade('1.8.0', '3.0.0', {
  policy: 'balanced',
  maxMajorJump: 1
});
```

The guard detects downgrades, major jumps beyond policy, stable to prerelease movement, prerelease channel movement, and build-metadata-only changes. Build metadata does not affect SemVer precedence, so an artifact that changes only build metadata is treated as a high-risk substitution signal.

## Policies

Three presets are provided:

- `strict`: fails on low severity and above, tight parser and object bounds, no unexpected major jump by default.
- `balanced`: fails on medium severity and above, one major jump by default.
- `ci`: fails on high severity and above, suitable for a CI gate that still blocks critical supply-chain behavior.

`requireIntegrity` controls whether missing or weak integrity is policy blocking, while malformed integrity always remains blocking. `requireHttps` controls whether non HTTPS resolved URLs are policy blocking; credentials, IP literals, and untrusted registries remain findings either way.

Policies can be customized:

```js
import { createPolicy } from 'semvercage';

const policy = createPolicy('strict', {
  maxMajorJump: 1,
  trustedRegistries: ['registry.npmjs.org'],
  privateNamePrefixes: ['internal-', 'corp-']
});
```

## CLI

```sh
semvercage parse 1.2.3
semvercage satisfies 1.2.4 '^1.2.0'
semvercage audit-spec example-package 1.2.3
semvercage audit-manifest package.json --strict
semvercage audit-lockfile package-lock.json --ci --json
semvercage audit-upgrade 1.8.0 2.0.0 --strict
```

Exit codes:

- `0`: pass, or the range match is true.
- `1`: policy blocked the input, or the range match is false.
- `2`: usage error, invalid input, unreadable file, or parser failure.

The CLI prints structured JSON with `--json` and does not print uncaught stack traces for hostile input.

## API surface

- `parseSemver(version, options)`
- `tryParseSemver(version, options)`
- `isValidSemver(version, options)`
- `compareSemver(left, right)`
- `parseRange(range, options)`
- `isValidRange(range, options)`
- `satisfies(version, range, options)`
- `auditSpecifier(packageName, specifier, options)`
- `auditPackageJson(manifest, options)`
- `auditLockfile(lockfile, options)`
- `auditUpgrade(fromVersion, toVersion, options)`
- `createPolicy(name, overrides)`
- `getPolicy(name)`
- `resolvePolicy(options)`
- `SemverCageError`
- `isSemverCageError(value)`

## Threat model boundary

`semvercage` is a static firewall. It does not download tarballs, verify registry signatures, execute package manager hooks, or prove that a registry response is authentic. It detects dangerous or inconsistent dependency instructions before install time and should be combined with registry authentication, network controls, sandboxed installs, and artifact verification.

## Development

```sh
npm test
node scripts/build-cjs.mjs --check
node scripts/check-types.mjs
node scripts/cli-smoke.mjs
npm pack --dry-run
node scripts/check-pack.mjs
```

The repository tests the ESM implementation and generated CommonJS bundle for export parity. The generated CommonJS file is deterministic and must be refreshed with `node scripts/build-cjs.mjs` after source changes.

## License

MIT
