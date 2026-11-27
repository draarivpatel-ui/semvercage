# Changelog

## Unreleased

### Changed

- TypeScript declarations now type report metadata (`dependencyCount`, `lifecycleScriptCount`, `packageCount`, `installScriptCount`, `packageName`, `specifier`, `dependencyType`, `fromVersion`, `toVersion`, `comparison`) and common finding context fields (`key`, `packagePath`, `depth`, `count`, `bound`).
- `scripts/check-types.mjs` verifies that every runtime policy field and report metadata field is declared, and adds positive and negative compile-time cases for policy overrides, report metadata, and finding fields.

## 1.0.0

Initial release.

### Added

- Strict bounded SemVer 2.0.0 parser and comparator.
- Safe range parser and evaluator for exact, caret, tilde, comparison, hyphen, X-range, and union forms.
- Dependency specifier supply-chain firewall.
- `package.json` dependency, override, resolution, lifecycle, bundled dependency, and prototype pollution auditing.
- `package-lock.json` v2 and v3 integrity, registry, version consistency, install script, and prototype pollution auditing.
- Version upgrade guard for downgrades, major jumps, prerelease transitions, and build metadata substitution.
- Strict, balanced, and CI policy presets.
- Dual ESM and CommonJS package entry points.
- Strict hand-authored TypeScript declarations.
- Command line interface with JSON output and clean exit codes.
- Hardened object graph sanitization for inherited properties, accessors, arrays, cycles, depth, and breadth.
- Hardened credential URL, build metadata, wildcard arity, tarball consistency, and package-lock legacy representation auditing.
