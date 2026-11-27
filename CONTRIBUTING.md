# Contributing

Contributions are welcome for correctness, security coverage, documentation, and test quality.

## Rules

- Keep runtime dependencies empty. Keep development dependencies limited to the pinned fast-check property-testing library.
- Preserve strict SemVer 2.0.0 behavior.
- Keep parsing linear and explicitly bounded.
- Do not add dynamically constructed regular expressions.
- Add regression tests for every security fix.
- Keep `src/` as the only hand-edited implementation source.
- Refresh `dist/cjs/index.cjs` with `node scripts/build-cjs.mjs`.
- Keep TypeScript declarations strict and hand-authored.
- Do not commit generated tarballs, dependency directories, local paths, credentials, or personal data.

## Verification

Run these commands before submitting a change:

```sh
npm test
node scripts/build-cjs.mjs --check
node scripts/check-types.mjs
node scripts/cli-smoke.mjs
for file in examples/*.mjs; do node "$file"; done
npm pack --dry-run
node scripts/check-pack.mjs
```

## Code style

Use plain modern JavaScript with named exports in `src/*.mjs`. Prefer small scanners over complex regular expressions. Security findings must include a stable machine-readable code, severity, clear explanation, and remediation.
