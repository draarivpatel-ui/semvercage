# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| < 1.0 | No |

## Reporting a vulnerability

Use the private GitHub Security Advisories form: [Report a vulnerability](https://github.com/draarivpatel-ui/semvercage/security/advisories/new). Do not open a public issue, pull request, or discussion with exploit details, secrets, private endpoints, or personal data.

Include the affected version, a minimal input or lockfile fixture, whether the issue concerns parsing, range evaluation, manifest auditing, lockfile auditing, upgrade auditing, or the CLI, the expected security result, and the actual result.

## Disclosure timeline

We acknowledge reports within 48 hours. We aim to confirm or reject the report within 7 days, prepare a fix as soon as practical, and coordinate public disclosure with the reporter. Unless a shorter deadline is required by an actively exploited issue, please allow up to 90 days for a coordinated fix and disclosure.

## Scope

In scope:

- Parser denial of service or complexity bypasses
- Incorrect SemVer precedence or range matching with security impact
- Missed detection for documented dependency specifier attacks
- Prototype pollution keys, inherited properties, accessor execution, and cyclic object handling
- Lockfile integrity, registry, install script, or version mismatch bypasses
- CLI output injection or uncaught hostile-input failures

## Out of scope

Attacks requiring write access to the repository or victim machine, registry compromise that cannot be detected from static manifest or lockfile data, package manager behavior outside npm-compatible manifests and package-lock v2 or v3 files, and downstream projects that ignore a blocking policy result are out of scope.

## Hardening notes

The package has zero runtime dependencies. Input budgets, fail-closed validation, deterministic tests, and property-based fuzz tests are part of the maintenance bar. A report that the library marks unsafe must block the operation in the caller; audit output is a boundary signal, not proof that a downstream system is safe.

## Disclosure history

No published advisories yet. Fixed versions will be listed here with their advisory links.
