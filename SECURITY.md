# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | yes |

## Reporting a vulnerability

Do not open a public issue for a vulnerability that can affect downstream users. Report it through the repository's private security advisory flow on GitHub.

Include:

- the affected version
- a minimal input or lockfile fixture
- whether the issue concerns parsing, range evaluation, manifest auditing, lockfile auditing, upgrade auditing, or the CLI
- the expected security result and the actual result
- whether the issue has a proof of concept that should remain private during triage

## Scope

In scope:

- parser denial of service or complexity bypasses
- incorrect SemVer precedence or range matching with security impact
- missed detection for documented dependency specifier attacks
- prototype pollution key handling
- lockfile integrity, registry, install script, or version mismatch bypasses
- CLI output injection or uncaught hostile-input failures

Out of scope:

- attacks requiring write access to the repository or victim machine
- registry compromise that cannot be detected from static manifest or lockfile data
- package manager behavior outside npm-compatible manifests and package-lock v2 or v3 files
- vulnerabilities in downstream projects that do not apply the returned policy result

## Hardening expectations

Inputs are bounded before parsing. Consumers should still enforce their own size limits when reading files from untrusted network input. A report with `ok: false` must block the operation in the caller. A report with `ok: true` does not prove a package is safe; it means the static firewall found no policy-blocking signal.
