import { auditLockfile } from '../src/index.mjs';

const lockfile = {
  lockfileVersion: 3,
  packages: {
    '': { name: 'example-service' },
    'node_modules/stable-package': {
      version: '1.4.2',
      resolved: 'https://registry.npmjs.org/stable-package/-/stable-package-1.4.2.tgz',
      integrity: 'sha512-' + 'A'.repeat(86) + '=='
    },
    'node_modules/install-hook': {
      version: '2.0.0',
      resolved: 'https://registry.npmjs.org/install-hook/-/install-hook-2.0.0.tgz',
      integrity: 'sha512-' + 'B'.repeat(86) + '==',
      hasInstallScript: true
    }
  }
};

const report = auditLockfile(lockfile, { policy: 'ci' });
console.log('lockfile ok', report.ok);
for (const finding of report.findings) {
  console.log(finding.severity, finding.code, finding.path);
}
