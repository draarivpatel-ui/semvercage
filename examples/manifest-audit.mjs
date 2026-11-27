import { auditPackageJson } from '../src/index.mjs';

const manifest = {
  name: 'example-service',
  dependencies: {
    'stable-package': '1.4.2',
    'risky-package': 'github:example/risky-package'
  },
  scripts: {
    postinstall: 'node install.js'
  }
};

const report = auditPackageJson(manifest, { policy: 'balanced' });
console.log('manifest ok', report.ok);
for (const finding of report.findings) {
  console.log(finding.severity, finding.code, finding.path);
}
