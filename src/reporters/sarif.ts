import type { ScanResult, Severity } from '../types.js';

const SEVERITY_TO_SARIF: Record<Severity, string> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'none',
};

export function formatSarif(result: ScanResult): string {
  const sarif = {
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "attack-surface-mapper",
            version: "0.1.0",
            informationUri: "https://github.com/AUTHENSOR/attack-surface-mapper",
            rules: result.findings.map((f) => ({
              id: f.id,
              shortDescription: { text: f.title },
              fullDescription: { text: f.description },
              help: { text: f.remediation },
              properties: {
                ...(f.owaspMapping ? { "security-severity": f.severity === 'critical' ? "9.0" : f.severity === 'high' ? "7.0" : f.severity === 'medium' ? "5.0" : "3.0" } : {}),
              },
            })),
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.id,
          level: SEVERITY_TO_SARIF[f.severity],
          message: { text: `${f.title}\n\n${f.description}\n\nRemediation: ${f.remediation}` },
          ...(f.tool ? { locations: [{ physicalLocation: { artifactLocation: { uri: f.tool } } }] } : {}),
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
