import type { ScanResult } from '../types.js';
import { getOwaspName } from '../risk/owasp-mapping.js';

export function formatMarkdown(result: ScanResult): string {
  const lines: string[] = [];

  lines.push(`# Attack Surface Report: ${result.agent}`);
  lines.push('');
  lines.push(`**Scanned:** ${result.scanDate}`);
  lines.push(`**Risk Score:** ${result.riskScore}/100 (Grade: ${result.grade})`);
  lines.push('');

  lines.push('## Attack Surface');
  lines.push('');
  lines.push(`- **Total tools:** ${result.attackSurface.totalTools}`);

  if (result.attackSurface.criticalPaths.length > 0) {
    lines.push('- **Critical paths:**');
    for (const path of result.attackSurface.criticalPaths) {
      lines.push(`  - \`${path}\``);
    }
  }
  lines.push('');

  lines.push(`## Findings (${result.findings.length})`);
  lines.push('');
  lines.push('| Severity | Title | OWASP | Remediation |');
  lines.push('|----------|-------|-------|-------------|');

  for (const f of result.findings) {
    const owasp = f.owaspMapping ? `${f.owaspMapping}: ${getOwaspName(f.owaspMapping)}` : '-';
    lines.push(`| ${f.severity.toUpperCase()} | ${f.title} | ${owasp} | ${f.remediation} |`);
  }

  return lines.join('\n');
}
