import type { ScanResult, Severity } from '../types.js';
import { gradeColor } from '../risk/scorer.js';
import { getOwaspName } from '../risk/owasp-mapping.js';

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const GREEN = '\x1b[32m';
const CYAN = '\x1b[36m';

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: RED + BOLD,
  high: RED,
  medium: YELLOW,
  low: DIM,
  info: DIM,
};

export function formatTerminal(result: ScanResult): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(`${BOLD}Attack Surface Report: ${result.agent}${RESET}`);
  lines.push(`${DIM}Scanned: ${result.scanDate}${RESET}`);
  lines.push('');

  // Grade
  const gc = gradeColor(result.grade);
  lines.push(`${BOLD}Risk Score: ${gc}${result.riskScore}/100 (Grade: ${result.grade})${RESET}`);
  lines.push('');

  // Attack surface summary
  lines.push(`${BOLD}Attack Surface${RESET}`);
  lines.push(`  Tools: ${result.attackSurface.totalTools}`);
  if (Object.keys(result.attackSurface.capabilityBreakdown).length > 0) {
    lines.push(`  Capabilities:`);
    for (const [cap, count] of Object.entries(result.attackSurface.capabilityBreakdown)) {
      lines.push(`    ${cap}: ${count} tool(s)`);
    }
  }
  if (result.attackSurface.criticalPaths.length > 0) {
    lines.push(`  ${RED}Critical paths:${RESET}`);
    for (const path of result.attackSurface.criticalPaths) {
      lines.push(`    ${RED}${path}${RESET}`);
    }
  }
  lines.push('');

  // Findings
  lines.push(`${BOLD}Findings (${result.findings.length})${RESET}`);
  lines.push('');

  for (const finding of result.findings) {
    const sc = SEVERITY_COLORS[finding.severity];
    const owasp = finding.owaspMapping ? ` ${DIM}[${finding.owaspMapping}: ${getOwaspName(finding.owaspMapping)}]${RESET}` : '';
    lines.push(`  ${sc}${finding.severity.toUpperCase()}${RESET} ${finding.title}${owasp}`);
    lines.push(`  ${DIM}${finding.description}${RESET}`);
    lines.push(`  ${CYAN}Fix: ${finding.remediation}${RESET}`);
    lines.push('');
  }

  return lines.join('\n');
}
