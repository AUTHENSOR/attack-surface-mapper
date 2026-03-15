import type { Finding, Severity } from '../types.js';

const SEVERITY_SCORES: Record<Severity, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
};

export function calculateRiskScore(findings: Finding[]): number {
  const total = findings.reduce((sum, f) => sum + SEVERITY_SCORES[f.severity], 0);
  return Math.min(100, total);
}

export function calculateGrade(score: number): string {
  if (score <= 15) return 'A';
  if (score <= 35) return 'B';
  if (score <= 55) return 'C';
  if (score <= 75) return 'D';
  return 'F';
}

export function gradeColor(grade: string): string {
  switch (grade) {
    case 'A': return '\x1b[32m'; // green
    case 'B': return '\x1b[33m'; // yellow
    case 'C': return '\x1b[33m'; // yellow
    case 'D': return '\x1b[31m'; // red
    case 'F': return '\x1b[31m'; // red
    default: return '\x1b[0m';
  }
}
