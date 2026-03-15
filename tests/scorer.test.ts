import { describe, it, expect } from 'vitest';
import { computeRiskScore, letterGrade, severitySummary } from '../src/risk/scorer.js';
import type { Finding, Severity } from '../src/types.js';

function makeFinding(severity: Severity, id = 'TEST-001'): Finding {
  return {
    id,
    severity,
    category: 'test',
    title: 'Test finding',
    description: 'Test',
    remediation: 'Test',
  };
}

describe('Risk Scorer', () => {
  describe('computeRiskScore', () => {
    it('returns 0 for no findings', () => {
      expect(computeRiskScore([])).toBe(0);
    });

    it('scores a single critical finding at 25', () => {
      expect(computeRiskScore([makeFinding('critical')])).toBe(25);
    });

    it('scores a single high finding at 15', () => {
      expect(computeRiskScore([makeFinding('high')])).toBe(15);
    });

    it('scores a single medium finding at 8', () => {
      expect(computeRiskScore([makeFinding('medium')])).toBe(8);
    });

    it('scores a single low finding at 3', () => {
      expect(computeRiskScore([makeFinding('low')])).toBe(3);
    });

    it('scores info findings at 0', () => {
      expect(computeRiskScore([makeFinding('info')])).toBe(0);
    });

    it('sums multiple findings', () => {
      const findings = [
        makeFinding('critical'),
        makeFinding('high'),
        makeFinding('medium'),
      ];
      // 25 + 15 + 8 = 48
      expect(computeRiskScore(findings)).toBe(48);
    });

    it('caps at 100', () => {
      const findings = Array.from({ length: 10 }, (_, i) =>
        makeFinding('critical', `TEST-${i}`),
      );
      // 10 * 25 = 250, capped at 100
      expect(computeRiskScore(findings)).toBe(100);
    });
  });

  describe('letterGrade', () => {
    it('gives A for score 0', () => expect(letterGrade(0)).toBe('A'));
    it('gives A for score 15', () => expect(letterGrade(15)).toBe('A'));
    it('gives B for score 16', () => expect(letterGrade(16)).toBe('B'));
    it('gives B for score 35', () => expect(letterGrade(35)).toBe('B'));
    it('gives C for score 36', () => expect(letterGrade(36)).toBe('C'));
    it('gives C for score 55', () => expect(letterGrade(55)).toBe('C'));
    it('gives D for score 56', () => expect(letterGrade(56)).toBe('D'));
    it('gives D for score 75', () => expect(letterGrade(75)).toBe('D'));
    it('gives F for score 76', () => expect(letterGrade(76)).toBe('F'));
    it('gives F for score 100', () => expect(letterGrade(100)).toBe('F'));
  });

  describe('severitySummary', () => {
    it('counts findings by severity', () => {
      const findings = [
        makeFinding('critical'),
        makeFinding('critical'),
        makeFinding('high'),
        makeFinding('medium'),
        makeFinding('low'),
        makeFinding('low'),
        makeFinding('info'),
      ];
      const summary = severitySummary(findings);
      expect(summary.critical).toBe(2);
      expect(summary.high).toBe(1);
      expect(summary.medium).toBe(1);
      expect(summary.low).toBe(2);
      expect(summary.info).toBe(1);
    });

    it('returns all zeros for empty findings', () => {
      const summary = severitySummary([]);
      expect(summary.critical).toBe(0);
      expect(summary.high).toBe(0);
      expect(summary.medium).toBe(0);
      expect(summary.low).toBe(0);
      expect(summary.info).toBe(0);
    });
  });
});
