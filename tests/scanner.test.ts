import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { AttackSurfaceScanner } from '../src/scanner.js';
import { analyzeTools } from '../src/analyzers/tool-analyzer.js';
import { analyzeMCPServers } from '../src/analyzers/mcp-analyzer.js';
import { analyzeEnvVars } from '../src/analyzers/env-analyzer.js';
import { analyzePermissions } from '../src/analyzers/permission-analyzer.js';
import { calculateRiskScore, calculateGrade } from '../src/risk/scorer.js';
import type { AgentConfig } from '../src/types.js';

const DANGEROUS_AGENT: AgentConfig = {
  name: 'dangerous-agent',
  tools: [
    {
      name: 'run-command',
      description: 'Execute shell commands',
      parameters: { command: { type: 'string' } },
      capabilities: ['shell_execute', 'network_request', 'file_delete'],
    },
    {
      name: 'read-secrets',
      description: 'Read credential files',
      capabilities: ['credential_access', 'file_read'],
    },
    {
      name: 'send-email',
      description: 'Send emails',
      capabilities: ['email_send', 'network_request'],
    },
  ],
  mcpServers: [
    {
      name: 'filesystem',
      command: 'npx @modelcontextprotocol/server-filesystem /',
      transport: 'stdio',
    },
  ],
  envVars: {
    OPENAI_API_KEY: 'sk-test-1234567890',
    DATABASE_URL: 'postgres://user:pass@host/db',
    APP_NAME: 'my-app',
  },
  permissions: {
    fileSystemPaths: ['/', '/etc', '~/.ssh'],
  },
};

const SAFE_AGENT: AgentConfig = {
  name: 'safe-agent',
  tools: [
    {
      name: 'read-docs',
      description: 'Read documentation files',
      capabilities: ['file_read'],
    },
  ],
  permissions: {
    fileSystemPaths: ['/app/docs'],
    networkAllowList: [],
    requireApproval: ['shell_execute', 'file_delete', 'payment_process', 'credential_access', 'system_config'],
  },
};

describe('AttackSurfaceScanner', () => {
  const scanner = new AttackSurfaceScanner();

  it('produces findings for a dangerous config', () => {
    const result = scanner.scan(DANGEROUS_AGENT);
    assert.ok(result.findings.length > 5, `Expected many findings, got ${result.findings.length}`);
    assert.ok(result.riskScore > 50, `Expected high risk score, got ${result.riskScore}`);
    assert.equal(result.agent, 'dangerous-agent');
  });

  it('produces clean results for a safe config', () => {
    const result = scanner.scan(SAFE_AGENT);
    assert.ok(result.riskScore <= 15, `Expected low risk score, got ${result.riskScore}`);
    assert.equal(result.grade, 'A');
  });

  it('sorts findings by severity', () => {
    const result = scanner.scan(DANGEROUS_AGENT);
    const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
    for (let i = 1; i < result.findings.length; i++) {
      const prev = severityOrder.indexOf(result.findings[i - 1].severity);
      const curr = severityOrder.indexOf(result.findings[i].severity);
      assert.ok(prev <= curr, 'Findings not sorted by severity');
    }
  });

  it('includes scan date', () => {
    const result = scanner.scan(SAFE_AGENT);
    assert.ok(result.scanDate.includes('T'));
  });
});

describe('Tool Analyzer', () => {
  it('detects shell + network combo', () => {
    const findings = analyzeTools([{
      name: 'uber-tool',
      description: 'Does everything',
      capabilities: ['shell_execute', 'network_request'],
    }]);
    assert.ok(findings.some((f) => f.category === 'data-exfiltration'));
  });

  it('detects overly broad parameters', () => {
    const findings = analyzeTools([{
      name: 'runner',
      description: 'Run commands',
      parameters: { command: { type: 'string' }, url: { type: 'string' } },
      capabilities: ['shell_execute'],
    }]);
    assert.ok(findings.some((f) => f.category === 'broad-parameters'));
  });

  it('detects too many capabilities', () => {
    const findings = analyzeTools([{
      name: 'god-tool',
      description: 'Everything',
      capabilities: ['shell_execute', 'network_request', 'file_read', 'file_write', 'credential_access'],
    }]);
    assert.ok(findings.some((f) => f.category === 'least-privilege'));
  });

  it('returns no findings for minimal tool', () => {
    const findings = analyzeTools([{
      name: 'reader',
      description: 'Read files',
      capabilities: ['file_read'],
    }]);
    assert.equal(findings.length, 0);
  });
});

describe('MCP Analyzer', () => {
  it('flags stdio transport', () => {
    const findings = analyzeMCPServers([{
      name: 'test-server',
      transport: 'stdio',
    }]);
    assert.ok(findings.some((f) => f.category === 'transport-security'));
  });

  it('flags known vulnerable servers', () => {
    const findings = analyzeMCPServers([{
      name: 'filesystem-server',
      command: 'npx @modelcontextprotocol/server-filesystem /',
      transport: 'stdio',
    }]);
    assert.ok(findings.some((f) => f.category === 'known-risk'));
  });

  it('flags sensitive env vars', () => {
    const findings = analyzeMCPServers([{
      name: 'api-server',
      transport: 'sse',
      env: { API_SECRET_KEY: 'test' },
    }]);
    assert.ok(findings.some((f) => f.category === 'secret-exposure'));
  });
});

describe('Env Analyzer', () => {
  it('detects known secret patterns', () => {
    const findings = analyzeEnvVars({ OPENAI_API_KEY: 'sk-test', APP_NAME: 'test' });
    assert.ok(findings.some((f) => f.title.includes('AI API key')));
    assert.equal(findings.filter((f) => f.title.includes('APP_NAME')).length, 0);
  });

  it('returns empty for safe env vars', () => {
    const findings = analyzeEnvVars({ NODE_ENV: 'production', PORT: '3000' });
    assert.equal(findings.length, 0);
  });
});

describe('Permission Analyzer', () => {
  it('flags root filesystem access', () => {
    const findings = analyzePermissions(
      [{ name: 'tool', description: '', capabilities: ['file_read'] }],
      { fileSystemPaths: ['/'] },
    );
    assert.ok(findings.some((f) => f.title.includes('Root filesystem')));
  });

  it('flags shell without approval', () => {
    const findings = analyzePermissions(
      [{ name: 'tool', description: '', capabilities: ['shell_execute'] }],
      { requireApproval: [] },
    );
    assert.ok(findings.some((f) => f.category === 'missing-approval'));
  });

  it('flags no permissions at all', () => {
    const findings = analyzePermissions(
      [{ name: 'tool', description: '', capabilities: ['file_read'] }],
    );
    assert.ok(findings.some((f) => f.category === 'no-permissions'));
  });
});

describe('Risk Scorer', () => {
  it('calculates correct scores', () => {
    assert.equal(calculateRiskScore([]), 0);
    assert.equal(calculateRiskScore([
      { id: '1', severity: 'critical', category: '', title: '', description: '', remediation: '' },
    ]), 25);
    assert.equal(calculateRiskScore([
      { id: '1', severity: 'high', category: '', title: '', description: '', remediation: '' },
      { id: '2', severity: 'medium', category: '', title: '', description: '', remediation: '' },
    ]), 23);
  });

  it('caps at 100', () => {
    const many = Array.from({ length: 10 }, (_, i) => ({
      id: String(i), severity: 'critical' as const, category: '', title: '', description: '', remediation: '',
    }));
    assert.equal(calculateRiskScore(many), 100);
  });

  it('assigns correct grades', () => {
    assert.equal(calculateGrade(0), 'A');
    assert.equal(calculateGrade(15), 'A');
    assert.equal(calculateGrade(16), 'B');
    assert.equal(calculateGrade(35), 'B');
    assert.equal(calculateGrade(55), 'C');
    assert.equal(calculateGrade(75), 'D');
    assert.equal(calculateGrade(76), 'F');
    assert.equal(calculateGrade(100), 'F');
  });
});
