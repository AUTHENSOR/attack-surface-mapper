import { describe, it, expect } from 'vitest';
import { mcpAnalyzer } from '../src/analyzers/mcp-analyzer.js';
import type { AgentConfig } from '../src/types.js';

function makeConfig(overrides: Partial<AgentConfig> = {}): AgentConfig {
  return {
    name: 'test-agent',
    tools: [],
    ...overrides,
  };
}

describe('MCP Analyzer', () => {
  it('returns no findings when there are no MCP servers', () => {
    const findings = mcpAnalyzer.analyze(makeConfig());
    expect(findings).toHaveLength(0);
  });

  it('detects known risky MCP servers by name', () => {
    const config = makeConfig({
      mcpServers: [
        {
          name: 'shell-executor',
          command: 'node',
          args: ['shell-server.js'],
          transport: 'stdio',
        },
      ],
    });
    const findings = mcpAnalyzer.analyze(config);
    const risky = findings.filter((f) => f.category === 'mcp:risky-server');
    expect(risky.length).toBeGreaterThan(0);
    expect(risky[0].severity).toBe('critical');
  });

  it('detects "everything" MCP server', () => {
    const config = makeConfig({
      mcpServers: [
        {
          name: 'everything',
          command: 'npx',
          args: ['-y', '@mcp/everything'],
          transport: 'stdio',
        },
      ],
    });
    const findings = mcpAnalyzer.analyze(config);
    const risky = findings.filter((f) => f.category === 'mcp:risky-server');
    expect(risky.length).toBeGreaterThan(0);
  });

  it('flags stdio transport', () => {
    const config = makeConfig({
      mcpServers: [
        {
          name: 'my-server',
          command: 'node',
          args: ['server.js'],
          transport: 'stdio',
        },
      ],
    });
    const findings = mcpAnalyzer.analyze(config);
    const stdio = findings.filter((f) => f.category === 'mcp:stdio-transport');
    expect(stdio.length).toBe(1);
    expect(stdio[0].severity).toBe('medium');
  });

  it('flags missing auth on HTTP/SSE transport', () => {
    const config = makeConfig({
      mcpServers: [
        {
          name: 'api-server',
          url: 'https://api.example.com',
          transport: 'sse',
          // No authentication
        },
      ],
    });
    const findings = mcpAnalyzer.analyze(config);
    const noAuth = findings.filter((f) => f.category === 'mcp:no-auth');
    expect(noAuth.length).toBe(1);
    expect(noAuth[0].severity).toBe('high');
  });

  it('does not flag auth issue when authentication is configured', () => {
    const config = makeConfig({
      mcpServers: [
        {
          name: 'api-server',
          url: 'https://api.example.com',
          transport: 'sse',
          authentication: { type: 'bearer', token: 'xxx' },
        },
      ],
    });
    const findings = mcpAnalyzer.analyze(config);
    const noAuth = findings.filter((f) => f.category === 'mcp:no-auth');
    expect(noAuth.length).toBe(0);
  });

  it('flags secrets in MCP server env vars', () => {
    const config = makeConfig({
      mcpServers: [
        {
          name: 'db-server',
          command: 'node',
          args: ['db.js'],
          transport: 'stdio',
          env: {
            DATABASE_URL: 'postgres://user:pass@localhost/db',
            APP_NAME: 'test',
          },
        },
      ],
    });
    const findings = mcpAnalyzer.analyze(config);
    const secrets = findings.filter((f) => f.category === 'mcp:env-secrets');
    expect(secrets.length).toBeGreaterThan(0);
    expect(secrets[0].evidence).toContain('DATABASE_URL');
  });

  it('flags excessive tools on a single server', () => {
    const tools = Array.from({ length: 25 }, (_, i) => ({
      name: `tool-${i}`,
      description: `Tool ${i}`,
      capabilities: [] as const,
    }));
    const config = makeConfig({
      mcpServers: [
        {
          name: 'mega-server',
          command: 'node',
          args: ['mega.js'],
          transport: 'stdio',
          tools: [...tools],
        },
      ],
    });
    const findings = mcpAnalyzer.analyze(config);
    const excessive = findings.filter(
      (f) => f.category === 'mcp:excessive-tools',
    );
    expect(excessive.length).toBe(1);
  });

  it('includes OWASP mapping on findings', () => {
    const config = makeConfig({
      mcpServers: [
        {
          name: 'shell-server',
          command: 'bash',
          transport: 'stdio',
        },
      ],
    });
    const findings = mcpAnalyzer.analyze(config);
    const mapped = findings.filter((f) => f.owaspMapping);
    expect(mapped.length).toBeGreaterThan(0);
  });
});
