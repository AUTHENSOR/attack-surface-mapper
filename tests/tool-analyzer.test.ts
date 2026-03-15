import { describe, it, expect } from 'vitest';
import { toolAnalyzer } from '../src/analyzers/tool-analyzer.js';
import type { AgentConfig, Capability } from '../src/types.js';

function makeConfig(overrides: Partial<AgentConfig> = {}): AgentConfig {
  return {
    name: 'test-agent',
    tools: [],
    ...overrides,
  };
}

describe('Tool Analyzer', () => {
  it('returns no findings for tools with no capabilities', () => {
    const config = makeConfig({
      tools: [
        { name: 'calculator', description: 'Math', capabilities: [] },
      ],
    });
    const findings = toolAnalyzer.analyze(config);
    expect(findings).toHaveLength(0);
  });

  it('detects dangerous combo: shell_execute + network_request in one tool', () => {
    const config = makeConfig({
      tools: [
        {
          name: 'super-tool',
          description: 'Does everything',
          capabilities: ['shell_execute', 'network_request'],
        },
      ],
    });
    const findings = toolAnalyzer.analyze(config);
    const combos = findings.filter((f) => f.category === 'tool:dangerous-combo');
    expect(combos.length).toBeGreaterThan(0);
    expect(combos[0].severity).toBe('critical');
  });

  it('detects dangerous combo across tools (cross-tool)', () => {
    const config = makeConfig({
      tools: [
        {
          name: 'shell-tool',
          description: 'Shell',
          capabilities: ['shell_execute'],
        },
        {
          name: 'net-tool',
          description: 'Network',
          capabilities: ['network_request'],
        },
      ],
    });
    const findings = toolAnalyzer.analyze(config);
    const crossTool = findings.filter(
      (f) => f.category === 'tool:dangerous-combo' && f.title.startsWith('Cross-tool'),
    );
    expect(crossTool.length).toBeGreaterThan(0);
  });

  it('flags shell_execute capability', () => {
    const config = makeConfig({
      tools: [
        {
          name: 'terminal',
          description: 'Run commands',
          capabilities: ['shell_execute'],
        },
      ],
    });
    const findings = toolAnalyzer.analyze(config);
    const shell = findings.filter((f) => f.category === 'tool:shell-execute');
    expect(shell.length).toBe(1);
  });

  it('flags overly broad parameters (command)', () => {
    const config = makeConfig({
      tools: [
        {
          name: 'exec',
          description: 'Execute',
          parameters: { command: { type: 'string' } },
          capabilities: ['shell_execute'],
        },
      ],
    });
    const findings = toolAnalyzer.analyze(config);
    const broad = findings.filter(
      (f) => f.category === 'tool:overly-broad-params',
    );
    expect(broad.length).toBeGreaterThan(0);
  });

  it('does not flag parameters with enum constraints', () => {
    const config = makeConfig({
      tools: [
        {
          name: 'exec',
          description: 'Execute',
          parameters: {
            command: { type: 'string', enum: ['ls', 'pwd', 'whoami'] },
          },
          capabilities: ['shell_execute'],
        },
      ],
    });
    const findings = toolAnalyzer.analyze(config);
    const broad = findings.filter(
      (f) => f.category === 'tool:overly-broad-params',
    );
    expect(broad.length).toBe(0);
  });

  it('flags overloaded tools with 5+ capabilities', () => {
    const caps: Capability[] = [
      'file_read',
      'file_write',
      'shell_execute',
      'network_request',
      'database_query',
    ];
    const config = makeConfig({
      tools: [
        {
          name: 'god-tool',
          description: 'All in one',
          capabilities: caps,
        },
      ],
    });
    const findings = toolAnalyzer.analyze(config);
    const overloaded = findings.filter(
      (f) => f.category === 'tool:single-tool-overloaded',
    );
    expect(overloaded.length).toBe(1);
  });

  it('includes MCP server tools in analysis', () => {
    const config = makeConfig({
      tools: [],
      mcpServers: [
        {
          name: 'my-server',
          command: 'node',
          args: ['server.js'],
          transport: 'stdio',
          tools: [
            {
              name: 'mcp-shell',
              description: 'Shell via MCP',
              capabilities: ['shell_execute'],
            },
          ],
        },
      ],
    });
    const findings = toolAnalyzer.analyze(config);
    const shell = findings.filter((f) => f.category === 'tool:shell-execute');
    expect(shell.length).toBe(1);
    expect(shell[0].tool).toBe('mcp-shell');
  });
});
