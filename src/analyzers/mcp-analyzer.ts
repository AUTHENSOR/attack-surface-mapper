import type { MCPServerConfig, Finding } from '../types.js';

const KNOWN_VULNERABLE_SERVERS = [
  { pattern: /filesystem/i, issue: 'Filesystem server grants broad file access', severity: 'medium' as const },
  { pattern: /everything/i, issue: 'Everything server exposes all capabilities', severity: 'critical' as const },
  { pattern: /shell|terminal|exec/i, issue: 'Shell server enables arbitrary command execution', severity: 'critical' as const },
  { pattern: /puppeteer|playwright|browser/i, issue: 'Browser server enables web interaction and data access', severity: 'high' as const },
  { pattern: /database|postgres|mysql|sqlite/i, issue: 'Database server enables arbitrary queries', severity: 'high' as const },
];

export function analyzeMCPServers(servers: MCPServerConfig[]): Finding[] {
  const findings: Finding[] = [];
  let idx = 0;

  for (const server of servers) {
    // Check transport security
    if (server.transport === 'stdio') {
      findings.push({
        id: `MCP-${String(++idx).padStart(3, '0')}`,
        severity: 'medium',
        category: 'transport-security',
        title: `${server.name}: stdio transport has no authentication`,
        description: `MCP server "${server.name}" uses stdio transport, which provides no authentication or authorization mechanism. Any process that can spawn the server can invoke its tools.`,
        tool: server.name,
        owaspMapping: 'ASI03',
        remediation: 'Use SSE or HTTP transport with token-based authentication, or place behind an Authensor MCP Gateway.',
      });
    }

    // Check for known high-risk servers
    const serverIdentifier = `${server.name} ${server.command ?? ''} ${server.url ?? ''}`;
    for (const vuln of KNOWN_VULNERABLE_SERVERS) {
      if (vuln.pattern.test(serverIdentifier)) {
        findings.push({
          id: `MCP-${String(++idx).padStart(3, '0')}`,
          severity: vuln.severity,
          category: 'known-risk',
          title: `${server.name}: ${vuln.issue}`,
          description: `MCP server "${server.name}" matches a known high-risk server pattern. ${vuln.issue}.`,
          tool: server.name,
          owaspMapping: 'ASI04',
          remediation: 'Place behind an Authensor MCP Gateway with restrictive policies. Limit tool access to required operations only.',
        });
      }
    }

    // Check for exposed environment variables
    if (server.env) {
      const sensitivePatterns = [/key/i, /secret/i, /token/i, /password/i, /credential/i];
      for (const [envKey] of Object.entries(server.env)) {
        if (sensitivePatterns.some((p) => p.test(envKey))) {
          findings.push({
            id: `MCP-${String(++idx).padStart(3, '0')}`,
            severity: 'high',
            category: 'secret-exposure',
            title: `${server.name}: Sensitive env var "${envKey}" passed to MCP server`,
            description: `Environment variable "${envKey}" appears to contain sensitive data and is passed to MCP server "${server.name}". If the server is compromised or has logging enabled, this credential could be leaked.`,
            tool: server.name,
            owaspMapping: 'ASI04',
            remediation: 'Use a secrets manager. Never pass credentials directly in MCP server configuration.',
          });
        }
      }
    }

    // Check for missing tool restrictions
    if (!server.tools || server.tools.length === 0) {
      findings.push({
        id: `MCP-${String(++idx).padStart(3, '0')}`,
        severity: 'medium',
        category: 'unrestricted-access',
        title: `${server.name}: No tool allowlist configured`,
        description: `MCP server "${server.name}" has no tool allowlist. All tools exposed by the server are available to the agent.`,
        tool: server.name,
        owaspMapping: 'ASI02',
        remediation: 'Configure an explicit tool allowlist to limit available tools to those required.',
      });
    }
  }

  return findings;
}
