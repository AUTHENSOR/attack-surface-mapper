import type { ToolDefinition, PermissionSet, Finding, DataFlow } from '../types.js';

export function analyzeNetwork(tools: ToolDefinition[], permissions?: PermissionSet): { findings: Finding[]; dataFlows: DataFlow[] } {
  const findings: Finding[] = [];
  const dataFlows: DataFlow[] = [];
  let idx = 0;

  const networkTools = tools.filter((t) => t.capabilities.includes('network_request'));

  // Check for unrestricted egress
  if (networkTools.length > 0 && (!permissions?.networkAllowList || permissions.networkAllowList.length === 0)) {
    findings.push({
      id: `NET-${String(++idx).padStart(3, '0')}`,
      severity: 'high',
      category: 'unrestricted-egress',
      title: 'No network egress allowlist configured',
      description: `${networkTools.length} tool(s) have network access with no egress restrictions. The agent can send data to any external endpoint.`,
      owaspMapping: 'ASI02',
      remediation: 'Configure a network allowlist limiting egress to known, required endpoints.',
    });
  }

  // Check for SSRF potential
  for (const tool of networkTools) {
    if (tool.parameters && Object.keys(tool.parameters).some((k) => /url|endpoint|host|target/i.test(k))) {
      findings.push({
        id: `NET-${String(++idx).padStart(3, '0')}`,
        severity: 'high',
        category: 'ssrf',
        title: `${tool.name}: SSRF potential — accepts arbitrary URLs`,
        description: `Tool "${tool.name}" accepts user-controlled URLs. An attacker could use prompt injection to make the agent send requests to internal services (SSRF).`,
        tool: tool.name,
        owaspMapping: 'ASI01',
        remediation: 'Validate URLs against an allowlist. Block requests to private IP ranges (10.x, 172.16.x, 192.168.x, 127.x).',
      });
    }
  }

  // Map data flows
  const dataReaders = tools.filter((t) =>
    t.capabilities.some((c) => ['file_read', 'database_query', 'user_data_access', 'credential_access'].includes(c))
  );
  const dataSenders = tools.filter((t) =>
    t.capabilities.some((c) => ['network_request', 'email_send'].includes(c))
  );

  for (const reader of dataReaders) {
    for (const sender of dataSenders) {
      const dataType = reader.capabilities.includes('credential_access') ? 'credentials' :
        reader.capabilities.includes('user_data_access') ? 'user data' :
        reader.capabilities.includes('database_query') ? 'database records' : 'files';

      dataFlows.push({
        source: reader.name,
        destination: sender.name,
        dataType,
        risk: dataType === 'credentials' ? 'critical' : 'high',
      });
    }
  }

  if (dataFlows.length > 0) {
    findings.push({
      id: `NET-${String(++idx).padStart(3, '0')}`,
      severity: dataFlows.some((f) => f.risk === 'critical') ? 'critical' : 'high',
      category: 'data-exfiltration-path',
      title: `${dataFlows.length} potential data exfiltration path(s) detected`,
      description: `Data can flow from read-capable tools to network-capable tools: ${dataFlows.map((f) => `${f.source} → ${f.destination} (${f.dataType})`).join('; ')}`,
      owaspMapping: 'ASI02',
      remediation: 'Add policy rules requiring approval for data transfers between read and send tools.',
    });
  }

  return { findings, dataFlows };
}
