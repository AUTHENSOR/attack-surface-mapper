import type { ToolDefinition, Finding, Capability } from '../types.js';

const DANGEROUS_COMBOS: { caps: Capability[]; finding: Omit<Finding, 'id' | 'tool'> }[] = [
  {
    caps: ['shell_execute', 'network_request'],
    finding: {
      severity: 'critical',
      category: 'data-exfiltration',
      title: 'Shell + network access enables data exfiltration',
      description: 'A tool with both shell execution and network access can pipe arbitrary data to external endpoints.',
      owaspMapping: 'ASI02',
      remediation: 'Separate shell and network capabilities into distinct tools with individual approval requirements.',
    },
  },
  {
    caps: ['credential_access', 'network_request'],
    finding: {
      severity: 'critical',
      category: 'credential-theft',
      title: 'Credential access + network enables credential exfiltration',
      description: 'Credentials can be read and sent to external endpoints in a single tool invocation.',
      owaspMapping: 'ASI03',
      remediation: 'Never combine credential access with network capabilities. Use separate tools with approval workflows.',
    },
  },
  {
    caps: ['file_read', 'network_request'],
    finding: {
      severity: 'high',
      category: 'data-exfiltration',
      title: 'File read + network enables file exfiltration',
      description: 'Arbitrary files can be read and transmitted to external endpoints.',
      owaspMapping: 'ASI02',
      remediation: 'Restrict file read to specific directories. Add network egress allowlist.',
    },
  },
  {
    caps: ['shell_execute', 'file_delete'],
    finding: {
      severity: 'high',
      category: 'destructive-action',
      title: 'Shell + file delete enables destructive operations',
      description: 'Combination allows recursive deletion, disk wiping, or system damage.',
      owaspMapping: 'ASI02',
      remediation: 'Require human approval for all destructive operations.',
    },
  },
  {
    caps: ['code_execute', 'system_config'],
    finding: {
      severity: 'critical',
      category: 'privilege-escalation',
      title: 'Code execution + system config enables privilege escalation',
      description: 'Arbitrary code can modify system configuration, potentially escalating privileges.',
      owaspMapping: 'ASI05',
      remediation: 'Sandbox code execution. Never allow system config changes without multi-party approval.',
    },
  },
  {
    caps: ['payment_process', 'code_execute'],
    finding: {
      severity: 'critical',
      category: 'financial-risk',
      title: 'Payment + code execution enables unauthorized transactions',
      description: 'Arbitrary code can trigger financial transactions without human oversight.',
      owaspMapping: 'ASI02',
      remediation: 'Always require human approval for payment operations. Never combine with code execution.',
    },
  },
];

const OVERLY_BROAD_PARAMS = [
  { pattern: /command|cmd|shell|exec/i, severity: 'high' as const, issue: 'Accepts arbitrary shell commands' },
  { pattern: /url|endpoint|host/i, severity: 'medium' as const, issue: 'Accepts arbitrary URLs/endpoints' },
  { pattern: /query|sql/i, severity: 'high' as const, issue: 'Accepts arbitrary database queries' },
  { pattern: /path|file|directory/i, severity: 'medium' as const, issue: 'Accepts arbitrary file paths' },
  { pattern: /code|script|eval/i, severity: 'high' as const, issue: 'Accepts arbitrary code for execution' },
];

export function analyzeTools(tools: ToolDefinition[]): Finding[] {
  const findings: Finding[] = [];
  let findingIdx = 0;

  for (const tool of tools) {
    // Check dangerous capability combinations within a single tool
    for (const combo of DANGEROUS_COMBOS) {
      if (combo.caps.every((c) => tool.capabilities.includes(c))) {
        findings.push({
          ...combo.finding,
          id: `TOOL-${String(++findingIdx).padStart(3, '0')}`,
          tool: tool.name,
        });
      }
    }

    // Check overly broad parameters
    if (tool.parameters) {
      for (const [paramName] of Object.entries(tool.parameters)) {
        for (const check of OVERLY_BROAD_PARAMS) {
          if (check.pattern.test(paramName)) {
            findings.push({
              id: `TOOL-${String(++findingIdx).padStart(3, '0')}`,
              severity: check.severity,
              category: 'broad-parameters',
              title: `${tool.name}: ${check.issue}`,
              description: `Parameter "${paramName}" in tool "${tool.name}" ${check.issue.toLowerCase()}. This could be exploited via prompt injection to execute unintended operations.`,
              tool: tool.name,
              owaspMapping: 'ASI01',
              remediation: `Constrain the "${paramName}" parameter to an allowlist of permitted values.`,
            });
          }
        }
      }
    }

    // Check for tools with too many capabilities (least privilege violation)
    if (tool.capabilities.length >= 4) {
      findings.push({
        id: `TOOL-${String(++findingIdx).padStart(3, '0')}`,
        severity: 'medium',
        category: 'least-privilege',
        title: `${tool.name}: Too many capabilities (${tool.capabilities.length})`,
        description: `Tool "${tool.name}" has ${tool.capabilities.length} capabilities. This violates the principle of least privilege and increases the blast radius if the tool is misused.`,
        tool: tool.name,
        owaspMapping: 'ASI03',
        remediation: 'Split into multiple focused tools, each with minimal required capabilities.',
      });
    }
  }

  return findings;
}
