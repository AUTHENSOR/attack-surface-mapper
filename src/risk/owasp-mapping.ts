export const OWASP_AGENTIC: Record<string, { id: string; name: string; description: string }> = {
  ASI01: {
    id: 'ASI01',
    name: 'Agent Goal Hijacking',
    description: 'Prompt injection or context manipulation redirects the agent to unintended goals.',
  },
  ASI02: {
    id: 'ASI02',
    name: 'Tool Misuse',
    description: 'Agent uses tools in unintended or harmful ways, either through manipulation or misconfiguration.',
  },
  ASI03: {
    id: 'ASI03',
    name: 'Identity & Privilege Abuse',
    description: 'Agent operates with excessive privileges or impersonates other identities.',
  },
  ASI04: {
    id: 'ASI04',
    name: 'Supply Chain Vulnerabilities',
    description: 'Third-party tools, plugins, or MCP servers introduce security risks.',
  },
  ASI05: {
    id: 'ASI05',
    name: 'Unexpected Code Execution',
    description: 'Agent executes arbitrary code without proper sandboxing or approval.',
  },
  ASI06: {
    id: 'ASI06',
    name: 'Memory & Context Poisoning',
    description: 'Adversarial data injected into agent memory or context influences future decisions.',
  },
  ASI07: {
    id: 'ASI07',
    name: 'Insecure Inter-Agent Communication',
    description: 'Multi-agent systems lack authentication or integrity checks between agents.',
  },
  ASI08: {
    id: 'ASI08',
    name: 'Cascading Failures',
    description: 'Failure in one agent or tool propagates to cause system-wide failures.',
  },
  ASI09: {
    id: 'ASI09',
    name: 'Human-Agent Trust Exploitation',
    description: 'Agent exploits human trust to bypass approval workflows or override safety controls.',
  },
  ASI10: {
    id: 'ASI10',
    name: 'Rogue Agents',
    description: 'Agent operates outside defined boundaries without detection or kill-switch capability.',
  },
};

export function getOwaspName(id: string): string {
  return OWASP_AGENTIC[id]?.name ?? id;
}
