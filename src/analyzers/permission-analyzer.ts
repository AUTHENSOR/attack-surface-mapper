import type { ToolDefinition, PermissionSet, Finding } from '../types.js';

const SENSITIVE_PATHS = [
  { pattern: /^\/etc\b/i, name: 'System config (/etc)', severity: 'critical' as const },
  { pattern: /^\/root\b|^~\/\.ssh\b|\.ssh\b/i, name: 'SSH keys', severity: 'critical' as const },
  { pattern: /\.env\b|\.env\./i, name: 'Environment files', severity: 'high' as const },
  { pattern: /^\/var\/log\b/i, name: 'System logs', severity: 'medium' as const },
  { pattern: /^\/proc\b|^\/sys\b/i, name: 'Kernel interfaces', severity: 'high' as const },
  { pattern: /\.git\b/i, name: 'Git repository data', severity: 'medium' as const },
  { pattern: /node_modules\b/i, name: 'Dependencies directory', severity: 'low' as const },
  { pattern: /^\/$|^\/\*$/, name: 'Root filesystem', severity: 'critical' as const },
];

const DANGEROUS_CAPS_WITHOUT_APPROVAL: { cap: string; severity: 'critical' | 'high'; name: string }[] = [
  { cap: 'shell_execute', severity: 'critical', name: 'Shell execution' },
  { cap: 'payment_process', severity: 'critical', name: 'Payment processing' },
  { cap: 'file_delete', severity: 'high', name: 'File deletion' },
  { cap: 'system_config', severity: 'high', name: 'System configuration' },
  { cap: 'credential_access', severity: 'critical', name: 'Credential access' },
];

export function analyzePermissions(tools: ToolDefinition[], permissions?: PermissionSet): Finding[] {
  const findings: Finding[] = [];
  let idx = 0;

  // Check filesystem paths
  if (permissions?.fileSystemPaths) {
    for (const path of permissions.fileSystemPaths) {
      for (const sp of SENSITIVE_PATHS) {
        if (sp.pattern.test(path)) {
          findings.push({
            id: `PERM-${String(++idx).padStart(3, '0')}`,
            severity: sp.severity,
            category: 'filesystem-exposure',
            title: `Access to ${sp.name}: ${path}`,
            description: `Agent has access to "${path}" which includes ${sp.name}. This is a high-value target for data exfiltration or system compromise.`,
            owaspMapping: 'ASI03',
            remediation: `Restrict filesystem access to the minimum required paths. Remove access to "${path}".`,
          });
          break;
        }
      }
    }
  }

  // Check for dangerous capabilities without approval requirement
  const allCaps = new Set(tools.flatMap((t) => t.capabilities));
  const approvalRequired = new Set(permissions?.requireApproval ?? []);

  for (const check of DANGEROUS_CAPS_WITHOUT_APPROVAL) {
    if (allCaps.has(check.cap as any) && !approvalRequired.has(check.cap as any)) {
      findings.push({
        id: `PERM-${String(++idx).padStart(3, '0')}`,
        severity: check.severity,
        category: 'missing-approval',
        title: `${check.name} allowed without human approval`,
        description: `The agent can perform ${check.name.toLowerCase()} without requiring human approval. This is a high-risk capability that should require explicit authorization.`,
        owaspMapping: 'ASI09',
        remediation: `Add "${check.cap}" to the requireApproval list in permissions.`,
      });
    }
  }

  // No permissions at all
  if (!permissions) {
    findings.push({
      id: `PERM-${String(++idx).padStart(3, '0')}`,
      severity: 'high',
      category: 'no-permissions',
      title: 'No permission boundaries configured',
      description: 'The agent has no explicit permission boundaries. All tool capabilities are unrestricted.',
      owaspMapping: 'ASI03',
      remediation: 'Define explicit permissions including filesystem paths, network allowlists, and approval requirements.',
    });
  }

  return findings;
}
