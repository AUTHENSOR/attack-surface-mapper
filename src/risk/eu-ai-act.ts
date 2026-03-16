/**
 * EU AI Act Compliance Mapping
 *
 * Maps attack surface findings to EU AI Act requirements for high-risk
 * AI systems. Relevant articles: 9 (risk management), 12 (record-keeping),
 * 13 (transparency), 14 (human oversight), 15 (accuracy and robustness).
 *
 * High-risk AI system requirements apply from August 2, 2026.
 */

export interface ComplianceRequirement {
  article: string;
  title: string;
  obligation: string;
  status: 'pass' | 'fail' | 'warning' | 'not_assessed';
  findings: string[];
  remediation: string;
}

export interface ComplianceReport {
  framework: string;
  version: string;
  deadline: string;
  overallStatus: 'compliant' | 'non_compliant' | 'partial';
  requirements: ComplianceRequirement[];
  passCount: number;
  failCount: number;
  warningCount: number;
}

export const EU_AI_ACT_ARTICLES: {
  article: string;
  title: string;
  obligation: string;
  checks: { findingCategory: string; failMessage: string; passMessage: string }[];
}[] = [
  {
    article: 'Article 9',
    title: 'Risk Management System',
    obligation: 'Establish and maintain a risk management system throughout the AI lifecycle. Identify and analyze known and foreseeable risks. Adopt suitable risk management measures.',
    checks: [
      {
        findingCategory: 'no-permissions',
        failMessage: 'No permission boundaries defined. Risk management requires explicit capability controls.',
        passMessage: 'Permission boundaries are configured.',
      },
      {
        findingCategory: 'missing-approval',
        failMessage: 'Dangerous capabilities lack approval requirements. High-risk operations must have human authorization controls.',
        passMessage: 'Dangerous capabilities require approval.',
      },
      {
        findingCategory: 'data-exfiltration',
        failMessage: 'Data exfiltration paths exist. Risk assessment must identify and mitigate data loss vectors.',
        passMessage: 'No unmitigated data exfiltration paths.',
      },
      {
        findingCategory: 'data-exfiltration-path',
        failMessage: 'Tool combinations enable data exfiltration. Risk management must address capability chaining.',
        passMessage: 'No dangerous tool capability chains.',
      },
    ],
  },
  {
    article: 'Article 12',
    title: 'Record-Keeping',
    obligation: 'High-risk AI systems shall support automatic recording of events (logs) for traceability. Logging must capture input/output data, decisions made, and system behavior.',
    checks: [
      {
        findingCategory: 'unrestricted-access',
        failMessage: 'MCP servers have no tool allowlists. Without tool-level access control, audit logging cannot attribute actions to authorized operations.',
        passMessage: 'Tool access is controlled via allowlists.',
      },
      {
        findingCategory: 'transport-security',
        failMessage: 'MCP stdio transport has no authentication. Unauthenticated channels cannot produce trustworthy audit records.',
        passMessage: 'Transport channels support authentication.',
      },
    ],
  },
  {
    article: 'Article 13',
    title: 'Transparency',
    obligation: 'High-risk AI systems shall be designed to allow deployers to interpret the system output and use it appropriately. Sufficient transparency for users to understand capabilities and limitations.',
    checks: [
      {
        findingCategory: 'broad-parameters',
        failMessage: 'Tools accept unconstrained parameters. Users and operators cannot predict or understand what operations the agent may perform.',
        passMessage: 'Tool parameters are constrained to defined values.',
      },
      {
        findingCategory: 'least-privilege',
        failMessage: 'Tools have excessive capabilities. When a single tool can perform many unrelated operations, the system behavior is opaque.',
        passMessage: 'Tools follow least-privilege with focused capabilities.',
      },
    ],
  },
  {
    article: 'Article 14',
    title: 'Human Oversight',
    obligation: 'High-risk AI systems shall be designed to allow effective oversight by natural persons. Include the ability to intervene, interrupt, or override the system.',
    checks: [
      {
        findingCategory: 'missing-approval',
        failMessage: 'Dangerous operations (shell execution, payments, credential access) proceed without human approval. Article 14 requires intervention capability for high-risk actions.',
        passMessage: 'Human approval is required for high-risk operations.',
      },
      {
        findingCategory: 'no-permissions',
        failMessage: 'No permission framework is configured. Without explicit boundaries, there is no mechanism for human oversight of agent actions.',
        passMessage: 'Permission framework enables oversight boundaries.',
      },
    ],
  },
  {
    article: 'Article 15',
    title: 'Accuracy, Robustness, Cybersecurity',
    obligation: 'High-risk AI systems shall achieve appropriate levels of accuracy, robustness, and cybersecurity. Resilient against errors, faults, or attempts at manipulation by unauthorized third parties.',
    checks: [
      {
        findingCategory: 'secret-exposure',
        failMessage: 'Credentials or secrets are exposed to the agent. Compromised credentials undermine system cybersecurity.',
        passMessage: 'No credentials exposed to agent environment.',
      },
      {
        findingCategory: 'known-risk',
        failMessage: 'Known vulnerable MCP servers are in use. System robustness requires vetted, secured components.',
        passMessage: 'No known vulnerable servers in use.',
      },
      {
        findingCategory: 'ssrf',
        failMessage: 'SSRF potential exists via unconstrained URL parameters. Agent could be manipulated to access internal services.',
        passMessage: 'URL parameters are constrained against SSRF.',
      },
      {
        findingCategory: 'credential-theft',
        failMessage: 'Credential access combined with network access enables exfiltration. This is a direct cybersecurity vulnerability.',
        passMessage: 'Credential and network capabilities are separated.',
      },
      {
        findingCategory: 'unrestricted-egress',
        failMessage: 'No network egress controls. Agent can communicate with arbitrary external endpoints.',
        passMessage: 'Network egress is restricted to known endpoints.',
      },
    ],
  },
];

export function assessCompliance(findingCategories: string[]): ComplianceReport {
  const categorySet = new Set(findingCategories);

  const requirements: ComplianceRequirement[] = EU_AI_ACT_ARTICLES.map((article) => {
    const failures: string[] = [];
    const passes: string[] = [];

    for (const check of article.checks) {
      if (categorySet.has(check.findingCategory)) {
        failures.push(check.failMessage);
      } else {
        passes.push(check.passMessage);
      }
    }

    const status: 'pass' | 'fail' | 'warning' =
      failures.length === 0 ? 'pass' :
      failures.length < article.checks.length ? 'warning' : 'fail';

    return {
      article: article.article,
      title: article.title,
      obligation: article.obligation,
      status,
      findings: failures.length > 0 ? failures : passes,
      remediation: failures.length > 0
        ? `Address ${failures.length} finding(s) to meet ${article.article} requirements.`
        : `${article.article} requirements are satisfied by current configuration.`,
    };
  });

  const passCount = requirements.filter((r) => r.status === 'pass').length;
  const failCount = requirements.filter((r) => r.status === 'fail').length;
  const warningCount = requirements.filter((r) => r.status === 'warning').length;

  const overallStatus: 'compliant' | 'non_compliant' | 'partial' =
    failCount > 0 ? 'non_compliant' :
    warningCount > 0 ? 'partial' : 'compliant';

  return {
    framework: 'EU AI Act (Regulation 2024/1689)',
    version: '2024',
    deadline: '2026-08-02',
    overallStatus,
    requirements,
    passCount,
    failCount,
    warningCount,
  };
}
