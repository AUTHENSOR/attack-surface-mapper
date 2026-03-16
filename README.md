# Attack Surface Mapper

**Security and compliance scanner for AI agents.**

Analyzes your AI agent's configuration and tells you two things: where the security gaps are, and whether you meet EU AI Act requirements. Maps every finding to OWASP Agentic Top 10 and EU AI Act Articles 9, 12, 13, 14, and 15. Outputs SARIF for GitHub Security integration.

Zero dependencies. Single binary. MIT licensed.

## Quick Start

```bash
npx @15rl/attack-surface-mapper agent-config.json
```

## What You Get

```
Attack Surface Report: production-agent
Scanned: 2026-03-15T10:00:00.000Z

Risk Score: 78/100 (Grade: F)

Attack Surface
  Tools: 4
  Capabilities:
    shell_execute: 1 tool(s)
    network_request: 2 tool(s)
    credential_access: 1 tool(s)
  Critical paths:
    shell_execute -> network_request
    credential_access -> network_request

Findings (12)

  CRITICAL Shell + network access enables data exfiltration [ASI02: Tool Misuse]
  Fix: Separate shell and network capabilities into distinct tools.

  CRITICAL Credential access + network enables credential exfiltration [ASI03]
  Fix: Never combine credential access with network capabilities.
  ...

EU AI Act Compliance
  Status: NON-COMPLIANT
  Deadline: 2026-08-02
  Articles: 1 pass, 1 warning, 3 fail

  FAIL Article 9: Risk Management System
    Data exfiltration paths exist. Risk assessment must identify and mitigate data loss vectors.
    Dangerous capabilities lack approval requirements.

  FAIL Article 14: Human Oversight
    Dangerous operations proceed without human approval. Article 14 requires intervention
    capability for high-risk actions.

  FAIL Article 15: Accuracy, Robustness, Cybersecurity
    Credentials exposed to the agent. SSRF potential exists. No network egress controls.

  WARN Article 12: Record-Keeping
    MCP stdio transport has no authentication.

  PASS Article 13: Transparency
    Tool parameters are constrained. Tools follow least-privilege.
```

## EU AI Act Coverage

The scanner assesses agent configurations against five articles that apply to high-risk AI systems. The compliance deadline is August 2, 2026.

| Article | Requirement | What We Check |
|---------|-------------|---------------|
| **Article 9** | Risk Management | Permission boundaries, approval requirements, exfiltration paths, capability chaining |
| **Article 12** | Record-Keeping | Tool allowlists, transport authentication, audit trail support |
| **Article 13** | Transparency | Parameter constraints, capability scope, least-privilege adherence |
| **Article 14** | Human Oversight | Approval workflows for dangerous operations, intervention mechanisms |
| **Article 15** | Cybersecurity | Secret exposure, known vulnerabilities, SSRF vectors, egress controls |

## OWASP Agentic Top 10 Mapping

Every finding also maps to the OWASP Top 10 for Agentic Applications (2026):

| ID | Name | What We Check |
|----|------|---------------|
| ASI01 | Agent Goal Hijacking | Broad parameters accepting arbitrary input |
| ASI02 | Tool Misuse | Dangerous capability combos, unrestricted egress |
| ASI03 | Identity and Privilege Abuse | Credential exposure, missing permissions, excessive access |
| ASI04 | Supply Chain Vulnerabilities | Known vulnerable MCP servers, secret leakage to third parties |
| ASI05 | Unexpected Code Execution | Code execution + system config combos |
| ASI09 | Human-Agent Trust Exploitation | Missing approval requirements for dangerous ops |

## Security Analyzers

| Analyzer | Checks |
|----------|--------|
| **Tool** | Dangerous capability combos, overly broad parameters, least privilege violations |
| **MCP** | Transport security, known vulnerable servers, secret exposure, missing tool allowlists |
| **Environment** | Exposed API keys, database credentials, payment secrets |
| **Network** | Unrestricted egress, SSRF potential, data exfiltration paths |
| **Permissions** | Sensitive path access, missing approval requirements, no boundaries |

## Config File Format

```json
{
  "name": "my-agent",
  "tools": [
    {
      "name": "run-command",
      "description": "Execute shell commands",
      "parameters": { "command": { "type": "string" } },
      "capabilities": ["shell_execute"]
    }
  ],
  "mcpServers": [
    {
      "name": "filesystem",
      "command": "npx @modelcontextprotocol/server-filesystem /tmp",
      "transport": "stdio"
    }
  ],
  "envVars": {
    "OPENAI_API_KEY": "sk-..."
  },
  "permissions": {
    "fileSystemPaths": ["/app", "/tmp"],
    "networkAllowList": ["api.openai.com"],
    "requireApproval": ["shell_execute", "payment_process"]
  }
}
```

## Output Formats

```bash
asm config.json                    # Terminal (default, colored)
asm config.json --json             # JSON (includes compliance report)
asm config.json --format markdown  # Markdown table
asm config.json --sarif            # SARIF for GitHub Security tab
```

## Programmatic Usage

```typescript
import { AttackSurfaceScanner } from '@15rl/attack-surface-mapper';

const scanner = new AttackSurfaceScanner();
const result = scanner.scan(agentConfig);

console.log(`Grade: ${result.grade}`);
console.log(`EU AI Act: ${result.compliance.overallStatus}`);
console.log(`Articles failing: ${result.compliance.failCount}`);
```

## Part of the Authensor Ecosystem

This project is part of the [Authensor](https://github.com/AUTHENSOR/AUTHENSOR) open-source AI safety ecosystem, built by [15 Research Lab](https://github.com/15-Research-Lab).

| Project | Description |
|---------|-------------|
| [Authensor](https://github.com/AUTHENSOR/AUTHENSOR) | The open-source safety stack for AI agents |
| [Prompt Injection Benchmark](https://github.com/AUTHENSOR/prompt-injection-benchmark) | Standardized benchmark for safety scanners |
| [AI SecLists](https://github.com/AUTHENSOR/ai-seclists) | Security wordlists and payloads for AI/LLM testing |
| [ATT&CK to Alignment Rosetta](https://github.com/AUTHENSOR/attack-alignment-rosetta) | Maps MITRE ATT&CK to AI alignment concepts |
| [Agent Forensics](https://github.com/AUTHENSOR/agent-forensics) | Post-incident analysis for receipt chains |
| [Behavioral Fingerprinting](https://github.com/AUTHENSOR/behavioral-fingerprinting) | Statistical behavioral drift detection |
| [Hawthorne Protocol](https://github.com/AUTHENSOR/hawthorne-protocol) | Can AI systems detect when they're being evaluated? |

## License

MIT
