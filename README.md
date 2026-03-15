# Attack Surface Mapper

**Map the attack surface of your AI agents.**

A zero-dependency CLI tool and library that analyzes an AI agent's configuration -- tools, MCP servers, environment variables, permissions -- and maps out its security gaps. Think `nmap` for AI agent capabilities.

## Quick Start

```bash
npx @15rl/attack-surface-mapper agent-config.json
```

## Example Output

```
Attack Surface Report: my-agent
Scanned: 2026-03-15T10:00:00.000Z

Risk Score: 78/100 (Grade: F)

Attack Surface
  Tools: 4
  Capabilities:
    shell_execute: 1 tool(s)
    network_request: 2 tool(s)
    credential_access: 1 tool(s)
  Critical paths:
    shell_execute → network_request
    credential_access → network_request

Findings (12)

  CRITICAL Shell + network access enables data exfiltration [ASI02: Tool Misuse]
  A tool with both shell execution and network access can pipe arbitrary data to external endpoints.
  Fix: Separate shell and network capabilities into distinct tools with individual approval requirements.

  CRITICAL Credential access + network enables credential exfiltration [ASI03: Identity & Privilege Abuse]
  Credentials can be read and sent to external endpoints in a single tool invocation.
  Fix: Never combine credential access with network capabilities.

  HIGH No network egress allowlist configured [ASI02: Tool Misuse]
  2 tool(s) have network access with no egress restrictions.
  Fix: Configure a network allowlist limiting egress to known, required endpoints.
  ...
```

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
    },
    {
      "name": "read-file",
      "description": "Read files from disk",
      "capabilities": ["file_read"]
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
    "OPENAI_API_KEY": "sk-...",
    "APP_NAME": "my-app"
  },
  "permissions": {
    "fileSystemPaths": ["/app", "/tmp"],
    "networkAllowList": ["api.openai.com"],
    "requireApproval": ["shell_execute", "payment_process"]
  }
}
```

## What It Checks

| Analyzer | Checks |
|----------|--------|
| **Tool** | Dangerous capability combos, overly broad parameters, least privilege violations |
| **MCP** | Transport security, known vulnerable servers, secret exposure, missing tool allowlists |
| **Environment** | Exposed API keys, database credentials, payment secrets |
| **Network** | Unrestricted egress, SSRF potential, data exfiltration paths |
| **Permissions** | Sensitive path access, missing approval requirements, no boundaries |

## Output Formats

```bash
asm config.json                    # Terminal (default, colored)
asm config.json --json             # JSON
asm config.json --format markdown  # Markdown table
asm config.json --sarif            # SARIF (GitHub Security tab)
```

## OWASP Agentic Top 10 Mapping

Every finding maps to the [OWASP Top 10 for Agentic Applications (2026)](https://owasp.org/www-project-top-10-for-large-language-model-applications/):

| ID | Name | What We Check |
|----|------|---------------|
| ASI01 | Agent Goal Hijacking | Broad parameters accepting arbitrary input |
| ASI02 | Tool Misuse | Dangerous capability combos, unrestricted egress |
| ASI03 | Identity & Privilege Abuse | Credential exposure, missing permissions, excessive access |
| ASI04 | Supply Chain Vulnerabilities | Known vulnerable MCP servers, secret leakage to third parties |
| ASI05 | Unexpected Code Execution | Code execution + system config combos |
| ASI09 | Human-Agent Trust Exploitation | Missing approval requirements for dangerous ops |

## Programmatic Usage

```typescript
import { AttackSurfaceScanner } from '@15rl/attack-surface-mapper';

const scanner = new AttackSurfaceScanner();
const result = scanner.scan(agentConfig);

console.log(`Grade: ${result.grade}`);
console.log(`Findings: ${result.findings.length}`);
console.log(`Critical paths: ${result.attackSurface.criticalPaths.join(', ')}`);
```

## Part of the Authensor Ecosystem

This project is part of the [Authensor](https://github.com/AUTHENSOR/AUTHENSOR) open-source AI safety ecosystem, built by [15 Research Lab](https://github.com/AUTHENSOR).

| Project | Description |
|---------|-------------|
| [Authensor](https://github.com/AUTHENSOR/AUTHENSOR) | The open-source safety stack for AI agents |
| [Prompt Injection Benchmark](https://github.com/AUTHENSOR/prompt-injection-benchmark) | Standardized benchmark for safety scanners |
| [AI SecLists](https://github.com/AUTHENSOR/ai-seclists) | Security wordlists and payloads for AI/LLM testing |
| [ATT&CK ↔ Alignment Rosetta](https://github.com/AUTHENSOR/attack-alignment-rosetta) | Maps MITRE ATT&CK to AI alignment concepts |
| [Agent Forensics](https://github.com/AUTHENSOR/agent-forensics) | Post-incident analysis for receipt chains |
| [Behavioral Fingerprinting](https://github.com/AUTHENSOR/behavioral-fingerprinting) | Statistical behavioral drift detection |
| [Hawthorne Protocol](https://github.com/AUTHENSOR/hawthorne-protocol) | Can AI systems detect when they're being evaluated? |

## License

MIT
