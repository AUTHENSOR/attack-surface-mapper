/**
 * Risk assessment rules -- defines what patterns to look for and how
 * to score them.
 */

import type { Capability, Severity } from '../types.js';

// ---------------------------------------------------------------------------
// Dangerous capability combinations
// ---------------------------------------------------------------------------

export interface DangerousCombo {
  capabilities: Capability[];
  severity: Severity;
  title: string;
  description: string;
  remediation: string;
}

/**
 * Known dangerous capability combinations. When a single tool (or the
 * union of all tools) possesses these capabilities together, they form
 * attack chains an adversary can exploit.
 */
export const DANGEROUS_COMBOS: readonly DangerousCombo[] = [
  {
    capabilities: ['shell_execute', 'network_request'],
    severity: 'critical',
    title: 'Data exfiltration path via shell + network',
    description:
      'An agent with shell execution and network access can exfiltrate arbitrary data. ' +
      'A prompt injection could instruct the agent to curl sensitive files to an attacker-controlled server.',
    remediation:
      'Restrict shell commands to an allow-list and limit network egress to known hosts.',
  },
  {
    capabilities: ['shell_execute', 'file_read'],
    severity: 'high',
    title: 'Arbitrary file read via shell',
    description:
      'Shell execution combined with file read allows reading any file on the system, ' +
      'including secrets, SSH keys, and credentials.',
    remediation:
      'Sandbox shell execution and restrict file read to specific directories.',
  },
  {
    capabilities: ['credential_access', 'network_request'],
    severity: 'critical',
    title: 'Credential theft and exfiltration path',
    description:
      'Access to credentials combined with network requests allows stealing and transmitting ' +
      'secrets to external servers.',
    remediation:
      'Never expose raw credentials to agent tools. Use scoped tokens with limited lifetimes.',
  },
  {
    capabilities: ['file_write', 'code_execute'],
    severity: 'critical',
    title: 'Arbitrary code write and execution',
    description:
      'An agent that can write files and execute code can write malicious scripts and run them, ' +
      'achieving full system compromise.',
    remediation:
      'Restrict file write to a sandboxed directory and use a code execution sandbox.',
  },
  {
    capabilities: ['database_query', 'network_request'],
    severity: 'high',
    title: 'Database exfiltration path',
    description:
      'Database access combined with network requests allows exfiltrating query results to external servers.',
    remediation:
      'Restrict database queries to read-only on specific tables and limit network egress.',
  },
  {
    capabilities: ['user_data_access', 'email_send'],
    severity: 'high',
    title: 'User data leak via email',
    description:
      'Access to user data combined with email sending allows leaking PII through crafted emails.',
    remediation:
      'Apply data masking before email composition and require human approval for emails containing user data.',
  },
  {
    capabilities: ['system_config', 'shell_execute'],
    severity: 'critical',
    title: 'System reconfiguration via shell',
    description:
      'System configuration access combined with shell execution enables privilege escalation ' +
      'and persistent backdoor installation.',
    remediation:
      'Run agent processes in unprivileged containers with read-only system directories.',
  },
  {
    capabilities: ['file_delete', 'system_config'],
    severity: 'high',
    title: 'Destructive system modification',
    description:
      'File deletion combined with system configuration access could allow an agent to destroy ' +
      'critical system files or configurations.',
    remediation:
      'Restrict file deletion to designated temporary directories only.',
  },
  {
    capabilities: ['payment_process', 'code_execute'],
    severity: 'critical',
    title: 'Unauthorized payment execution',
    description:
      'Code execution combined with payment processing allows crafting and executing arbitrary payment transactions.',
    remediation:
      'Require multi-party approval for all payment operations. Never allow code execution in the same context as payment processing.',
  },
  {
    capabilities: ['credential_access', 'file_write'],
    severity: 'high',
    title: 'Credential persistence to disk',
    description:
      'Credential access combined with file write allows persisting stolen credentials to disk for later retrieval.',
    remediation:
      'Isolate credential access from file system write capabilities.',
  },
] as const;

// ---------------------------------------------------------------------------
// Sensitive environment variable patterns
// ---------------------------------------------------------------------------

export interface SecretPattern {
  pattern: RegExp;
  name: string;
  severity: Severity;
}

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  { pattern: /^(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)$/i, name: 'AWS credentials', severity: 'critical' },
  { pattern: /^(OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_AI_KEY)$/i, name: 'AI provider API key', severity: 'high' },
  { pattern: /^(DATABASE_URL|DB_PASSWORD|POSTGRES_PASSWORD|MYSQL_PASSWORD)$/i, name: 'Database credentials', severity: 'critical' },
  { pattern: /^(GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN)$/i, name: 'VCS token', severity: 'high' },
  { pattern: /^(STRIPE_SECRET_KEY|STRIPE_WEBHOOK_SECRET)$/i, name: 'Payment credentials', severity: 'critical' },
  { pattern: /^(SENDGRID_API_KEY|MAILGUN_API_KEY|SMTP_PASSWORD)$/i, name: 'Email service credentials', severity: 'high' },
  { pattern: /^(JWT_SECRET|SESSION_SECRET|COOKIE_SECRET|ENCRYPTION_KEY)$/i, name: 'Application secret', severity: 'critical' },
  { pattern: /^(SLACK_TOKEN|SLACK_WEBHOOK_URL|DISCORD_TOKEN)$/i, name: 'Messaging platform token', severity: 'medium' },
  { pattern: /_(SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|AUTH)$/i, name: 'Potential secret', severity: 'medium' },
  { pattern: /^(PRIVATE_KEY|SSH_KEY|GPG_KEY)$/i, name: 'Cryptographic key', severity: 'critical' },
] as const;

// ---------------------------------------------------------------------------
// Secret value patterns -- detect actual secret values in env vars
// ---------------------------------------------------------------------------

export interface SecretValuePattern {
  pattern: RegExp;
  name: string;
  severity: Severity;
}

export const SECRET_VALUE_PATTERNS: readonly SecretValuePattern[] = [
  { pattern: /^sk-[a-zA-Z0-9]{20,}$/, name: 'OpenAI API key value', severity: 'critical' },
  { pattern: /^sk-ant-[a-zA-Z0-9]{20,}$/, name: 'Anthropic API key value', severity: 'critical' },
  { pattern: /^ghp_[a-zA-Z0-9]{36}$/, name: 'GitHub personal access token', severity: 'critical' },
  { pattern: /^gho_[a-zA-Z0-9]{36}$/, name: 'GitHub OAuth token', severity: 'critical' },
  { pattern: /^xoxb-[0-9]{10,13}-[a-zA-Z0-9-]+$/, name: 'Slack bot token', severity: 'high' },
  { pattern: /^AKIA[0-9A-Z]{16}$/, name: 'AWS access key ID', severity: 'critical' },
  { pattern: /^[a-f0-9]{64}$/, name: 'Possible hex-encoded secret (64 chars)', severity: 'medium' },
] as const;

// ---------------------------------------------------------------------------
// Sensitive file system paths
// ---------------------------------------------------------------------------

export const SENSITIVE_PATHS: readonly { path: string; description: string; severity: Severity }[] = [
  { path: '/etc', description: 'System configuration directory', severity: 'high' },
  { path: '/etc/passwd', description: 'User account information', severity: 'high' },
  { path: '/etc/shadow', description: 'Password hashes', severity: 'critical' },
  { path: '/etc/ssh', description: 'SSH server configuration', severity: 'critical' },
  { path: '~/.ssh', description: 'User SSH keys', severity: 'critical' },
  { path: '~/.aws', description: 'AWS credentials and config', severity: 'critical' },
  { path: '~/.gnupg', description: 'GPG keys', severity: 'critical' },
  { path: '~/.config', description: 'User application configs', severity: 'medium' },
  { path: '/var/log', description: 'System logs', severity: 'medium' },
  { path: '/proc', description: 'Process information', severity: 'high' },
  { path: '/sys', description: 'Kernel parameters', severity: 'high' },
  { path: '/root', description: 'Root home directory', severity: 'critical' },
  { path: '/tmp', description: 'Shared temporary directory', severity: 'low' },
  { path: '~/.env', description: 'Environment file with secrets', severity: 'high' },
  { path: '~/.netrc', description: 'Network authentication file', severity: 'critical' },
  { path: '~/.docker', description: 'Docker configuration and credentials', severity: 'high' },
  { path: '~/.kube', description: 'Kubernetes configuration', severity: 'critical' },
] as const;

// ---------------------------------------------------------------------------
// Known vulnerable / high-risk MCP servers
// ---------------------------------------------------------------------------

export const KNOWN_RISKY_MCP_SERVERS: readonly { pattern: RegExp; description: string; severity: Severity }[] = [
  { pattern: /shell|exec|terminal|bash|cmd/i, description: 'Shell execution MCP server -- grants arbitrary command execution', severity: 'critical' },
  { pattern: /filesystem|fs-access|file-manager/i, description: 'Unrestricted filesystem MCP server', severity: 'high' },
  { pattern: /database|sql|postgres|mysql|mongo/i, description: 'Database access MCP server -- may allow arbitrary queries', severity: 'high' },
  { pattern: /puppeteer|playwright|browser/i, description: 'Browser automation MCP server -- SSRF and data scraping risk', severity: 'medium' },
  { pattern: /everything/i, description: '"Everything" server grants overly broad capabilities', severity: 'critical' },
] as const;

// ---------------------------------------------------------------------------
// Severity scoring weights
// ---------------------------------------------------------------------------

export const SEVERITY_SCORES: Record<string, number> = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 3,
  info: 0,
} as const;
