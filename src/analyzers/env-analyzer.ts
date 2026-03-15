import type { Finding } from '../types.js';

const SECRET_PATTERNS: { pattern: RegExp; name: string }[] = [
  { pattern: /^(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)$/i, name: 'AWS credential' },
  { pattern: /^(OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_AI_KEY)$/i, name: 'AI API key' },
  { pattern: /^(DATABASE_URL|DB_PASSWORD|POSTGRES_PASSWORD)$/i, name: 'Database credential' },
  { pattern: /^(STRIPE_SECRET_KEY|STRIPE_WEBHOOK_SECRET)$/i, name: 'Payment credential' },
  { pattern: /^(GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN)$/i, name: 'Git platform token' },
  { pattern: /^(SLACK_TOKEN|SLACK_WEBHOOK_URL|DISCORD_TOKEN)$/i, name: 'Messaging platform token' },
  { pattern: /^(SENDGRID_API_KEY|MAILGUN_API_KEY|SMTP_PASSWORD)$/i, name: 'Email service credential' },
  { pattern: /^(TWILIO_AUTH_TOKEN|TWILIO_API_KEY)$/i, name: 'Telephony credential' },
  { pattern: /_SECRET$|_TOKEN$|_KEY$|_PASSWORD$/i, name: 'Potential secret' },
];

export function analyzeEnvVars(envVars: Record<string, string>): Finding[] {
  const findings: Finding[] = [];
  let idx = 0;

  for (const [key, value] of Object.entries(envVars)) {
    for (const sp of SECRET_PATTERNS) {
      if (sp.pattern.test(key)) {
        findings.push({
          id: `ENV-${String(++idx).padStart(3, '0')}`,
          severity: key.match(/PASSWORD|SECRET|CREDENTIAL/i) ? 'critical' : 'high',
          category: 'secret-exposure',
          title: `${sp.name} exposed: ${key}`,
          description: `Environment variable "${key}" (${sp.name}) is accessible to the agent. If the agent is compromised via prompt injection or tool misuse, this credential can be exfiltrated.`,
          owaspMapping: 'ASI03',
          remediation: `Remove "${key}" from the agent's environment. Use a secrets manager with scoped, short-lived tokens instead.`,
        });
        break; // Only report first matching pattern
      }
    }

    // Check for hardcoded-looking values (long hex/base64 strings)
    if (value.length > 20 && /^[A-Za-z0-9+/=_-]{20,}$/.test(value) && !SECRET_PATTERNS.some((p) => p.pattern.test(key))) {
      findings.push({
        id: `ENV-${String(++idx).padStart(3, '0')}`,
        severity: 'low',
        category: 'potential-secret',
        title: `Potential secret in env var: ${key}`,
        description: `Environment variable "${key}" contains a long encoded string that may be a secret or API key.`,
        owaspMapping: 'ASI03',
        remediation: `Review whether "${key}" contains sensitive data. If so, use a secrets manager.`,
      });
    }
  }

  return findings;
}
