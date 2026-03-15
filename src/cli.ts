#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { AttackSurfaceScanner } from './scanner.js';
import { formatTerminal } from './reporters/terminal.js';
import { formatJson } from './reporters/json.js';
import { formatMarkdown } from './reporters/markdown.js';
import { formatSarif } from './reporters/sarif.js';
import type { AgentConfig } from './types.js';

function usage(): never {
  console.log(`
Usage: asm [options] <config-file>

Map the attack surface of an AI agent from its configuration file.

Options:
  -f, --format <format>    Output format: terminal, markdown, json, sarif (default: terminal)
  -o, --output <file>      Output file (default: stdout)
  --min-severity <level>   Minimum severity: critical, high, medium, low, info (default: low)
  --json                   Shortcut for --format json
  --sarif                  Shortcut for --format sarif
  -h, --help               Show this help
`);
  process.exit(0);
}

function main(): void {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    usage();
  }

  let format = 'terminal';
  let outputFile: string | null = null;
  let minSeverity = 'low';
  let configFile: string | null = null;

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '-f':
      case '--format':
        format = args[++i];
        break;
      case '-o':
      case '--output':
        outputFile = args[++i];
        break;
      case '--min-severity':
        minSeverity = args[++i];
        break;
      case '--json':
        format = 'json';
        break;
      case '--sarif':
        format = 'sarif';
        break;
      default:
        if (!args[i].startsWith('-')) {
          configFile = args[i];
        }
    }
  }

  if (!configFile) {
    console.error('Error: No config file specified.');
    process.exit(1);
  }

  let config: AgentConfig;
  try {
    const raw = readFileSync(configFile, 'utf-8');
    config = JSON.parse(raw) as AgentConfig;
  } catch (err) {
    console.error(`Error reading config file: ${(err as Error).message}`);
    process.exit(1);
  }

  const scanner = new AttackSurfaceScanner();
  const result = scanner.scan(config);

  // Filter by min severity
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
  const minIdx = severityOrder.indexOf(minSeverity);
  if (minIdx >= 0) {
    result.findings = result.findings.filter((f) => severityOrder.indexOf(f.severity) <= minIdx);
  }

  let output: string;
  switch (format) {
    case 'json': output = formatJson(result); break;
    case 'markdown': output = formatMarkdown(result); break;
    case 'sarif': output = formatSarif(result); break;
    default: output = formatTerminal(result);
  }

  if (outputFile) {
    const { writeFileSync } = require('node:fs');
    writeFileSync(outputFile, output, 'utf-8');
    console.log(`Report written to ${outputFile}`);
  } else {
    console.log(output);
  }
}

main();
