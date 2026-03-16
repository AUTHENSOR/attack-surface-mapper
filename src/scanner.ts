import type { AgentConfig, ScanResult, Finding, AttackSurface, Capability } from './types.js';
import { analyzeTools } from './analyzers/tool-analyzer.js';
import { analyzeMCPServers } from './analyzers/mcp-analyzer.js';
import { analyzeEnvVars } from './analyzers/env-analyzer.js';
import { analyzeNetwork } from './analyzers/network-analyzer.js';
import { analyzePermissions } from './analyzers/permission-analyzer.js';
import { calculateRiskScore, calculateGrade } from './risk/scorer.js';
import { assessCompliance, type ComplianceReport } from './risk/eu-ai-act.js';

export class AttackSurfaceScanner {
  scan(config: AgentConfig): ScanResult {
    const findings: Finding[] = [];

    // Run all analyzers
    findings.push(...analyzeTools(config.tools));

    if (config.mcpServers && config.mcpServers.length > 0) {
      findings.push(...analyzeMCPServers(config.mcpServers));
    }

    if (config.envVars) {
      findings.push(...analyzeEnvVars(config.envVars));
    }

    const { findings: netFindings, dataFlows } = analyzeNetwork(config.tools, config.permissions);
    findings.push(...netFindings);

    findings.push(...analyzePermissions(config.tools, config.permissions));

    // Deduplicate findings by ID
    const seen = new Set<string>();
    const deduped = findings.filter((f) => {
      if (seen.has(f.id)) return false;
      seen.add(f.id);
      return true;
    });

    // Calculate risk
    const riskScore = calculateRiskScore(deduped);
    const grade = calculateGrade(riskScore);

    // Build attack surface summary
    const attackSurface = this.buildAttackSurface(config, dataFlows);

    // EU AI Act compliance assessment
    const findingCategories = deduped.map((f) => f.category);
    const compliance = assessCompliance(findingCategories);

    return {
      agent: config.name,
      scanDate: new Date().toISOString(),
      findings: deduped.sort((a, b) => {
        const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return order[a.severity] - order[b.severity];
      }),
      riskScore,
      grade,
      attackSurface,
      compliance,
    };
  }

  private buildAttackSurface(config: AgentConfig, dataFlows: { source: string; destination: string; dataType: string; risk: string }[]): AttackSurface {
    const capBreakdown: Partial<Record<Capability, number>> = {};
    for (const tool of config.tools) {
      for (const cap of tool.capabilities) {
        capBreakdown[cap] = (capBreakdown[cap] ?? 0) + 1;
      }
    }

    // Identify critical paths (chains of capabilities)
    const criticalPaths: string[] = [];
    const dangerousCombos: Capability[][] = [
      ['shell_execute', 'network_request'],
      ['credential_access', 'network_request'],
      ['file_read', 'network_request'],
      ['code_execute', 'system_config'],
      ['payment_process', 'code_execute'],
    ];

    for (const combo of dangerousCombos) {
      const hasAll = combo.every((cap) => config.tools.some((t) => t.capabilities.includes(cap)));
      if (hasAll) {
        criticalPaths.push(combo.join(' → '));
      }
    }

    // Exposed endpoints
    const exposedEndpoints: string[] = [];
    if (config.mcpServers) {
      for (const server of config.mcpServers) {
        if (server.url) exposedEndpoints.push(server.url);
      }
    }

    return {
      totalTools: config.tools.length + (config.mcpServers?.length ?? 0),
      capabilityBreakdown: capBreakdown,
      criticalPaths,
      exposedEndpoints,
      dataFlows: dataFlows as any,
    };
  }
}
