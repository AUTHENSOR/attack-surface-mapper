export type Capability =
  | 'file_read' | 'file_write' | 'file_delete'
  | 'shell_execute' | 'network_request' | 'database_query'
  | 'email_send' | 'payment_process' | 'user_data_access'
  | 'code_execute' | 'system_config' | 'credential_access';

export const ALL_CAPABILITIES: Capability[] = [
  'file_read', 'file_write', 'file_delete',
  'shell_execute', 'network_request', 'database_query',
  'email_send', 'payment_process', 'user_data_access',
  'code_execute', 'system_config', 'credential_access',
];

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface ToolDefinition {
  name: string;
  description: string;
  parameters?: Record<string, unknown>;
  capabilities: Capability[];
}

export interface MCPServerConfig {
  name: string;
  command?: string;
  url?: string;
  transport: 'stdio' | 'sse' | 'http';
  tools?: string[];
  env?: Record<string, string>;
}

export interface PermissionSet {
  fileSystemPaths?: string[];
  networkAllowList?: string[];
  maxConcurrentTools?: number;
  requireApproval?: Capability[];
}

export interface AgentConfig {
  name: string;
  tools: ToolDefinition[];
  mcpServers?: MCPServerConfig[];
  envVars?: Record<string, string>;
  permissions?: PermissionSet;
}

export interface Finding {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  tool?: string;
  owaspMapping?: string;
  remediation: string;
}

export interface DataFlow {
  source: string;
  destination: string;
  dataType: string;
  risk: Severity;
}

export interface AttackSurface {
  totalTools: number;
  capabilityBreakdown: Partial<Record<Capability, number>>;
  criticalPaths: string[];
  exposedEndpoints: string[];
  dataFlows: DataFlow[];
}

export interface ScanResult {
  agent: string;
  scanDate: string;
  findings: Finding[];
  riskScore: number;
  grade: string;
  attackSurface: AttackSurface;
}
