export type RuleTarget = "PROXY" | "DIRECT" | "REJECT";
export type RuleType = "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "DOMAIN-REGEX" | "IP-CIDR" | "MATCH";
export type TrafficStatus = "active" | "closed" | "error";

export interface Rule {
  id: string;
  enabled: boolean;
  type: RuleType;
  value: string;
  target: RuleTarget;
  folder: string;
  remark: string;
}

export interface BatchRuleRequest {
  content: string;
  target: RuleTarget;
  folder: string;
  remark: string;
  enabled: boolean;
}

export interface BatchRuleItem {
  raw: string;
  type: RuleType;
  value: string;
  target: RuleTarget;
  folder: string;
  duplicate: boolean;
}

export interface BatchRuleResult {
  state: AppState;
  addedCount: number;
  mergedCount: number;
  skipped: BatchRuleItem[];
  added: BatchRuleItem[];
}

export interface TrafficLog {
  id: string;
  time: string;
  source: string;
  host: string;
  port: string;
  protocol: string;
  processId: number;
  processName: string;
  processPath: string;
  matchedRuleType: RuleType;
  matchedRuleValue: string;
  matchedRuleIndex: number;
  target: RuleTarget;
  path: string;
  uploadBytes: number;
  downloadBytes: number;
  durationMs: number;
  status: TrafficStatus;
  error: string;
}

export interface WindowsProxyConfig {
  autoConfigURL: string;
  proxyEnable: boolean;
  proxyServer: string;
}

export interface AppConfig {
  rules: Rule[];
  pacListenAddr: string;
  proxyListenAddr: string;
  fastLinkProxyAddr: string;
  fastLinkProxyType: string;
  proxyInterfaceName: string;
  proxyGuardEnabled: boolean;
  proxyGuardInterface: string;
  proxyGuardProgramPaths: string[];
  directInterfaceName: string;
  tunInterfaceName: string;
  tunAddressCidr: string;
  tunMtu: number;
  tunIncludedApps: string[];
  autoStartTunService: boolean;
  autoStartPacService: boolean;
  autoStartProxyService: boolean;
  autoEnableSystemPac: boolean;
  disableSystemPacOnExit: boolean;
  maxLogEntries: number;
  savedWindowsProxyConfig?: WindowsProxyConfig | null;
}

export interface ManagedAppStatus {
  query: string;
  name: string;
  path: string;
  running: boolean;
  pidCount: number;
  activeConnections: number;
}

export interface NetworkAdapterOption {
  name: string;
  description: string;
  status: string;
}

export interface NetworkRoute {
  ifIndex: number;
  interfaceAlias: string;
  destination: string;
  nextHop: string;
  routeMetric: number;
  interfaceMetric: number;
  state: string;
}

export interface DiagnosticPaths {
  rootDir: string;
  configPath: string;
  legacyConfigPath: string;
  diagnosticsPath: string;
  tunRuntimeDir: string;
  tunConfigPath: string;
  tunLogPath: string;
  coreDir: string;
  coreExecutable: string;
}

export interface ProxyGuardRuntimeStatus {
  applied: boolean;
  message: string;
  programCount: number;
  blockedInterfaceCount: number;
}

export interface TunRuntimeStatus {
  running: boolean;
  available: boolean;
  message: string;
  packetCount: number;
  byteCount: number;
}

export interface AgentDiagnostics {
  generatedAt: string;
  paths: DiagnosticPaths;
  state: AppState;
  proxyGuard: ProxyGuardRuntimeStatus;
  tunStatus: TunRuntimeStatus;
  networkAdapters: NetworkAdapterOption[];
  defaultIpv4Routes: NetworkRoute[];
  currentWindowsProxy?: WindowsProxyConfig | null;
  tunConfigPreview: string;
  tunLogTail: string;
  recentLogs: TrafficLog[];
}

export interface ServiceStatus {
  pacRunning: boolean;
  pacUrl: string;
  proxyRunning: boolean;
  proxyAddr: string;
  proxyGuardApplied: boolean;
  proxyGuardMessage: string;
  proxyGuardProgramCount: number;
  tunRunning: boolean;
  tunAvailable: boolean;
  tunMessage: string;
  tunIncludedAppCount: number;
  managedAppCount: number;
  managedProcessCount: number;
  managedConnectionCount: number;
  tunPacketCount: number;
  tunByteCount: number;
  systemPacEnabled: boolean;
  currentAutoConfigURL: string;
  fastLinkReachable: boolean;
  fastLinkMessage: string;
  ruleCount: number;
  enabledRuleCount: number;
  activeConnectionCount: number;
  recentLogCount: number;
  lastError: string;
}

export interface AppState {
  config: AppConfig;
  status: ServiceStatus;
  logs: TrafficLog[];
  managedApps: ManagedAppStatus[];
  availableNetworkAdapters: NetworkAdapterOption[];
}

declare global {
  interface Window {
    go?: {
      main?: {
        App?: {
          GetState(): Promise<AppState>;
          StartPacService(): Promise<void>;
          StopPacService(): Promise<void>;
          StartProxyService(): Promise<void>;
          StopProxyService(): Promise<void>;
          StartTunService(): Promise<void>;
          StopTunService(): Promise<void>;
          EnableSystemPac(): Promise<void>;
          DisableSystemPac(): Promise<void>;
          RefreshStatus(): Promise<AppState>;
          ClearLogs(): Promise<AppState>;
          UpsertRule(rule: Rule): Promise<AppState>;
          BatchUpsertRules(request: BatchRuleRequest): Promise<BatchRuleResult>;
          DeleteRule(id: string): Promise<AppState>;
          MoveRule(id: string, direction: "up" | "down"): Promise<AppState>;
          SaveSettings(config: AppConfig): Promise<AppState>;
          PauseTrafficRouting(): Promise<AppState>;
          ExportConfig(): Promise<void>;
          ExportAgentDiagnostics(): Promise<string>;
          GetAgentDiagnostics(): Promise<AgentDiagnostics>;
          ImportConfig(): Promise<AppState>;
          OpenConfigLocation(): Promise<void>;
          OpenDataDirectory(): Promise<void>;
          SetNetworkAdapterEnabled(name: string, enabled: boolean): Promise<AppState>;
        };
      };
    };
  }
}

export {};
