export type RuleTarget = "PROXY" | "DIRECT" | "REJECT";
export type RuleType = "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "DOMAIN-REGEX" | "IP-CIDR" | "MATCH";
export type TrafficStatus = "active" | "closed" | "error";

export interface Rule {
  id: string;
  enabled: boolean;
  type: RuleType;
  value: string;
  target: RuleTarget;
  remark: string;
}

export interface BatchRuleRequest {
  content: string;
  target: RuleTarget;
  remark: string;
  enabled: boolean;
}

export interface BatchRuleItem {
  raw: string;
  type: RuleType;
  value: string;
  target: RuleTarget;
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
  host: string;
  port: string;
  protocol: string;
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
  autoStartPacService: boolean;
  autoStartProxyService: boolean;
  autoEnableSystemPac: boolean;
  disableSystemPacOnExit: boolean;
  maxLogEntries: number;
  savedWindowsProxyConfig?: WindowsProxyConfig | null;
}

export interface ServiceStatus {
  pacRunning: boolean;
  pacUrl: string;
  proxyRunning: boolean;
  proxyAddr: string;
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
          EnableSystemPac(): Promise<void>;
          DisableSystemPac(): Promise<void>;
          RefreshStatus(): Promise<AppState>;
          ClearLogs(): Promise<AppState>;
          UpsertRule(rule: Rule): Promise<AppState>;
          BatchUpsertRules(request: BatchRuleRequest): Promise<BatchRuleResult>;
          DeleteRule(id: string): Promise<AppState>;
          MoveRule(id: string, direction: "up" | "down"): Promise<AppState>;
          SaveSettings(config: AppConfig): Promise<AppState>;
          ExportConfig(): Promise<void>;
          ImportConfig(): Promise<AppState>;
        };
      };
    };
  }
}

export {};
