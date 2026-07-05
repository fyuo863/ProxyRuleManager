import { FormEvent, useEffect, useMemo, useRef, useState } from "react";
import type {
  AppConfig,
  AppState,
  BatchRuleRequest,
  BatchRuleResult,
  NetworkAdapterOption,
  Rule,
  RuleTarget,
  RuleType,
  TrafficLog,
  TunAppProfile,
  TunAppRoutingMode,
} from "./wails";

const defaultTunIncludedApps = ["Codex.exe", "codex.exe", "codex-command-runner-*.exe"];
const defaultSteamApps = ["steam.exe", "steamwebhelper.exe"];

type AppPreset = {
  id: string;
  label: string;
  category: string;
  profile: TunAppProfile;
  description: string;
};

const appPresets: AppPreset[] = [
  {
    id: "codex",
    label: "Codex Desktop",
    category: "开发 / AI",
    profile: {
      id: "",
      name: "Codex Desktop",
      enabled: true,
      queries: defaultTunIncludedApps,
      routingMode: "FORCE_PROXY",
      bypassTransparentProxy: false,
      remark: "覆盖 Codex 桌面主进程、CLI 和命令执行子进程；默认全部走代理。",
    },
    description: "保留之前的 Codex 透明接管配置，覆盖桌面主进程、CLI 和命令执行子进程。",
  },
  {
    id: "steam",
    label: "Steam Desktop",
    category: "游戏平台",
    profile: {
      id: "",
      name: "Steam Desktop",
      enabled: true,
      queries: defaultSteamApps,
      routingMode: "RULES_DIRECT_FALLBACK",
      bypassTransparentProxy: true,
      remark: "高吞吐下载默认绕过透明接管，仅保留进程监控；需要代理商店/社区时建议使用系统 PAC 或单独关闭绕过。",
    },
    description: "监控 Steam 主进程和 Web Helper，但默认不把游戏下载流量送入透明接管数据面。",
  },
  {
    id: "steam-games-auto",
    label: "Steam Games Auto",
    category: "游戏平台",
    profile: {
      id: "",
      name: "Steam Games Auto",
      enabled: true,
      queries: ["steam-library-games:"],
      routingMode: "FORCE_DIRECT",
      bypassTransparentProxy: true,
      remark: "自动识别 Steam 库目录 steamapps/common 下的游戏进程，默认直连，避免影响成就、Overlay 和游戏联网。",
    },
    description: "自动识别 Steam 库目录 steamapps/common 下的游戏进程，默认直连，避免影响成就、Overlay 和游戏联网。",
  },
];

const defaultTunAppProfiles: TunAppProfile[] = [
  {
    id: "codex-default",
    name: "Codex Desktop",
    enabled: true,
    queries: defaultTunIncludedApps,
    routingMode: "FORCE_PROXY",
    bypassTransparentProxy: false,
    remark: "覆盖 Codex 桌面主进程、CLI 和命令执行子进程；默认全部走代理。",
  },
];

const routingModeOptions: Array<{ value: TunAppRoutingMode; label: string; description: string }> = [
  {
    value: "FORCE_PROXY",
    label: "全部走代理",
    description: "无论域名是否可识别，当前应用的透明接管连接都走上游代理。",
  },
  {
    value: "RULES_PROXY_FALLBACK",
    label: "按规则匹配，未识别时走代理",
    description: "优先识别 TLS SNI / HTTP Host 并按规则处理；识别不到时回退到代理。",
  },
  {
    value: "RULES_DIRECT_FALLBACK",
    label: "按规则匹配，未识别时直连",
    description: "优先识别 TLS SNI / HTTP Host 并按规则处理；识别不到时回退到直连。",
  },
  {
    value: "FORCE_DIRECT",
    label: "全部直连",
    description: "当前应用的透明接管连接全部直连，不经过上游代理。",
  },
];

const createTunAppProfile = (profile?: Partial<TunAppProfile>): TunAppProfile => ({
  id: profile?.id ?? "",
  name: profile?.name ?? "",
  enabled: profile?.enabled ?? true,
  queries: Array.isArray(profile?.queries) ? profile!.queries : [],
  routingMode: profile?.routingMode ?? "RULES_PROXY_FALLBACK",
  bypassTransparentProxy: profile?.bypassTransparentProxy ?? false,
  remark: profile?.remark ?? "",
});

const applyTunPreset = (presetId: string, current?: Partial<TunAppProfile>): TunAppProfile => {
  const preset = appPresets.find((item) => item.id === presetId);
  if (!preset) {
    return createTunAppProfile(current);
  }
  return createTunAppProfile({
    ...preset.profile,
    id: current?.id ?? "",
  });
};

const flattenTunProfiles = (profiles: TunAppProfile[]) => {
  const seen = new Set<string>();
  const queries: string[] = [];
  for (const profile of profiles) {
    if (!profile.enabled) continue;
    for (const raw of profile.queries ?? []) {
      const value = raw.trim();
      if (!value) continue;
      const key = value.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      queries.push(value);
    }
  }
  return queries;
};

const emptyState: AppState = {
  config: {
    rules: [],
    pacListenAddr: "127.0.0.1:18088",
    proxyListenAddr: "127.0.0.1:18089",
    upstreamProxyAddr: "127.0.0.1:7892",
    upstreamProxyType: "http",
    proxyInterfaceName: "",
    upstreamProxyRouteEnabled: false,
    upstreamProxyRouteInterface: "",
    upstreamProxyRouteTargets: [],
    proxyGuardEnabled: false,
    proxyGuardInterface: "",
    proxyGuardProgramPaths: [],
    directInterfaceName: "",
    tunInterfaceName: "ProxyRuleManagerTun",
    tunAddressCidr: "172.19.0.1/30",
    tunMtu: 1500,
    tunAppProfiles: defaultTunAppProfiles,
    tunIncludedApps: flattenTunProfiles(defaultTunAppProfiles),
    autoStartTunService: false,
    autoStartPacService: false,
    autoStartProxyService: false,
    autoEnableSystemPac: false,
    disableSystemPacOnExit: false,
    maxLogEntries: 500,
    savedWindowsProxyConfig: null,
  },
  status: {
    pacRunning: false,
    pacUrl: "",
    proxyRunning: false,
    proxyAddr: "",
    upstreamProxyRouteApplied: false,
    upstreamProxyRouteMessage: "",
    upstreamProxyRouteCount: 0,
    proxyGuardApplied: false,
    proxyGuardMessage: "",
    proxyGuardProgramCount: 0,
    tunRunning: false,
    tunAvailable: false,
    tunMessage: "",
    tunIncludedAppCount: 0,
    managedAppCount: 0,
    managedProcessCount: 0,
    managedConnectionCount: 0,
    tunPacketCount: 0,
    tunByteCount: 0,
    systemPacEnabled: false,
    currentAutoConfigURL: "",
    upstreamProxyReachable: false,
    upstreamProxyMessage: "",
    ruleCount: 0,
    enabledRuleCount: 0,
    activeConnectionCount: 0,
    recentLogCount: 0,
    lastError: "",
  },
  logs: [],
  managedApps: [],
  availableNetworkAdapters: [],
};

const ruleTypes: RuleType[] = ["DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX", "IP-CIDR"];
const ruleTargets: RuleTarget[] = ["PROXY", "DIRECT", "REJECT"];
type AppApi = NonNullable<NonNullable<NonNullable<typeof window.go>["main"]>["App"]>;

const invoke = <T,>(name: keyof AppApi, ...args: unknown[]) => {
  const app = window.go?.main?.App as AppApi | undefined;
  if (!app) {
    return Promise.reject(new Error("Wails runtime is not available. Please run this UI through Wails."));
  }
  const fn = app[name] as (...params: unknown[]) => Promise<T>;
  return fn(...args);
};

const formatBytes = (value: number) => {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MB`;
};

const formatDuration = (ms: number) => `${ms} ms`;

const normalizeConfig = (config?: Partial<AppConfig> | null): AppConfig => ({
  ...emptyState.config,
  ...config,
  rules: Array.isArray(config?.rules) ? config.rules : emptyState.config.rules,
  proxyGuardProgramPaths: Array.isArray(config?.proxyGuardProgramPaths) ? config.proxyGuardProgramPaths : emptyState.config.proxyGuardProgramPaths,
  upstreamProxyRouteTargets: Array.isArray(config?.upstreamProxyRouteTargets) ? config.upstreamProxyRouteTargets : emptyState.config.upstreamProxyRouteTargets,
  tunAppProfiles: Array.isArray(config?.tunAppProfiles) ? config.tunAppProfiles.map((item) => createTunAppProfile(item)) : emptyState.config.tunAppProfiles,
  tunIncludedApps: Array.isArray(config?.tunIncludedApps) ? config.tunIncludedApps : flattenTunProfiles(Array.isArray(config?.tunAppProfiles) ? config.tunAppProfiles.map((item) => createTunAppProfile(item)) : emptyState.config.tunAppProfiles),
  savedWindowsProxyConfig: config?.savedWindowsProxyConfig ?? null,
});

const normalizeState = (next?: Partial<AppState> | null): AppState => ({
  ...emptyState,
  ...next,
  config: normalizeConfig(next?.config),
  status: {
    ...emptyState.status,
    ...(next?.status ?? {}),
  },
  logs: Array.isArray(next?.logs) ? next.logs : [],
  managedApps: Array.isArray(next?.managedApps) ? next.managedApps : [],
  availableNetworkAdapters: Array.isArray(next?.availableNetworkAdapters) ? next.availableNetworkAdapters : [],
});

const buildAdapterOptions = (adapters: NetworkAdapterOption[], currentValues: string[]) => {
  const seen = new Set<string>();
  const options: NetworkAdapterOption[] = [];

  for (const item of adapters) {
    if (!item.name || seen.has(item.name)) continue;
    seen.add(item.name);
    options.push(item);
  }

  for (const value of currentValues) {
    const name = value.trim();
    if (!name || seen.has(name)) continue;
    seen.add(name);
    options.push({ name, description: "当前配置，未在自动识别列表中", status: "Unknown" });
  }

  return options;
};

const formatAdapterLabel = (adapter: NetworkAdapterOption) => {
  const details = [adapter.status, adapter.description].filter(Boolean).join(" / ");
  return details ? `${adapter.name} (${details})` : adapter.name;
};

const detectRuleType = (raw: string): { type: RuleType; value: string } => {
  let value = raw.trim().toLowerCase();
  if (!value) {
    return { type: "DOMAIN-SUFFIX", value: "" };
  }

  try {
    if (value.startsWith("http://") || value.startsWith("https://")) {
      value = new URL(value).hostname.toLowerCase();
    }
  } catch {}

  const stripPrefix = (prefix: string) => value.startsWith(prefix) ? value.slice(prefix.length).trim() : "";
  const normalizeHost = (input: string) => input.trim().toLowerCase().replace(/^\*\./, "").replace(/^\./, "").replace(/\/$/, "");

  if (stripPrefix("domain-suffix:")) return { type: "DOMAIN-SUFFIX", value: normalizeHost(stripPrefix("domain-suffix:")) };
  if (stripPrefix("suffix:")) return { type: "DOMAIN-SUFFIX", value: normalizeHost(stripPrefix("suffix:")) };
  if (stripPrefix("domain:")) return { type: "DOMAIN", value: normalizeHost(stripPrefix("domain:")) };
  if (stripPrefix("keyword:")) return { type: "DOMAIN-KEYWORD", value: stripPrefix("keyword:") };
  if (stripPrefix("regex:")) return { type: "DOMAIN-REGEX", value: raw.trim().slice(raw.indexOf(":") + 1).trim() };
  if (stripPrefix("cidr:")) return { type: "IP-CIDR", value: stripPrefix("cidr:") };

  if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(value)) return { type: "IP-CIDR", value };
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return { type: "IP-CIDR", value: `${value}/32` };
  if (/[\^\$\[\]\(\)\|\\+]/.test(value)) return { type: "DOMAIN-REGEX", value: raw.trim() };
  if (value.includes("*")) return { type: "DOMAIN-SUFFIX", value: normalizeHost(value.split("*").join("")) };
  if (value.includes(".") && !value.includes(" ")) return { type: "DOMAIN-SUFFIX", value: normalizeHost(value) };
  return { type: "DOMAIN-KEYWORD", value: raw.trim() };
};

function App() {
  const [state, setState] = useState<AppState>(emptyState);
  const [error, setError] = useState<string>("");
  const [hostFilter, setHostFilter] = useState("");
  const [sourceFilter, setSourceFilter] = useState<"ALL" | "APP" | "WEB">("ALL");
  const [targetFilter, setTargetFilter] = useState<RuleTarget | "ALL">("ALL");
  const [ruleFolderFilter, setRuleFolderFilter] = useState("ALL");
  const [logLimit, setLogLimit] = useState<100 | 500>(100);
  const [editingRule, setEditingRule] = useState<Rule | null>(null);
  const [settingsDraft, setSettingsDraft] = useState<AppConfig>(emptyState.config);
  const [activeSection, setActiveSection] = useState<"console" | "rules" | "logs" | "settings">("console");
  const [batchDraft, setBatchDraft] = useState<BatchRuleRequest>({
    content: "",
    target: "PROXY",
    folder: "",
    remark: "",
    enabled: true,
  });
  const [batchMessage, setBatchMessage] = useState<string>("");
  const [settingsMessage, setSettingsMessage] = useState<string>("");
  const [selectedTunAppId, setSelectedTunAppId] = useState(defaultTunAppProfiles[0]?.id ?? "");
  const [editingTunApp, setEditingTunApp] = useState<TunAppProfile | null>(null);
  const [tunAppPresetId, setTunAppPresetId] = useState(appPresets[0]?.id ?? "");
  const settingsDirtyRef = useRef(false);
  const refreshInFlightRef = useRef(false);
  const adapterOptions = useMemo(
    () => buildAdapterOptions(state.availableNetworkAdapters, [
      settingsDraft.proxyInterfaceName,
      settingsDraft.upstreamProxyRouteInterface,
      settingsDraft.proxyGuardInterface,
      settingsDraft.directInterfaceName,
    ]),
    [settingsDraft.directInterfaceName, settingsDraft.upstreamProxyRouteInterface, settingsDraft.proxyGuardInterface, settingsDraft.proxyInterfaceName, state.availableNetworkAdapters],
  );

  const applyNextState = (next: AppState, syncSettings = false) => {
    setState(next);
    if (syncSettings || !settingsDirtyRef.current) {
      settingsDirtyRef.current = false;
      setSettingsDraft(next.config);
      setSelectedTunAppId((prev) => {
        const profiles = next.config.tunAppProfiles ?? [];
        if (profiles.some((item) => item.id === prev)) {
          return prev;
        }
        return profiles[0]?.id ?? "";
      });
    }
  };

  const updateSettingsDraft = (patch: Partial<AppConfig>) => {
    settingsDirtyRef.current = true;
    setSettingsDraft((prev) => {
      const next = { ...prev, ...patch };
      const profiles = Array.isArray(next.tunAppProfiles) ? next.tunAppProfiles.map((item) => createTunAppProfile(item)) : prev.tunAppProfiles;
      next.tunAppProfiles = profiles;
      next.tunIncludedApps = flattenTunProfiles(profiles);
      return next;
    });
  };

  const refresh = async () => {
    if (refreshInFlightRef.current) {
      return;
    }
    refreshInFlightRef.current = true;
    try {
      const next = normalizeState(await invoke<AppState>("GetState"));
      applyNextState(next);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      refreshInFlightRef.current = false;
    }
  };

  const refreshStatus = async () => {
    try {
      const next = normalizeState(await invoke<AppState>("RefreshStatus"));
      applyNextState(next);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => {
      void refresh();
    }, 1000);
    return () => window.clearInterval(timer);
  }, []);

  const filteredLogs = useMemo(() => {
    let items = [...state.logs].reverse();
    if (hostFilter) {
      items = items.filter((item) => item.host.toLowerCase().includes(hostFilter.toLowerCase()));
    }
    if (sourceFilter === "APP") {
      items = items.filter((item) => item.source === "process");
    }
    if (sourceFilter === "WEB") {
      items = items.filter((item) => item.source !== "process");
    }
    if (targetFilter !== "ALL") {
      items = items.filter((item) => item.target === targetFilter);
    }
    return items.slice(0, logLimit);
  }, [state.logs, hostFilter, sourceFilter, targetFilter, logLimit]);

  const availableRuleFolders = useMemo(() => {
    const folders = state.config.rules
      .map((rule) => rule.folder?.trim() || "未分类")
      .filter((value, index, arr) => arr.indexOf(value) === index);
    return folders;
  }, [state.config.rules]);

  const visibleRules = useMemo(() => {
    if (ruleFolderFilter === "ALL") {
      return state.config.rules;
    }
    return state.config.rules.filter((rule) => (rule.folder?.trim() || "未分类") === ruleFolderFilter);
  }, [ruleFolderFilter, state.config.rules]);

  const batchPreview = useMemo(() => {
    return batchDraft.content
      .split(/[\n,;\t]+/)
      .map((item) => item.trim())
      .filter(Boolean)
      .slice(0, 8)
      .map((item) => ({ raw: item, ...detectRuleType(item) }));
  }, [batchDraft.content]);

  const selectedTunApp = useMemo(
    () => settingsDraft.tunAppProfiles.find((item) => item.id === selectedTunAppId) ?? settingsDraft.tunAppProfiles[0] ?? null,
    [selectedTunAppId, settingsDraft.tunAppProfiles],
  );

  const appPresetCategories = useMemo(() => {
    const grouped = new Map<string, AppPreset[]>();
    for (const preset of appPresets) {
      const current = grouped.get(preset.category) ?? [];
      current.push(preset);
      grouped.set(preset.category, current);
    }
    return Array.from(grouped.entries());
  }, []);

  const selectedTunAppStatuses = useMemo(() => {
    if (!selectedTunApp) return [];
    const statusMap = new Map(state.managedApps.map((item) => [item.query.toLowerCase(), item] as const));
    return selectedTunApp.queries.map((query) => {
      const matched = statusMap.get(query.toLowerCase());
      return {
        query,
        running: matched?.running ?? false,
        pidCount: matched?.pidCount ?? 0,
        activeConnections: matched?.activeConnections ?? 0,
        path: matched?.path ?? "",
      };
    });
  }, [selectedTunApp, state.managedApps]);

  const runAction = async (action: () => Promise<unknown>) => {
    try {
      await action();
      await refresh();
      setError("");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      try {
        const next = normalizeState(await invoke<AppState>("GetState"));
        applyNextState(next);
      } catch {}
      setError(message);
    }
  };

  const submitRule = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!editingRule) return;
    const suggested = detectRuleType(editingRule.value);
    await runAction(() => invoke("UpsertRule", { ...editingRule, type: editingRule.type || suggested.type, value: suggested.value }));
    setEditingRule(null);
  };

  const saveSettings = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      const next = normalizeState(await invoke<AppState>("SaveSettings", settingsDraft));
      applyNextState(next, true);
      setError("");
      setSettingsMessage("设置已保存到 .PRM 目录；已按当前上游配置自动补全代理出口限制默认值（如适用）");
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      try {
        const next = normalizeState(await invoke<AppState>("GetState"));
        applyNextState(next);
      } catch {}
      setError(message);
    }
  };

  const mergeStringItems = (current: string[], incoming: string[]) => {
    const seen = new Set<string>();
    const next: string[] = [];
    for (const raw of [...current, ...incoming]) {
      const value = raw.trim();
      if (!value) continue;
      const key = value.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      next.push(value);
    }
    return next;
  };

  const upsertTunAppProfile = (profile: TunAppProfile) => {
    const normalized = createTunAppProfile({
      ...profile,
      queries: mergeStringItems([], profile.queries ?? []),
    });
    const nextProfiles = [...settingsDraft.tunAppProfiles];
    const index = nextProfiles.findIndex((item) => item.id === normalized.id && normalized.id);
    if (index >= 0) {
      nextProfiles[index] = normalized;
    } else {
      normalized.id = normalized.id || `tun-app-${Date.now()}`;
      nextProfiles.push(normalized);
    }
    updateSettingsDraft({ tunAppProfiles: nextProfiles });
    setSelectedTunAppId(normalized.id);
  };

  const deleteTunAppProfile = (id: string) => {
    const nextProfiles = settingsDraft.tunAppProfiles.filter((item) => item.id !== id);
    updateSettingsDraft({ tunAppProfiles: nextProfiles });
    setSelectedTunAppId((prev) => (prev === id ? nextProfiles[0]?.id ?? "" : prev));
  };

  const openNewTunApp = () => {
    setTunAppPresetId(appPresets[0]?.id ?? "");
    setEditingTunApp(applyTunPreset(appPresets[0]?.id ?? "", { id: "", name: "", queries: [] }));
  };

  const openEditTunApp = () => {
    if (!selectedTunApp) return;
    setTunAppPresetId("");
    setEditingTunApp(createTunAppProfile(selectedTunApp));
  };

  const submitTunApp = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!editingTunApp) return;
    upsertTunAppProfile(editingTunApp);
    setEditingTunApp(null);
    setSettingsMessage(`已更新透明接管应用：${editingTunApp.name || "未命名应用"}，保存设置后生效。`);
  };

  const exportDiagnostics = async () => {
    try {
      const path = await invoke<string>("ExportAgentDiagnostics");
      setSettingsMessage(`诊断已导出: ${path}`);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const openDataDirectory = async () => {
    try {
      await invoke<void>("OpenDataDirectory");
      setSettingsMessage("已打开 .PRM 目录");
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const submitBatchRules = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      const result = await invoke<BatchRuleResult>("BatchUpsertRules", batchDraft);
      const next = normalizeState(result.state);
      applyNextState(next);
      setBatchDraft({ ...batchDraft, content: "" });
      setBatchMessage(`已新增 ${result.addedCount} 条，合并重复 ${result.mergedCount} 条，跳过 ${result.skipped.filter((item) => !item.duplicate).length} 条。`);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const openNewRule = () => {
    setEditingRule({
      id: "",
      enabled: true,
      type: "DOMAIN-SUFFIX",
      value: "",
      target: "DIRECT",
      folder: "",
      remark: "",
    });
  };

  const openRuleFromLog = (log: TrafficLog, target: RuleTarget) => {
    const detected = detectRuleType(log.host);
    setEditingRule({
      id: "",
      enabled: true,
      type: detected.type,
      value: detected.value,
      target,
      folder: "",
      remark: `来自日志 ${log.host}`,
    });
  };

  const applyDetectedRuleType = () => {
    if (!editingRule) return;
    const detected = detectRuleType(editingRule.value);
    setEditingRule({ ...editingRule, type: detected.type, value: detected.value });
  };

  return (
    <div className="shell">
      <div className="app-frame">
        <aside className="sidebar">
          <div className="sidebar-hero">
            <p className="eyebrow">Windows PAC + Local Routing Proxy</p>
            <h1>Proxy Rule Manager</h1>
            <p className="subtitle">
              浏览器流量先进本地分流代理，再由规则决定进入上游代理通道，还是保持直连。
            </p>
          </div>

          <div className="sidebar-stack">
            <div className="sidebar-nav">
              <button className={`nav-item ${activeSection === "console" ? "active" : ""}`} onClick={() => setActiveSection("console")}>
                <span>控制台</span>
                <small>{state.status.activeConnectionCount} 活跃</small>
              </button>
              <button className={`nav-item ${activeSection === "rules" ? "active" : ""}`} onClick={() => setActiveSection("rules")}>
                <span>规则管理</span>
                <small>{state.status.ruleCount} 条</small>
              </button>
              <button className={`nav-item ${activeSection === "logs" ? "active" : ""}`} onClick={() => setActiveSection("logs")}>
                <span>实时日志</span>
                <small>{state.status.recentLogCount} 条</small>
              </button>
              <button className={`nav-item ${activeSection === "settings" ? "active" : ""}`} onClick={() => setActiveSection("settings")}>
                  <span>系统设置</span>
                <small>{state.status.upstreamProxyReachable ? "上游代理 OK" : "需检查"}</small>
              </button>
            </div>

            <div className="sidebar-pills">
              <span className={`pill ${state.status.upstreamProxyReachable ? "ok" : "warn"}`}>{state.status.upstreamProxyMessage || "状态检测中"}</span>
              <span className={`pill ${state.status.systemPacEnabled ? "ok" : ""}`}>System PAC {state.status.systemPacEnabled ? "Enabled" : "Disabled"}</span>
            </div>

            {(error || state.status.lastError) && <div className="error-banner">{error || state.status.lastError}</div>}
            {batchMessage && <div className="info-banner">{batchMessage}</div>}
          </div>
        </aside>

        <main className="content">
          {activeSection === "console" && (
          <div className="content-section content-grid">
            <div className="panel panel-flat">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Console</p>
                  <h2>控制台</h2>
                </div>
                <button className="ghost" onClick={() => void refreshStatus()}>刷新状态</button>
              </div>
              <div className="content-cards">
                <StatusCard title="PAC 服务" value={state.status.pacRunning ? "运行中" : "未运行"} meta={state.status.pacUrl} accent={state.status.pacRunning} />
                <StatusCard title="本地分流代理" value={state.status.proxyRunning ? "运行中" : "未运行"} meta={state.status.proxyAddr} accent={state.status.proxyRunning} />
                <StatusCard title="系统 PAC" value={state.status.systemPacEnabled ? "已启用" : "未启用"} meta={state.status.currentAutoConfigURL || "未设置"} accent={state.status.systemPacEnabled} />
                <StatusCard title="上游代理" value={state.status.upstreamProxyReachable ? "可连接" : "不可连接"} meta={state.status.upstreamProxyMessage} accent={state.status.upstreamProxyReachable} />
                <StatusCard title="代理节点路由" value={state.status.upstreamProxyRouteApplied ? "已应用" : "未应用"} meta={state.status.upstreamProxyRouteMessage || "未配置"} accent={state.status.upstreamProxyRouteApplied} />
                <StatusCard title="代理出口限制" value={state.config.proxyGuardEnabled ? (state.status.proxyGuardApplied ? "已应用" : "待处理") : "未启用"} meta={state.status.proxyGuardMessage || "未配置"} accent={state.status.proxyGuardApplied} />
              </div>
            </div>

            <div className="panel panel-flat">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Actions</p>
                  <h2>快捷操作</h2>
                </div>
              </div>
              <div className="console-switches">
                <button
                  className={`switch-btn ${state.status.pacRunning ? "active" : "inactive"}`}
                  onClick={() => void runAction(() => state.status.pacRunning ? invoke("StopPacService") : invoke("StartPacService"))}
                >
                  PAC 服务
                </button>
                <button
                  className={`switch-btn ${state.status.proxyRunning ? "active" : "inactive"}`}
                  onClick={() => void runAction(() => state.status.proxyRunning ? invoke("StopProxyService") : invoke("StartProxyService"))}
                >
                  本地分流代理
                </button>
                <button
                  className={`switch-btn ${state.status.systemPacEnabled ? "active" : "inactive"}`}
                  onClick={() => void runAction(() => state.status.systemPacEnabled ? invoke("DisableSystemPac") : invoke("EnableSystemPac"))}
                >
                  系统 PAC
                </button>
                <button
                  className={`switch-btn ${state.status.tunRunning ? "active" : "inactive"}`}
                  onClick={() => void runAction(() => state.status.tunRunning ? invoke("StopTunService") : invoke("StartTunService"))}
                >
                  应用透明接管
                </button>
              </div>
              <div className="hint">
                透明接管状态: {state.status.tunMessage || "未检测"}
              </div>
              <div className="hint">
                代理出口限制: {state.status.proxyGuardMessage || "未检测"}
              </div>
              <div className="hint">
                代理节点路由: {state.status.upstreamProxyRouteMessage || "未检测"}
              </div>
              <div className="console-actions secondary-actions">
                <button className="ghost" onClick={() => void runAction(() => invoke("PauseTrafficRouting"))}>暂停分流</button>
                <button className="ghost" onClick={() => void runAction(() => invoke("ClearLogs"))}>清空日志</button>
                <button className="ghost" onClick={() => void runAction(() => invoke("ExportConfig"))}>导出配置</button>
                <button className="ghost" onClick={() => void runAction(() => invoke("ImportConfig"))}>导入配置</button>
              </div>
              <div className="hint">“暂停分流”会保留 PRM 窗口，但会停掉系统 PAC、本地分流代理、应用透明接管，并撤销代理出口限制；恢复时按上面的开关重新开启即可。</div>
            </div>

            <div className="panel panel-flat console-overview">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Overview</p>
                  <h2>当前概览</h2>
                </div>
              </div>
              <div className="overview-grid">
                <div className="overview-item">
                  <span>启用规则</span>
                  <strong>{state.status.enabledRuleCount}</strong>
                </div>
                <div className="overview-item">
                  <span>最近日志</span>
                  <strong>{state.status.recentLogCount}</strong>
                </div>
                <div className="overview-item">
                  <span>受管应用</span>
                  <strong>{state.status.managedAppCount}</strong>
                </div>
                <div className="overview-item">
                  <span>受管进程</span>
                  <strong>{state.status.managedProcessCount}</strong>
                </div>
                <div className="overview-item">
                  <span>应用连接</span>
                  <strong>{state.status.managedConnectionCount}</strong>
                </div>
                <div className="overview-item">
                  <span>透明接管</span>
                  <strong>{state.status.tunRunning ? "ON" : "OFF"}</strong>
                </div>
                <div className="overview-item">
                  <span>受控代理进程</span>
                  <strong>{state.status.proxyGuardProgramCount}</strong>
                </div>
                <div className="overview-item">
                  <span>重定向包数</span>
                  <strong>{state.status.tunPacketCount}</strong>
                </div>
                <div className="overview-item">
                  <span>重定向流量</span>
                  <strong>{formatBytes(state.status.tunByteCount)}</strong>
                </div>
              </div>
              <div className="hint">透明接管: {state.status.tunMessage || "未检测"}</div>
            </div>

            <div className="panel panel-flat">
              <div className="section-head">
                <div>
                  <p className="eyebrow">Adapters</p>
                  <h2>网卡控制</h2>
                </div>
              </div>
              <div className="preview-list">
                {state.availableNetworkAdapters.map((adapter) => {
                  const isUp = adapter.status === "Up";
                  return (
                    <div key={adapter.name} className="preview-item">
                      <strong>{adapter.name}</strong>
                      <span className="muted">{adapter.description || "无描述"}</span>
                      <span className="muted">状态: {adapter.status || "Unknown"}</span>
                      <div className="inline-actions compact-actions-single">
                        <button
                          className="small"
                          onClick={() => void runAction(() => invoke("SetNetworkAdapterEnabled", adapter.name, !isUp))}
                        >
                          {isUp ? "停用" : "启用"}
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
              {state.availableNetworkAdapters.length === 0 && <div className="hint">当前未检测到可控制网卡。</div>}
            </div>
          </div>
          )}

          {activeSection === "rules" && (
          <div className="content-section">
            <div className="section-head">
              <div>
                <p className="eyebrow">Rules</p>
                <h2>规则管理</h2>
              </div>
              <button onClick={openNewRule}>新增规则</button>
            </div>
            <div className="panel panel-flat">
              <div className="panel-header">
                <div className="toolbar compact-toolbar">
                  <select value={ruleFolderFilter} onChange={(e) => setRuleFolderFilter(e.target.value)}>
                    <option value="ALL">全部分类夹</option>
                    {availableRuleFolders.map((folder) => <option key={folder} value={folder}>{folder}</option>)}
                  </select>
                </div>
              </div>
              <div className="desktop-table">
              <table>
                <thead>
                  <tr>
                    <th>启用</th>
                    <th>分类夹</th>
                    <th>类型</th>
                    <th>值</th>
                    <th>目标</th>
                    <th>备注</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleRules.map((rule) => (
                    <tr key={rule.id}>
                      <td>{rule.enabled ? "Yes" : "No"}</td>
                      <td>{rule.folder || "未分类"}</td>
                      <td>{rule.type}</td>
                      <td className="mono">{rule.value}</td>
                      <td>{rule.target}</td>
                      <td>{rule.remark}</td>
                      <td>
                        <div className="inline-actions">
                          <button className="small" onClick={() => setEditingRule(rule)}>编辑</button>
                          <button className="small ghost" onClick={() => void runAction(() => invoke("MoveRule", rule.id, "up"))}>上移</button>
                          <button className="small ghost" onClick={() => void runAction(() => invoke("MoveRule", rule.id, "down"))}>下移</button>
                          {rule.type !== "MATCH" && <button className="small ghost danger" onClick={() => void runAction(() => invoke("DeleteRule", rule.id))}>删除</button>}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
              <div className="compact-list">
                {visibleRules.map((rule) => (
                  <div key={rule.id} className="compact-card">
                    <div className="compact-card-head">
                      <strong className="mono">{rule.value}</strong>
                      <span className={`pill ${rule.target === "PROXY" ? "ok" : rule.target === "REJECT" ? "warn" : ""}`}>{rule.target}</span>
                    </div>
                    <div className="compact-meta">
                      <span>{rule.enabled ? "启用" : "禁用"}</span>
                      <span>{rule.type}</span>
                      <span>{rule.folder || "未分类"}</span>
                    </div>
                    {rule.remark && <div className="compact-note">{rule.remark}</div>}
                    <div className="inline-actions compact-actions">
                      <button className="small" onClick={() => setEditingRule(rule)}>编辑</button>
                      <button className="small ghost" onClick={() => void runAction(() => invoke("MoveRule", rule.id, "up"))}>上移</button>
                      <button className="small ghost" onClick={() => void runAction(() => invoke("MoveRule", rule.id, "down"))}>下移</button>
                      {rule.type !== "MATCH" && <button className="small ghost danger" onClick={() => void runAction(() => invoke("DeleteRule", rule.id))}>删除</button>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
          )}

          {activeSection === "logs" && (
          <div className="content-section">
            <div className="section-head">
              <div>
                <p className="eyebrow">Traffic</p>
                <h2>实时流量日志</h2>
              </div>
            </div>
            <div className="panel panel-flat">
              <div className="panel-header">
                <div className="toolbar compact-toolbar">
                  <input placeholder="按 host 过滤" value={hostFilter} onChange={(e) => setHostFilter(e.target.value)} />
                  <select value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value as "ALL" | "APP" | "WEB")}>
                    <option value="ALL">全部来源</option>
                    <option value="APP">App</option>
                    <option value="WEB">网页</option>
                  </select>
                  <select value={targetFilter} onChange={(e) => setTargetFilter(e.target.value as RuleTarget | "ALL")}>
                    <option value="ALL">全部目标</option>
                    {ruleTargets.map((item) => <option key={item} value={item}>{item}</option>)}
                  </select>
                  <select value={logLimit} onChange={(e) => setLogLimit(Number(e.target.value) as 100 | 500)}>
                    <option value={100}>最近 100 条</option>
                    <option value={500}>最近 500 条</option>
                  </select>
                </div>
              </div>
              <div className="desktop-table">
              <table>
                <thead>
                  <tr>
                    <th>时间</th>
                    <th>Host</th>
                    <th>端口</th>
                    <th>协议</th>
                    <th>命中规则</th>
                    <th>目标</th>
                    <th>上传</th>
                    <th>下载</th>
                    <th>耗时</th>
                    <th>状态</th>
                    <th>路径</th>
                    <th>快捷加规则</th>
                    <th>错误</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredLogs.map((item) => (
                    <LogRow
                      key={item.id}
                      item={item}
                      onAddRule={() => openRuleFromLog(item, item.target === "REJECT" ? "DIRECT" : item.target)}
                    />
                  ))}
                </tbody>
              </table>
              </div>
              <div className="compact-list">
                {filteredLogs.map((item) => (
                  <div key={item.id} className="compact-card">
                    <div className="compact-card-head">
                      <strong className="mono">{item.host}</strong>
                      <span className={`pill ${item.target === "PROXY" ? "ok" : item.target === "REJECT" ? "warn" : ""}`}>{item.target}</span>
                    </div>
                    <div className="compact-meta">
                      <span>{new Date(item.time).toLocaleTimeString()}</span>
                      <span>{item.protocol}</span>
                      <span>{item.port}</span>
                    </div>
                    {(item.processName || item.source) && (
                      <div className="compact-meta">
                        <span>{item.source === "process" ? "应用流量" : "网页流量"}</span>
                        {item.processName && <span>{item.processName}{item.processId ? ` #${item.processId}` : ""}</span>}
                      </div>
                    )}
                    <div className="compact-note compact-ellipsis">{`${item.matchedRuleType}:${item.matchedRuleValue}`}</div>
                    <div className="compact-note compact-ellipsis">{item.path}</div>
                    <div className="compact-meta">
                      <span>{formatBytes(item.uploadBytes)} ↑</span>
                      <span>{formatBytes(item.downloadBytes)} ↓</span>
                      <span>{formatDuration(item.durationMs)}</span>
                    </div>
                    <div className="inline-actions compact-actions compact-actions-single">
                      <button className="small" onClick={() => openRuleFromLog(item, item.target === "REJECT" ? "DIRECT" : item.target)}>
                        添加规则
                      </button>
                    </div>
                    {item.error && <div className="compact-note compact-error">{item.error}</div>}
                  </div>
                ))}
              </div>
            </div>
          </div>
          )}

          {activeSection === "settings" && (
            <div className="content-section content-grid settings-grid">
              <div className="panel panel-flat">
                <div className="section-head">
                  <div>
                    <p className="eyebrow">Batch</p>
                    <h2>批量添加规则</h2>
                  </div>
                </div>
                <form className="form-grid" onSubmit={submitBatchRules}>
                  <label className="full">
                    批量内容
                    <textarea
                      rows={10}
                      value={batchDraft.content}
                      onChange={(e) => setBatchDraft({ ...batchDraft, content: e.target.value })}
                      placeholder={"chat.openai.com\nhttps://platform.openai.com\n*.oaistatic.com\nkeyword:openai\n1.2.3.4/32"}
                    />
                  </label>
                  <label>
                    目标
                    <select value={batchDraft.target} onChange={(e) => setBatchDraft({ ...batchDraft, target: e.target.value as RuleTarget })}>
                      {ruleTargets.map((item) => <option key={item} value={item}>{item}</option>)}
                    </select>
                  </label>
                  <label>
                    分类夹
                    <input value={batchDraft.folder} onChange={(e) => setBatchDraft({ ...batchDraft, folder: e.target.value })} placeholder="例如：开发 / GitHub" />
                  </label>
                  <label>
                    备注
                    <input value={batchDraft.remark} onChange={(e) => setBatchDraft({ ...batchDraft, remark: e.target.value })} placeholder="例如：一组 AI 站点" />
                  </label>
                  <label className="check full">
                    <input type="checkbox" checked={batchDraft.enabled} onChange={(e) => setBatchDraft({ ...batchDraft, enabled: e.target.checked })} />
                    导入后立即启用
                  </label>
                  <button type="submit">批量写入</button>
                </form>
                {batchPreview.length > 0 && (
                  <div className="preview-list">
                    {batchPreview.map((item) => (
                      <div key={`${item.raw}-${item.value}`} className="preview-item">
                        <span className="mono">{item.raw}</span>
                        <span className="muted">{item.type}</span>
                        <span className="mono">{item.value}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="panel panel-flat">
                <div className="section-head">
                  <div>
                    <p className="eyebrow">Config</p>
                    <h2>系统设置</h2>
                  </div>
                  <div className="console-actions secondary-actions">
                    <button type="button" className="ghost" onClick={() => void openDataDirectory()}>打开 .PRM 目录</button>
                    <button type="button" className="ghost" onClick={() => void exportDiagnostics()}>导出诊断</button>
                  </div>
                </div>
                {settingsMessage && <div className="hint full">{settingsMessage}</div>}
                <form className="form-grid" onSubmit={saveSettings}>
                  <label>
                    兼容字段：接口名
                    <input value={settingsDraft.tunInterfaceName} onChange={(e) => updateSettingsDraft({ tunInterfaceName: e.target.value })} />
                  </label>
                  <label>
                    兼容字段：地址段
                    <input value={settingsDraft.tunAddressCidr} onChange={(e) => updateSettingsDraft({ tunAddressCidr: e.target.value })} />
                  </label>
                  <label>
                    兼容字段：MTU
                    <input type="number" min={1280} max={9000} value={settingsDraft.tunMtu} onChange={(e) => updateSettingsDraft({ tunMtu: Number(e.target.value) })} />
                  </label>
                  <label>
                    PAC 监听地址
                    <input value={settingsDraft.pacListenAddr} onChange={(e) => updateSettingsDraft({ pacListenAddr: e.target.value })} />
                  </label>
                  <label>
                    本地分流代理地址
                    <input value={settingsDraft.proxyListenAddr} onChange={(e) => updateSettingsDraft({ proxyListenAddr: e.target.value })} />
                  </label>
                  <label>
                    上游代理地址
                    <input value={settingsDraft.upstreamProxyAddr} onChange={(e) => updateSettingsDraft({ upstreamProxyAddr: e.target.value })} />
                  </label>
                  <label>
                    上游类型
                    <select value={settingsDraft.upstreamProxyType} onChange={(e) => updateSettingsDraft({ upstreamProxyType: e.target.value })}>
                      <option value="http">HTTP CONNECT</option>
                      <option value="socks">SOCKS</option>
                    </select>
                  </label>
                  <label>
                    上游代理出口网卡
                    <select value={settingsDraft.proxyInterfaceName} onChange={(e) => updateSettingsDraft({ proxyInterfaceName: e.target.value })}>
                      <option value="">未指定</option>
                      {adapterOptions.map((adapter) => (
                        <option key={`proxy-${adapter.name}`} value={adapter.name}>{formatAdapterLabel(adapter)}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    代理节点路由网卡
                    <select value={settingsDraft.upstreamProxyRouteInterface} onChange={(e) => updateSettingsDraft({ upstreamProxyRouteInterface: e.target.value })}>
                      <option value="">跟随上游代理出口网卡</option>
                      {adapterOptions.map((adapter) => (
                        <option key={`upstream-route-${adapter.name}`} value={adapter.name}>{formatAdapterLabel(adapter)}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    代理进程出口网卡
                    <select value={settingsDraft.proxyGuardInterface} onChange={(e) => updateSettingsDraft({ proxyGuardInterface: e.target.value })}>
                      <option value="">未指定</option>
                      {adapterOptions.map((adapter) => (
                        <option key={`guard-${adapter.name}`} value={adapter.name}>{formatAdapterLabel(adapter)}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    直连出口网卡
                    <select value={settingsDraft.directInterfaceName} onChange={(e) => updateSettingsDraft({ directInterfaceName: e.target.value })}>
                      <option value="">未指定</option>
                      {adapterOptions.map((adapter) => (
                        <option key={`direct-${adapter.name}`} value={adapter.name}>{formatAdapterLabel(adapter)}</option>
                      ))}
                    </select>
                  </label>
                  {adapterOptions.length === 0 && (
                    <div className="hint full">当前未自动识别到可选物理网卡，请检查网卡状态或以管理员身份重新启动应用。</div>
                  )}
                  <label>
                    日志上限
                    <input type="number" min={100} max={5000} value={settingsDraft.maxLogEntries} onChange={(e) => updateSettingsDraft({ maxLogEntries: Number(e.target.value) })} />
                  </label>
                  <label className="full">
                    代理节点 IP
                    <textarea
                      rows={3}
                      value={(settingsDraft.upstreamProxyRouteTargets ?? []).join("\n")}
                      onChange={(e) => updateSettingsDraft({ upstreamProxyRouteTargets: e.target.value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean) })}
                      placeholder={"203.0.113.10\n198.51.100.8/32"}
                    />
                  </label>
                  <label className="check full">
                    <input type="checkbox" checked={settingsDraft.upstreamProxyRouteEnabled} onChange={(e) => updateSettingsDraft({ upstreamProxyRouteEnabled: e.target.checked })} />
                    启用代理节点 /32 路由
                  </label>
                  <div className="hint full">启用后，程序会把手动填写的节点 IP，以及自动识别到的上游代理进程当前远端 IPv4，添加为 `/32` 路由并指向所选网关；不会调整全局网卡 metric。</div>
                  <label className="full">
                    受控代理进程路径
                    <textarea
                      rows={4}
                      value={(settingsDraft.proxyGuardProgramPaths ?? []).join("\n")}
                      onChange={(e) => updateSettingsDraft({ proxyGuardProgramPaths: e.target.value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean) })}
                      placeholder={"D:\\Program Files\\Clash\\clash.exe\nD:\\Program Files\\sing-box\\sing-box.exe"}
                    />
                  </label>
                  <label className="check full">
                    <input type="checkbox" checked={settingsDraft.proxyGuardEnabled} onChange={(e) => updateSettingsDraft({ proxyGuardEnabled: e.target.checked })} />
                    启用代理进程出口限制
                  </label>
                  <div className="hint full">当上游代理地址是 `127.0.0.1` 或 `localhost` 时，要固定真正的外网出口，可以直接启用这里的限制。若“代理进程出口网卡”留空，会默认跟随“上游代理出口网卡”；若“受控代理进程路径”留空，程序会优先尝试按本地监听端口自动识别代理进程。</div>
                  <div className="full tun-app-manager">
                    <div className="tun-app-header">
                      <span className="tun-app-title">透明接管应用名单</span>
                      <select value={selectedTunApp?.id ?? ""} onChange={(e) => setSelectedTunAppId(e.target.value)}>
                        {settingsDraft.tunAppProfiles.map((profile) => (
                          <option key={profile.id} value={profile.id}>{profile.name || "未命名应用"}</option>
                        ))}
                      </select>
                    </div>
                    {selectedTunApp ? (
                      <>
                        <div className="hint">
                          {selectedTunApp.remark || routingModeOptions.find((item) => item.value === selectedTunApp.routingMode)?.description || "未填写说明"}
                        </div>
                        <div className="preview-item tun-app-summary">
                          <strong>{selectedTunApp.name || "未命名应用"}</strong>
                          <span className="muted">策略：{routingModeOptions.find((item) => item.value === selectedTunApp.routingMode)?.label || selectedTunApp.routingMode}</span>
                          <span className="muted">数据面：{selectedTunApp.bypassTransparentProxy ? "绕过透明接管，仅监控" : "进入透明接管"}</span>
                          <span className="muted">匹配进程：{selectedTunApp.queries.join("、") || "未填写"}</span>
                        </div>
                      </>
                    ) : (
                      <div className="hint">当前还没有配置透明接管应用，可先点下方“添加应用”。</div>
                    )}
                    {selectedTunAppStatuses.length > 0 ? (
                      <div className="preview-list tun-app-preview">
                        {selectedTunAppStatuses.map((item) => (
                          <div key={item.query} className="preview-item tun-app-card">
                            <strong className="mono">{item.query}</strong>
                            <span className="muted">
                              {item.running ? `运行中，${item.pidCount} 个进程 / ${item.activeConnections} 条连接` : "当前未检测到运行中的匹配进程"}
                            </span>
                            {item.path && <span className="muted compact-ellipsis">{item.path}</span>}
                          </div>
                        ))}
                      </div>
                    ) : selectedTunApp ? <div className="hint">当前应用还没有配置匹配进程。</div> : null}
                    <div className="inline-actions tun-app-actions">
                      <button type="button" className="ghost" onClick={openEditTunApp} disabled={!selectedTunApp}>
                        修改配置
                      </button>
                      <button type="button" onClick={openNewTunApp}>
                        添加应用
                      </button>
                    </div>
                    {selectedTunApp && settingsDraft.tunAppProfiles.length > 1 && (
                      <button type="button" className="ghost danger" onClick={() => deleteTunAppProfile(selectedTunApp.id)}>
                        删除当前应用
                      </button>
                    )}
                  </div>
                  <label className="check full">
                    <input type="checkbox" checked={settingsDraft.autoStartTunService} onChange={(e) => updateSettingsDraft({ autoStartTunService: e.target.checked })} />
                    启动时自动启动应用透明接管
                  </label>
                  <div className="hint full">`Codex.exe` 会覆盖桌面主进程，`codex.exe` 会覆盖内置 CLI / resources 子进程，`codex-command-runner-*.exe` 用来兜住带版本号的命令执行子进程。</div>
                  <div className="hint full">未勾选“绕过透明接管”的应用会进入透明接管数据面；已绕过的应用只做进程监控，不参与逐包转发。</div>
                  <div className="hint full">当前透明接管由 WinDivert 在 Windows 上按进程拦截 TCP 连接，再通过本程序经上游 HTTP CONNECT 或 SOCKS5 建立隧道。</div>
                  <div className="hint full">如果上游代理地址填写的是 `127.0.0.1` 或 `localhost`，最终外网出口仍由那个本地代理程序自己决定；需要固定出口时，请继续使用“代理进程出口限制”。</div>
                  <div className="hint full">当前优先透明接管 TCP；对已识别到实际路径的目标进程，会额外下发 UDP 出站阻断规则，尽量压住 QUIC/UDP 旁路。</div>
                  <label className="check full">
                    <input type="checkbox" checked={settingsDraft.autoStartPacService} onChange={(e) => updateSettingsDraft({ autoStartPacService: e.target.checked })} />
                    启动时自动启动 PAC 服务
                  </label>
                  <label className="check full">
                    <input type="checkbox" checked={settingsDraft.autoStartProxyService} onChange={(e) => updateSettingsDraft({ autoStartProxyService: e.target.checked })} />
                    启动时自动启动本地分流代理
                  </label>
                  <label className="check full">
                    <input type="checkbox" checked={settingsDraft.autoEnableSystemPac} onChange={(e) => updateSettingsDraft({ autoEnableSystemPac: e.target.checked })} />
                    启动时自动启用系统 PAC
                  </label>
                  <label className="check full">
                    <input type="checkbox" checked={settingsDraft.disableSystemPacOnExit} onChange={(e) => updateSettingsDraft({ disableSystemPacOnExit: e.target.checked })} />
                    退出时自动停用系统 PAC
                  </label>
                  <button type="submit">保存设置</button>
                </form>
              </div>
            </div>
          )}
        </main>
      </div>

      {editingTunApp && (
        <div className="modal-backdrop">
          <div className="modal">
            <div className="panel-header">
              <h2>{editingTunApp.id ? "编辑透明接管应用" : "新增透明接管应用"}</h2>
              <button className="ghost" onClick={() => setEditingTunApp(null)}>关闭</button>
            </div>
            <form className="form-grid compact-form" onSubmit={submitTunApp}>
              <label>
                预设模板
                <div className="inline-actions">
                  <select value={tunAppPresetId} onChange={(e) => setTunAppPresetId(e.target.value)}>
                    <option value="">不套用预设</option>
                    {appPresetCategories.map(([category, presets]) => (
                      <optgroup key={category} label={category}>
                        {presets.map((preset) => (
                          <option key={preset.id} value={preset.id}>{preset.label}</option>
                        ))}
                      </optgroup>
                    ))}
                  </select>
                  <button
                    type="button"
                    className="ghost"
                    onClick={() => tunAppPresetId && setEditingTunApp(applyTunPreset(tunAppPresetId, editingTunApp))}
                    disabled={!tunAppPresetId}
                  >
                    套用预设
                  </button>
                </div>
              </label>
              <label>
                应用名称
                <input value={editingTunApp.name} onChange={(e) => setEditingTunApp({ ...editingTunApp, name: e.target.value })} placeholder="例如：Steam Desktop / My Custom App" />
              </label>
              <label>
                连接策略
                <select value={editingTunApp.routingMode} onChange={(e) => setEditingTunApp({ ...editingTunApp, routingMode: e.target.value as TunAppRoutingMode })}>
                  {routingModeOptions.map((item) => (
                    <option key={item.value} value={item.value}>{item.label}</option>
                  ))}
                </select>
              </label>
              <div className="hint full">{routingModeOptions.find((item) => item.value === editingTunApp.routingMode)?.description || "未选择策略"}</div>
              <label className="check full">
                <input type="checkbox" checked={editingTunApp.bypassTransparentProxy} onChange={(e) => setEditingTunApp({ ...editingTunApp, bypassTransparentProxy: e.target.checked })} />
                高吞吐应用绕过透明接管，仅保留进程监控
              </label>
              <div className="hint full">开启后，这组进程不会进入 WinDivert 逐包透明转发路径，适合 Steam、游戏下载器、网盘同步等大流量下载应用。</div>
              <label className="full">
                匹配进程
                <textarea
                  rows={5}
                  value={(editingTunApp.queries ?? []).join("\n")}
                  onChange={(e) => setEditingTunApp({ ...editingTunApp, queries: e.target.value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean) })}
                  placeholder={"steam.exe\nsteamwebhelper.exe\nC:\\Program Files\\MyApp\\myapp.exe"}
                />
              </label>
              <label className="full">
                说明
                <textarea rows={3} value={editingTunApp.remark} onChange={(e) => setEditingTunApp({ ...editingTunApp, remark: e.target.value })} placeholder="说明这个应用组的用途或特殊策略" />
              </label>
              <label className="check full">
                <input type="checkbox" checked={editingTunApp.enabled} onChange={(e) => setEditingTunApp({ ...editingTunApp, enabled: e.target.checked })} />
                启用这个透明接管应用配置
              </label>
              <button type="submit">保存应用配置</button>
            </form>
          </div>
        </div>
      )}

      {editingRule && (
        <div className="modal-backdrop">
          <div className="modal">
            <div className="panel-header">
              <h2>{editingRule.id ? "编辑规则" : "新增规则"}</h2>
              <button className="ghost" onClick={() => setEditingRule(null)}>关闭</button>
            </div>
            <form className="form-grid" onSubmit={submitRule}>
              <label>
                类型
                <select value={editingRule.type} onChange={(e) => setEditingRule({ ...editingRule, type: e.target.value as RuleType })}>
                  {ruleTypes.map((item) => <option key={item} value={item}>{item}</option>)}
                </select>
              </label>
              <label>
                目标
                <select value={editingRule.target} onChange={(e) => setEditingRule({ ...editingRule, target: e.target.value as RuleTarget })}>
                  {ruleTargets.map((item) => <option key={item} value={item}>{item}</option>)}
                </select>
              </label>
              <label className="full">
                规则值
                <div className="inline-field wrap-field">
                  <input value={editingRule.value} onChange={(e) => setEditingRule({ ...editingRule, value: e.target.value })} required />
                  <button type="button" className="ghost" onClick={applyDetectedRuleType}>自动识别</button>
                </div>
              </label>
              <label className="full">
                备注
                <input value={editingRule.remark} onChange={(e) => setEditingRule({ ...editingRule, remark: e.target.value })} />
              </label>
              <label className="full">
                分类夹
                <input value={editingRule.folder} onChange={(e) => setEditingRule({ ...editingRule, folder: e.target.value })} placeholder="留空时按已知站点自动归类" />
              </label>
              <label className="check">
                <input type="checkbox" checked={editingRule.enabled} onChange={(e) => setEditingRule({ ...editingRule, enabled: e.target.checked })} />
                启用规则
              </label>
                <div className="hint full">
                  已知站点在这里会自动补齐同组兄弟域名，例如 `github.com` 会顺带补上 `githubassets.com`、`githubusercontent.com`。
                </div>
                <div className="hint full">
                  当前识别建议：`{detectRuleType(editingRule.value).type}` / `{detectRuleType(editingRule.value).value || "待输入"}`
                </div>
                <button type="submit">保存规则</button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

function StatusCard({ title, value, meta, accent }: { title: string; value: string; meta: string; accent?: boolean }) {
  return (
    <div className={`status-card ${accent ? "accent" : ""}`}>
      <span>{title}</span>
      <strong>{value}</strong>
      <small>{meta}</small>
    </div>
  );
}

function LogRow({
  item,
  onAddRule,
}: {
  item: TrafficLog;
  onAddRule: () => void;
}) {
  return (
    <tr>
      <td>{new Date(item.time).toLocaleTimeString()}</td>
      <td className="mono">{item.host}</td>
      <td>{item.port}</td>
      <td>{item.protocol}</td>
      <td className="mono">{`${item.matchedRuleIndex}. ${item.matchedRuleType}:${item.matchedRuleValue}`}</td>
      <td><span className={`pill ${item.target === "PROXY" ? "ok" : item.target === "REJECT" ? "warn" : ""}`}>{item.target}</span></td>
      <td>{formatBytes(item.uploadBytes)}</td>
      <td>{formatBytes(item.downloadBytes)}</td>
      <td>{formatDuration(item.durationMs)}</td>
      <td>{item.status}</td>
      <td>{item.path}</td>
      <td>
        <div className="inline-actions compact-actions-single">
          <button className="small" onClick={onAddRule}>添加规则</button>
        </div>
      </td>
      <td>{item.error}</td>
    </tr>
  );
}

export default App;
