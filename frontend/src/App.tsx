import { FormEvent, useEffect, useMemo, useState } from "react";
import type {
  AppConfig,
  AppState,
  BatchRuleRequest,
  BatchRuleResult,
  Rule,
  RuleTarget,
  RuleType,
  TrafficLog,
} from "./wails";

const emptyState: AppState = {
  config: {
    rules: [],
    pacListenAddr: "127.0.0.1:18088",
    proxyListenAddr: "127.0.0.1:18089",
    fastLinkProxyAddr: "127.0.0.1:7892",
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
    systemPacEnabled: false,
    currentAutoConfigURL: "",
    fastLinkReachable: false,
    fastLinkMessage: "",
    ruleCount: 0,
    enabledRuleCount: 0,
    activeConnectionCount: 0,
    recentLogCount: 0,
    lastError: "",
  },
  logs: [],
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
  const [targetFilter, setTargetFilter] = useState<RuleTarget | "ALL">("ALL");
  const [logLimit, setLogLimit] = useState<100 | 500>(100);
  const [editingRule, setEditingRule] = useState<Rule | null>(null);
  const [settingsDraft, setSettingsDraft] = useState<AppConfig>(emptyState.config);
  const [activeSection, setActiveSection] = useState<"console" | "rules" | "logs" | "settings">("console");
  const [batchDraft, setBatchDraft] = useState<BatchRuleRequest>({
    content: "",
    target: "PROXY",
    remark: "",
    enabled: true,
  });
  const [batchMessage, setBatchMessage] = useState<string>("");

  const refresh = async () => {
    try {
      const next = await invoke<AppState>("GetState");
      setState(next);
      setSettingsDraft(next.config);
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
    if (targetFilter !== "ALL") {
      items = items.filter((item) => item.target === targetFilter);
    }
    return items.slice(0, logLimit);
  }, [state.logs, hostFilter, targetFilter, logLimit]);

  const batchPreview = useMemo(() => {
    return batchDraft.content
      .split(/[\n,;\t]+/)
      .map((item) => item.trim())
      .filter(Boolean)
      .slice(0, 8)
      .map((item) => ({ raw: item, ...detectRuleType(item) }));
  }, [batchDraft.content]);

  const runAction = async (action: () => Promise<unknown>) => {
    try {
      await action();
      await refresh();
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
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
    await runAction(() => invoke("SaveSettings", settingsDraft));
  };

  const submitBatchRules = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      const result = await invoke<BatchRuleResult>("BatchUpsertRules", batchDraft);
      setState(result.state);
      setSettingsDraft(result.state.config);
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
              浏览器流量先进本地分流代理，再由规则决定走 FastLink + Wi-Fi，还是 DIRECT + 有线。
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
                <small>{state.status.fastLinkReachable ? "FastLink OK" : "需检查"}</small>
              </button>
            </div>

            <div className="sidebar-pills">
              <span className={`pill ${state.status.fastLinkReachable ? "ok" : "warn"}`}>{state.status.fastLinkMessage || "状态检测中"}</span>
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
                <button className="ghost" onClick={() => void refresh()}>刷新状态</button>
              </div>
              <div className="content-cards">
                <StatusCard title="PAC 服务" value={state.status.pacRunning ? "运行中" : "未运行"} meta={state.status.pacUrl} accent={state.status.pacRunning} />
                <StatusCard title="本地分流代理" value={state.status.proxyRunning ? "运行中" : "未运行"} meta={state.status.proxyAddr} accent={state.status.proxyRunning} />
                <StatusCard title="系统 PAC" value={state.status.systemPacEnabled ? "已启用" : "未启用"} meta={state.status.currentAutoConfigURL || "未设置"} accent={state.status.systemPacEnabled} />
                <StatusCard title="FastLink" value={state.status.fastLinkReachable ? "可连接" : "不可连接"} meta={state.status.fastLinkMessage} accent={state.status.fastLinkReachable} />
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
                  className={`switch-btn ${state.status.fastLinkReachable ? "active" : "inactive"}`}
                  onClick={() => void refresh()}
                >
                  FastLink
                </button>
              </div>
              <div className="console-actions secondary-actions">
                <button className="ghost" onClick={() => void runAction(() => invoke("ClearLogs"))}>清空日志</button>
                <button className="ghost" onClick={() => void runAction(() => invoke("ExportConfig"))}>导出配置</button>
                <button className="ghost" onClick={() => void runAction(() => invoke("ImportConfig"))}>导入配置</button>
              </div>
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
                  <span>总规则数</span>
                  <strong>{state.status.ruleCount}</strong>
                </div>
                <div className="overview-item">
                  <span>最近日志</span>
                  <strong>{state.status.recentLogCount}</strong>
                </div>
                <div className="overview-item">
                  <span>活跃连接</span>
                  <strong>{state.status.activeConnectionCount}</strong>
                </div>
              </div>
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
              <div className="desktop-table">
              <table>
                <thead>
                  <tr>
                    <th>启用</th>
                    <th>类型</th>
                    <th>值</th>
                    <th>目标</th>
                    <th>备注</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {state.config.rules.map((rule) => (
                    <tr key={rule.id}>
                      <td>{rule.enabled ? "Yes" : "No"}</td>
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
                {state.config.rules.map((rule) => (
                  <div key={rule.id} className="compact-card">
                    <div className="compact-card-head">
                      <strong className="mono">{rule.value}</strong>
                      <span className={`pill ${rule.target === "PROXY" ? "ok" : rule.target === "REJECT" ? "warn" : ""}`}>{rule.target}</span>
                    </div>
                    <div className="compact-meta">
                      <span>{rule.enabled ? "启用" : "禁用"}</span>
                      <span>{rule.type}</span>
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
              </div>
              <form className="form-grid" onSubmit={saveSettings}>
                <label>
                  PAC 监听地址
                  <input value={settingsDraft.pacListenAddr} onChange={(e) => setSettingsDraft({ ...settingsDraft, pacListenAddr: e.target.value })} />
                </label>
                <label>
                  本地分流代理地址
                  <input value={settingsDraft.proxyListenAddr} onChange={(e) => setSettingsDraft({ ...settingsDraft, proxyListenAddr: e.target.value })} />
                </label>
                <label>
                  FastLink 上游代理
                  <input value={settingsDraft.fastLinkProxyAddr} onChange={(e) => setSettingsDraft({ ...settingsDraft, fastLinkProxyAddr: e.target.value })} />
                </label>
                <label>
                  日志上限
                  <input type="number" min={100} max={5000} value={settingsDraft.maxLogEntries} onChange={(e) => setSettingsDraft({ ...settingsDraft, maxLogEntries: Number(e.target.value) })} />
                </label>
                <label className="check full">
                  <input type="checkbox" checked={settingsDraft.autoStartPacService} onChange={(e) => setSettingsDraft({ ...settingsDraft, autoStartPacService: e.target.checked })} />
                  启动时自动启动 PAC 服务
                </label>
                <label className="check full">
                  <input type="checkbox" checked={settingsDraft.autoStartProxyService} onChange={(e) => setSettingsDraft({ ...settingsDraft, autoStartProxyService: e.target.checked })} />
                  启动时自动启动本地分流代理
                </label>
                <label className="check full">
                  <input type="checkbox" checked={settingsDraft.autoEnableSystemPac} onChange={(e) => setSettingsDraft({ ...settingsDraft, autoEnableSystemPac: e.target.checked })} />
                  启动时自动启用系统 PAC
                </label>
                <label className="check full">
                  <input type="checkbox" checked={settingsDraft.disableSystemPacOnExit} onChange={(e) => setSettingsDraft({ ...settingsDraft, disableSystemPacOnExit: e.target.checked })} />
                  退出时自动停用系统 PAC
                </label>
                <button type="submit">保存设置</button>
              </form>
            </div>
          </div>
          )}
        </main>
      </div>

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
              <label className="check">
                <input type="checkbox" checked={editingRule.enabled} onChange={(e) => setEditingRule({ ...editingRule, enabled: e.target.checked })} />
                启用规则
              </label>
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
