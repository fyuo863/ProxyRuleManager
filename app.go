package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"proxy-rule-manager/internal/appmonitor"
	"proxy-rule-manager/internal/config"
	"proxy-rule-manager/internal/external"
	"proxy-rule-manager/internal/logs"
	"proxy-rule-manager/internal/model"
	"proxy-rule-manager/internal/netadapter"
	"proxy-rule-manager/internal/pac"
	"proxy-rule-manager/internal/prmfs"
	"proxy-rule-manager/internal/proxy"
	"proxy-rule-manager/internal/proxyguard"
	"proxy-rule-manager/internal/rules"
	"proxy-rule-manager/internal/tun"
	"proxy-rule-manager/internal/winproxy"
)

type App struct {
	ctx          context.Context
	config       *config.Store
	ruleEngine   *rules.Engine
	logStore     *logs.Store
	pacServer    *pac.Server
	proxySrv     *proxy.Server
	appMonitor   appmonitor.Service
	proxyGuard   proxyguard.Service
	tunService   tun.Service
	adaptersSeen []model.NetworkAdapterOption
	adaptersAt   time.Time
	pacRunning   bool
	proxyRunning bool
	tunRunning   bool
	lastError    string
}

func NewApp() *App {
	return &App{
		ruleEngine: rules.NewEngine(),
		proxyGuard: proxyguard.NewService(),
		tunService: tun.NewService(),
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	// Ensure external runtime components are available under user's .PRM layout.
	if err := external.EnsureComponents(); err != nil {
		// record error but continue; specific services will surface missing components when started
		a.lastError = "external components: " + err.Error()
	}

	store, err := config.NewStore()
	if err != nil {
		a.lastError = err.Error()
		return
	}
	a.config = store
	a.logStore = logs.NewStore(store.Get().MaxLogEntries)
	a.appMonitor = appmonitor.NewService(a.addLog, a.updateLog, a.managedAppRouteHint)
	a.rebuildServices()
	a.appMonitor.Start(store.Get().TunIncludedApps)
	if err := a.reconcileProxyGuard(store.Get()); err != nil {
		a.lastError = err.Error()
	}

	cfg := a.config.Get()
	if cfg.AutoStartPacService {
		_ = a.StartPacService()
	}
	if cfg.AutoStartProxyService {
		_ = a.StartProxyService()
	}
	if cfg.AutoEnableSystemPac {
		if !a.pacRunning {
			_ = a.StartPacService()
		}
		if !a.proxyRunning {
			_ = a.StartProxyService()
		}
		_ = a.EnableSystemPac()
	}
	if cfg.AutoStartTunService {
		_ = a.StartTunService()
	}
}

func (a *App) shutdown(ctx context.Context) {
	if a.config != nil {
		cfg := a.config.Get()
		if cfg.DisableSystemPacOnExit && cfg.SavedWindowsProxy != nil {
			_ = winproxy.Restore(*cfg.SavedWindowsProxy)
		}
	}
	a.stopServers()
}

func (a *App) rebuildServices() {
	cfg := a.config.Get()
	a.logStore.SetMax(cfg.MaxLogEntries)
	a.pacServer = pac.NewServer(cfg.PacListenAddr, cfg.ProxyListenAddr)
	a.proxySrv = proxy.NewServer(cfg.ProxyListenAddr, cfg.FastLinkProxyAddr, a.matchRule, a.addLog, a.updateLog)
}

func (a *App) stopServers() {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if a.pacServer != nil {
		_ = a.pacServer.Stop(ctx)
	}
	if a.proxySrv != nil {
		_ = a.proxySrv.Stop(ctx)
	}
	if a.tunService != nil {
		_ = a.tunService.Stop()
	}
	if a.appMonitor != nil {
		a.appMonitor.Stop()
	}
	a.pacRunning = false
	a.proxyRunning = false
	a.tunRunning = false
}

func (a *App) matchRule(host string) (model.Rule, model.MatchedRule) {
	return a.ruleEngine.Match(host, a.config.Get().Rules)
}

func (a *App) addLog(entry model.TrafficLog) {
	a.logStore.Add(entry)
	a.emitState()
}

func (a *App) updateLog(id string, mutator func(*model.TrafficLog)) {
	a.logStore.Update(id, mutator)
	a.emitState()
}

func (a *App) emitState() {
	if a.ctx == nil {
		return
	}
	wruntime.EventsEmit(a.ctx, "state:updated")
}

func (a *App) GetState() model.AppState {
	return a.getState(false)
}

func (a *App) getState(forceAdapters bool) model.AppState {
	if a.config == nil {
		return model.AppState{}
	}

	cfg := a.config.Get()
	currentProxyCfg, err := winproxy.ReadCurrentConfig()
	if err != nil {
		a.lastError = err.Error()
	}

	fastLinkReachable, fastLinkMessage := a.probeFastLink(cfg.FastLinkProxyAddr)

	enabledRules := 0
	for _, rule := range cfg.Rules {
		if rule.Enabled {
			enabledRules++
		}
	}
	managedSnapshot := appmonitor.Snapshot{}
	if a.appMonitor != nil {
		managedSnapshot = a.appMonitor.Snapshot()
	}
	adapters := a.availableNetworkAdapters(forceAdapters)
	proxyGuardStatus := model.ProxyGuardRuntimeStatus{Message: "代理进程出口限制未初始化"}
	if a.proxyGuard != nil {
		proxyGuardStatus = a.proxyGuard.Status()
	}
	tunStatus := a.tunService.Status(model.TunOptions{
		InterfaceName:   cfg.TunInterfaceName,
		AddressCIDR:     cfg.TunAddressCIDR,
		MTU:             cfg.TunMTU,
		IncludedApps:    cfg.TunIncludedApps,
		FastLinkAddr:    cfg.FastLinkProxyAddr,
		FastLinkType:    cfg.FastLinkProxyType,
		ProxyInterface:  cfg.ProxyInterfaceName,
		DirectInterface: cfg.DirectInterfaceName,
		Rules:           cfg.Rules,
	})

	return model.AppState{
		Config: cfg,
		Status: model.ServiceStatus{
			PacRunning:             a.pacRunning,
			PacURL:                 "http://" + cfg.PacListenAddr + "/proxy.pac",
			ProxyRunning:           a.proxyRunning,
			ProxyAddr:              cfg.ProxyListenAddr,
			ProxyGuardApplied:      proxyGuardStatus.Applied,
			ProxyGuardMessage:      proxyGuardStatus.Message,
			ProxyGuardProgramCount: proxyGuardStatus.ProgramCount,
			TunRunning:             a.tunRunning && tunStatus.Running,
			TunAvailable:           tunStatus.Available,
			TunMessage:             tunStatus.Message,
			TunIncludedAppCount:    len(cfg.TunIncludedApps),
			ManagedAppCount:        len(managedSnapshot.ManagedApps),
			ManagedProcessCount:    managedSnapshot.ManagedProcessCount,
			ManagedConnectionCount: managedSnapshot.ManagedConnectionCount,
			TunPacketCount:         tunStatus.PacketCount,
			TunByteCount:           tunStatus.ByteCount,
			SystemPacEnabled:       currentProxyCfg.AutoConfigURL == "http://"+cfg.PacListenAddr+"/proxy.pac",
			CurrentAutoConfigURL:   currentProxyCfg.AutoConfigURL,
			FastLinkReachable:      fastLinkReachable,
			FastLinkMessage:        fastLinkMessage,
			RuleCount:              len(cfg.Rules),
			EnabledRuleCount:       enabledRules,
			ActiveConnectionCount:  a.logStore.ActiveCount(),
			RecentLogCount:         a.logStore.Count(),
			LastError:              a.lastError,
		},
		Logs:                     a.logStore.List(),
		ManagedApps:              managedSnapshot.ManagedApps,
		AvailableNetworkAdapters: adapters,
	}
}

func (a *App) probeFastLink(addr string) (bool, string) {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return false, "上游代理地址为空"
	}
	host, port, err := net.SplitHostPort(trimmed)
	if err != nil {
		return false, "上游代理地址格式无效，应为 host:port"
	}
	if a.hasObservedFastLinkConnection(host, port) {
		return true, "已检测到应用与上游代理的活动连接"
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		conn, dialErr := net.DialTimeout("tcp", trimmed, 1200*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			return true, "上游代理端口可连接"
		}
		lastErr = dialErr
		if attempt < 2 {
			time.Sleep(150 * time.Millisecond)
		}
	}
	if lastErr == nil {
		return false, "上游代理端口不可用，请检查代理客户端或远端代理是否可达"
	}
	return false, fmt.Sprintf("上游代理端口不可用: %v", lastErr)
}

func (a *App) hasObservedFastLinkConnection(host, port string) bool {
	if a.logStore == nil {
		return false
	}
	for _, item := range a.logStore.List() {
		if item.Source != "process" || item.Status != model.TrafficStatusActive {
			continue
		}
		if strings.TrimSpace(item.Port) != strings.TrimSpace(port) {
			continue
		}
		if sameEndpointHost(item.Host, host) {
			return true
		}
	}
	return false
}

func sameEndpointHost(observed, configured string) bool {
	left := strings.Trim(strings.TrimSpace(observed), "[]")
	right := strings.Trim(strings.TrimSpace(configured), "[]")
	if strings.EqualFold(left, right) {
		return true
	}
	if strings.EqualFold(right, "localhost") {
		if strings.EqualFold(left, "localhost") {
			return true
		}
		if ip := net.ParseIP(left); ip != nil && ip.IsLoopback() {
			return true
		}
		return false
	}
	if configuredIP := net.ParseIP(right); configuredIP != nil {
		if observedIP := net.ParseIP(left); observedIP != nil {
			if configuredIP.Equal(observedIP) {
				return true
			}
			if configuredIP.IsLoopback() && observedIP.IsLoopback() {
				return true
			}
		}
	}
	return false
}

func (a *App) StartPacService() error {
	if a.pacRunning {
		return nil
	}
	if a.pacServer == nil {
		a.rebuildServices()
	}
	if err := a.pacServer.Start(); err != nil {
		a.lastError = err.Error()
		return err
	}
	a.pacRunning = true
	a.lastError = ""
	a.emitState()
	return nil
}

func (a *App) StopPacService() error {
	if a.pacServer == nil || !a.pacRunning {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := a.pacServer.Stop(ctx)
	if err != nil {
		a.lastError = err.Error()
		return err
	}
	cfg := a.config.Get()
	a.pacServer = pac.NewServer(cfg.PacListenAddr, cfg.ProxyListenAddr)
	a.pacRunning = false
	a.emitState()
	return nil
}

func (a *App) StartProxyService() error {
	if a.proxyRunning {
		return nil
	}
	if a.proxySrv == nil {
		a.rebuildServices()
	}
	if err := a.proxySrv.Start(); err != nil {
		a.lastError = err.Error()
		return err
	}
	a.proxyRunning = true
	a.lastError = ""
	a.emitState()
	return nil
}

func (a *App) StopProxyService() error {
	if a.proxySrv == nil || !a.proxyRunning {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := a.proxySrv.Stop(ctx)
	if err != nil {
		a.lastError = err.Error()
		return err
	}
	cfg := a.config.Get()
	a.proxySrv = proxy.NewServer(cfg.ProxyListenAddr, cfg.FastLinkProxyAddr, a.matchRule, a.addLog, a.updateLog)
	a.proxyRunning = false
	a.emitState()
	return nil
}

func (a *App) StartTunService() error {
	cfg := a.config.Get()
	err := a.tunService.Start(model.TunOptions{
		InterfaceName:   cfg.TunInterfaceName,
		AddressCIDR:     cfg.TunAddressCIDR,
		MTU:             cfg.TunMTU,
		IncludedApps:    cfg.TunIncludedApps,
		FastLinkAddr:    cfg.FastLinkProxyAddr,
		FastLinkType:    cfg.FastLinkProxyType,
		ProxyInterface:  cfg.ProxyInterfaceName,
		DirectInterface: cfg.DirectInterfaceName,
		Rules:           cfg.Rules,
	})
	if err != nil {
		a.lastError = err.Error()
		a.emitState()
		return err
	}
	a.tunRunning = true
	a.lastError = ""
	a.emitState()
	return nil
}

func (a *App) StopTunService() error {
	if err := a.tunService.Stop(); err != nil {
		a.lastError = err.Error()
		a.emitState()
		return err
	}
	a.tunRunning = false
	a.lastError = ""
	a.emitState()
	return nil
}

func (a *App) PauseTrafficRouting() (model.AppState, error) {
	var errs []error

	if err := a.DisableSystemPac(); err != nil {
		errs = append(errs, err)
	}
	if a.tunRunning {
		if err := a.StopTunService(); err != nil {
			errs = append(errs, err)
		}
	}
	if a.proxyRunning {
		if err := a.StopProxyService(); err != nil {
			errs = append(errs, err)
		}
	}
	if a.pacRunning {
		if err := a.StopPacService(); err != nil {
			errs = append(errs, err)
		}
	}

	cfg := a.config.Get()
	cfg.ProxyGuardEnabled = false
	if err := a.reconcileProxyGuard(cfg); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		joined := errors.Join(errs...)
		a.lastError = joined.Error()
		return a.GetState(), joined
	}

	a.lastError = ""
	return a.GetState(), nil
}

func (a *App) EnableSystemPac() error {
	cfg := a.config.Get()
	if !a.pacRunning || !a.proxyRunning {
		return errors.New("启用系统 PAC 前，请先启动 PAC 服务和本地分流代理")
	}

	if current, err := winproxy.ReadCurrentConfig(); err == nil && cfg.SavedWindowsProxy == nil {
		_ = a.config.Update(func(config *model.AppConfig) error {
			config.SavedWindowsProxy = &current
			return nil
		})
		_ = a.config.Save()
		cfg = a.config.Get()
	}

	url := "http://" + cfg.PacListenAddr + "/proxy.pac"
	if err := winproxy.ApplyPAC(url); err != nil {
		a.lastError = err.Error()
		return err
	}
	a.lastError = ""
	a.emitState()
	return nil
}

func (a *App) DisableSystemPac() error {
	cfg := a.config.Get()
	if cfg.SavedWindowsProxy == nil {
		return nil
	}
	if err := winproxy.Restore(*cfg.SavedWindowsProxy); err != nil {
		a.lastError = err.Error()
		return err
	}
	a.lastError = ""
	a.emitState()
	return nil
}

func (a *App) RefreshStatus() model.AppState {
	return a.getState(true)
}

func (a *App) ClearLogs() model.AppState {
	a.logStore.Clear()
	a.emitState()
	return a.GetState()
}

func (a *App) UpsertRule(rule model.Rule) (model.AppState, error) {
	if rule.Type == model.RuleTypeMatch {
		return a.GetState(), errors.New("MATCH,DIRECT 兜底规则由系统维护，不能单独编辑为其它形式")
	}
	rule = a.normalizeSingleRule(rule)
	expandedRules := a.expandRuleSet(rule)

	err := a.config.Update(func(cfg *model.AppConfig) error {
		for _, item := range expandedRules {
			if item.ID == "" {
				item.ID = uuid.NewString()
			}
			a.applyRuleChange(cfg, item)
		}
		return nil
	})
	if err != nil {
		return a.GetState(), err
	}
	if err := a.config.Save(); err != nil {
		return a.GetState(), err
	}
	if err := a.reloadTunIfRunning(); err != nil {
		return a.GetState(), err
	}
	return a.GetState(), nil
}

func (a *App) BatchUpsertRules(request model.BatchRuleRequest) (model.BatchRuleResult, error) {
	items := splitBatchContent(request.Content)
	if len(items) == 0 {
		return model.BatchRuleResult{State: a.GetState()}, errors.New("没有可导入的规则内容")
	}

	var added []model.BatchRuleItem
	var skipped []model.BatchRuleItem
	addedCount := 0
	mergedCount := 0

	err := a.config.Update(func(cfg *model.AppConfig) error {
		for _, raw := range items {
			rule, ok := rules.NormalizeRuleInput(raw, request.Target, request.Folder, request.Remark, request.Enabled)
			if !ok {
				skipped = append(skipped, model.BatchRuleItem{Raw: raw})
				continue
			}
			for _, item := range a.expandRuleSet(rule) {
				item.ID = uuid.NewString()
				change := a.applyRuleChange(cfg, item)
				entry := model.BatchRuleItem{
					Raw:    raw,
					Type:   item.Type,
					Value:  item.Value,
					Target: item.Target,
					Folder: item.Folder,
				}
				switch change {
				case "merged":
					entry.Duplicate = true
					skipped = append(skipped, entry)
					mergedCount++
				case "added":
					added = append(added, entry)
					addedCount++
				}
			}
		}
		return nil
	})
	if err != nil {
		return model.BatchRuleResult{State: a.GetState()}, err
	}
	if err := a.config.Save(); err != nil {
		return model.BatchRuleResult{State: a.GetState()}, err
	}
	if err := a.reloadTunIfRunning(); err != nil {
		return model.BatchRuleResult{State: a.GetState()}, err
	}

	return model.BatchRuleResult{
		State:       a.GetState(),
		AddedCount:  addedCount,
		MergedCount: mergedCount,
		Skipped:     skipped,
		Added:       added,
	}, nil
}

func (a *App) DeleteRule(id string) (model.AppState, error) {
	err := a.config.Update(func(cfg *model.AppConfig) error {
		filtered := make([]model.Rule, 0, len(cfg.Rules))
		for _, rule := range cfg.Rules {
			if rule.ID == id && rule.Type == model.RuleTypeMatch {
				return errors.New("不能删除 MATCH,DIRECT 兜底规则")
			}
			if rule.ID != id {
				filtered = append(filtered, rule)
			}
		}
		cfg.Rules = filtered
		return nil
	})
	if err != nil {
		return a.GetState(), err
	}
	if err := a.config.Save(); err != nil {
		return a.GetState(), err
	}
	if err := a.reloadTunIfRunning(); err != nil {
		return a.GetState(), err
	}
	return a.GetState(), nil
}

func (a *App) MoveRule(id string, direction string) (model.AppState, error) {
	err := a.config.Update(func(cfg *model.AppConfig) error {
		for idx := range cfg.Rules {
			if cfg.Rules[idx].ID != id {
				continue
			}
			if cfg.Rules[idx].Type == model.RuleTypeMatch {
				return errors.New("MATCH,DIRECT 兜底规则必须保持最后一条")
			}
			target := idx - 1
			if direction == "down" {
				target = idx + 1
			}
			if target < 0 || target >= len(cfg.Rules)-1 {
				return nil
			}
			cfg.Rules[idx], cfg.Rules[target] = cfg.Rules[target], cfg.Rules[idx]
			return nil
		}
		return nil
	})
	if err != nil {
		return a.GetState(), err
	}
	if err := a.config.Save(); err != nil {
		return a.GetState(), err
	}
	if err := a.reloadTunIfRunning(); err != nil {
		return a.GetState(), err
	}
	return a.GetState(), nil
}

func (a *App) reloadTunIfRunning() error {
	if !a.tunRunning {
		return nil
	}
	if err := a.StopTunService(); err != nil {
		return err
	}
	return a.StartTunService()
}

func (a *App) SaveSettings(next model.AppConfig) (model.AppState, error) {
	restartPac := a.pacRunning
	restartProxy := a.proxyRunning
	restartTun := a.tunRunning

	prepared, err := proxyguard.PrepareConfig(next)
	if err == nil {
		next = prepared
	}

	err = a.config.Update(func(cfg *model.AppConfig) error {
		cfg.PacListenAddr = next.PacListenAddr
		cfg.ProxyListenAddr = next.ProxyListenAddr
		cfg.FastLinkProxyAddr = next.FastLinkProxyAddr
		cfg.FastLinkProxyType = next.FastLinkProxyType
		cfg.ProxyInterfaceName = next.ProxyInterfaceName
		cfg.ProxyGuardEnabled = next.ProxyGuardEnabled
		cfg.ProxyGuardInterface = next.ProxyGuardInterface
		cfg.ProxyGuardProgramPaths = next.ProxyGuardProgramPaths
		cfg.DirectInterfaceName = next.DirectInterfaceName
		cfg.TunInterfaceName = next.TunInterfaceName
		cfg.TunAddressCIDR = next.TunAddressCIDR
		cfg.TunMTU = next.TunMTU
		cfg.TunIncludedApps = next.TunIncludedApps
		cfg.AutoStartTunService = next.AutoStartTunService
		cfg.AutoStartPacService = next.AutoStartPacService
		cfg.AutoStartProxyService = next.AutoStartProxyService
		cfg.AutoEnableSystemPac = next.AutoEnableSystemPac
		cfg.DisableSystemPacOnExit = next.DisableSystemPacOnExit
		cfg.MaxLogEntries = next.MaxLogEntries
		return nil
	})
	if err != nil {
		return a.GetState(), err
	}
	if err := a.config.Save(); err != nil {
		return a.GetState(), err
	}
	if a.appMonitor != nil {
		a.appMonitor.UpdateIncludedApps(next.TunIncludedApps)
	}

	if restartPac {
		_ = a.StopPacService()
	}
	if restartProxy {
		_ = a.StopProxyService()
	}
	if restartTun {
		_ = a.StopTunService()
	}
	a.rebuildServices()
	if restartPac {
		if err := a.StartPacService(); err != nil {
			return a.GetState(), err
		}
	}
	if restartProxy {
		if err := a.StartProxyService(); err != nil {
			return a.GetState(), err
		}
	}
	if restartTun {
		if err := a.StartTunService(); err != nil {
			return a.GetState(), err
		}
	}
	if err := a.reconcileProxyGuard(a.config.Get()); err != nil {
		a.lastError = err.Error()
		return a.GetState(), err
	}
	a.lastError = ""
	return a.GetState(), nil
}

func (a *App) managedAppRouteHint(processName, processPath string) (model.RuleTarget, string) {
	if a.tunRunning {
		return model.RuleTargetProxy, "已识别到目标进程；当前应用级透明接管已启用，匹配进程的 TCP 连接会被直接导入上游代理链"
	}
	return model.RuleTargetDirect, "进程级识别已启用；当前仅观测应用连接，透明接管尚未启动"
}

func (a *App) ExportConfig() error {
	path, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		Title:           "导出配置",
		DefaultFilename: "proxy-rule-manager-config.json",
	})
	if err != nil || path == "" {
		return err
	}

	data, err := json.MarshalIndent(a.config.Get(), "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (a *App) ImportConfig() (model.AppState, error) {
	path, err := wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{
		Title: "导入配置",
	})
	if err != nil || path == "" {
		return a.GetState(), err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return a.GetState(), err
	}
	var cfg model.AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return a.GetState(), err
	}
	if err := a.config.Replace(cfg); err != nil {
		return a.GetState(), err
	}
	if err := a.config.Save(); err != nil {
		return a.GetState(), err
	}
	a.rebuildServices()
	if err := a.reconcileProxyGuard(a.config.Get()); err != nil {
		a.lastError = err.Error()
		return a.GetState(), err
	}
	return a.GetState(), nil
}

func (a *App) reconcileProxyGuard(cfg model.AppConfig) error {
	if a.proxyGuard == nil {
		return nil
	}
	prepared, err := proxyguard.PrepareConfig(cfg)
	if err != nil {
		return err
	}
	if a.config != nil && proxyGuardConfigChanged(cfg, prepared) {
		if updateErr := a.config.Update(func(current *model.AppConfig) error {
			current.ProxyGuardInterface = prepared.ProxyGuardInterface
			current.ProxyGuardProgramPaths = prepared.ProxyGuardProgramPaths
			return nil
		}); updateErr != nil {
			return updateErr
		}
		if saveErr := a.config.Save(); saveErr != nil {
			return saveErr
		}
		cfg = a.config.Get()
	} else {
		cfg = prepared
	}
	return a.proxyGuard.Reconcile(cfg)
}

func proxyGuardConfigChanged(before, after model.AppConfig) bool {
	if strings.TrimSpace(before.ProxyGuardInterface) != strings.TrimSpace(after.ProxyGuardInterface) {
		return true
	}
	if len(before.ProxyGuardProgramPaths) != len(after.ProxyGuardProgramPaths) {
		return true
	}
	for idx := range before.ProxyGuardProgramPaths {
		if before.ProxyGuardProgramPaths[idx] != after.ProxyGuardProgramPaths[idx] {
			return true
		}
	}
	return false
}

func (a *App) availableNetworkAdapters(force bool) []model.NetworkAdapterOption {
	const cacheTTL = 15 * time.Second
	if !force && len(a.adaptersSeen) > 0 && time.Since(a.adaptersAt) < cacheTTL {
		return append([]model.NetworkAdapterOption(nil), a.adaptersSeen...)
	}

	adapters, err := netadapter.List()
	if err != nil {
		return append([]model.NetworkAdapterOption(nil), a.adaptersSeen...)
	}

	a.adaptersSeen = adapters
	a.adaptersAt = time.Now()
	return append([]model.NetworkAdapterOption(nil), a.adaptersSeen...)
}

func (a *App) OpenConfigLocation() error {
	path := a.config.Path()
	wruntime.BrowserOpenURL(a.ctx, "file:///"+path)
	return nil
}

func (a *App) OpenDataDirectory() error {
	root, err := prmfs.RootDir()
	if err != nil {
		return err
	}
	wruntime.BrowserOpenURL(a.ctx, "file:///"+root)
	return nil
}

func (a *App) SetNetworkAdapterEnabled(name string, enabled bool) (model.AppState, error) {
	if err := netadapter.SetEnabled(name, enabled); err != nil {
		a.lastError = err.Error()
		return a.getState(true), err
	}
	a.adaptersSeen = nil
	a.adaptersAt = time.Time{}
	if err := a.reconcileProxyGuard(a.config.Get()); err != nil {
		a.lastError = err.Error()
		return a.getState(true), err
	}
	a.lastError = ""
	return a.getState(true), nil
}

func (a *App) normalizeSingleRule(rule model.Rule) model.Rule {
	if detectedType, detectedValue := rules.DetectRuleType(rule.Value); rule.Type == "" || strings.TrimSpace(rule.Value) != detectedValue {
		switch rule.Type {
		case model.RuleTypeDomain, model.RuleTypeDomainSuffix, model.RuleTypeDomainKeyword, model.RuleTypeDomainRegex, model.RuleTypeIPCIDR:
			rule.Value = detectedValue
			if rule.Type == model.RuleTypeDomain && detectedType == model.RuleTypeDomainSuffix {
				if strings.Count(detectedValue, ".") <= 1 {
					rule.Type = model.RuleTypeDomain
				}
			}
		default:
			rule.Type = detectedType
			rule.Value = detectedValue
		}
	}
	rule.Value = strings.TrimSpace(rule.Value)
	rule.Folder = strings.TrimSpace(rule.Folder)
	rule.Remark = strings.TrimSpace(rule.Remark)
	rule.Folder = rules.DefaultFolderForRule(rule)
	rule.Remark = rules.DefaultRemarkForRule(rule)
	return rule
}

func (a *App) expandRuleSet(rule model.Rule) []model.Rule {
	expanded := rules.ExpandRuleSiblings(rule)
	out := make([]model.Rule, 0, len(expanded))
	for _, item := range expanded {
		out = append(out, a.normalizeSingleRule(item))
	}
	return out
}

func (a *App) applyRuleChange(cfg *model.AppConfig, rule model.Rule) string {
	insertAt := len(cfg.Rules) - 1
	for idx := range cfg.Rules {
		if cfg.Rules[idx].ID == rule.ID && rule.ID != "" {
			cfg.Rules[idx] = rule
			a.mergeDuplicateRules(cfg, rule.ID)
			return "updated"
		}
	}
	for idx := range cfg.Rules {
		if rules.EquivalentRule(cfg.Rules[idx], rule) {
			cfg.Rules[idx].Enabled = rule.Enabled
			if strings.TrimSpace(rule.Folder) != "" {
				cfg.Rules[idx].Folder = rule.Folder
			}
			if strings.TrimSpace(rule.Remark) != "" {
				cfg.Rules[idx].Remark = mergeRemarks(cfg.Rules[idx].Remark, rule.Remark)
			}
			return "merged"
		}
	}
	cfg.Rules = append(cfg.Rules[:insertAt], append([]model.Rule{rule}, cfg.Rules[insertAt:]...)...)
	return "added"
}

func (a *App) mergeDuplicateRules(cfg *model.AppConfig, keepID string) {
	filtered := make([]model.Rule, 0, len(cfg.Rules))
	var keep *model.Rule
	for idx := range cfg.Rules {
		if cfg.Rules[idx].ID == keepID {
			keep = &cfg.Rules[idx]
			break
		}
	}
	for _, rule := range cfg.Rules {
		if keep != nil && rule.ID != keepID && rules.EquivalentRule(rule, *keep) {
			if strings.TrimSpace(rule.Remark) != "" {
				keep.Remark = mergeRemarks(keep.Remark, rule.Remark)
			}
			continue
		}
		filtered = append(filtered, rule)
	}
	cfg.Rules = filtered
}

func splitBatchContent(content string) []string {
	normalized := strings.NewReplacer("\r\n", "\n", "\r", "\n", "，", ",", "；", ";").Replace(content)
	parts := strings.FieldsFunc(normalized, func(r rune) bool {
		return r == '\n' || r == ',' || r == ';' || r == '\t'
	})
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func mergeRemarks(left, right string) string {
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	switch {
	case left == "":
		return right
	case right == "":
		return left
	case left == right:
		return left
	default:
		return left + " | " + right
	}
}
