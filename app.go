package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
	"proxy-rule-manager/internal/netroute"
	"proxy-rule-manager/internal/pac"
	"proxy-rule-manager/internal/prmfs"
	"proxy-rule-manager/internal/proxy"
	"proxy-rule-manager/internal/proxyguard"
	"proxy-rule-manager/internal/rules"
	"proxy-rule-manager/internal/tun"
	"proxy-rule-manager/internal/winproxy"
)

type App struct {
	ctx                      context.Context
	config                   *config.Store
	ruleEngine               *rules.Engine
	logStore                 *logs.Store
	pacServer                *pac.Server
	proxySrv                 *proxy.Server
	appMonitor               appmonitor.Service
	proxyGuard               proxyguard.Service
	tunService               tun.Service
	adaptersSeen             []model.NetworkAdapterOption
	adaptersAt               time.Time
	upstreamProxyRouteStatus model.UpstreamProxyRouteStatus
	pacRunning               bool
	proxyRunning             bool
	tunRunning               bool
	lastError                string
	systemPacGuardStop       chan struct{}
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
	a.appMonitor.Start(flattenTunAppProfileQueries(store.Get().TunAppProfiles, store.Get().TunIncludedApps))
	if err := a.reconcileProxyGuard(store.Get()); err != nil {
		a.lastError = err.Error()
	}
	if err := a.reconcileUpstreamProxyRoutes(store.Get()); err != nil {
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
		_ = a.EnableSystemPac()
	}
	if cfg.AutoStartTunService {
		_ = a.StartTunService()
	}
	a.startSystemPacGuard()
}

func (a *App) shutdown(ctx context.Context) {
	a.stopSystemPacGuard()
	if a.config != nil {
		cfg := a.config.Get()
		if cfg.DisableSystemPacOnExit && cfg.SavedWindowsProxy != nil {
			_ = winproxy.Restore(*cfg.SavedWindowsProxy)
		}
	}
	_ = a.clearUpstreamProxyRoutes()
	a.stopServers()
}

func (a *App) rebuildServices() {
	cfg := a.config.Get()
	a.logStore.SetMax(cfg.MaxLogEntries)
	a.pacServer = pac.NewServer(cfg.PacListenAddr, cfg.ProxyListenAddr)
	a.proxySrv = proxy.NewServer(cfg.ProxyListenAddr, cfg.UpstreamProxyAddr, cfg.DirectInterfaceName, a.matchRule, a.addLog, a.updateLog)
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

func (a *App) startSystemPacGuard() {
	if a.systemPacGuardStop != nil {
		return
	}
	stopCh := make(chan struct{})
	a.systemPacGuardStop = stopCh
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				a.ensureSystemPacOwnership()
			case <-stopCh:
				return
			}
		}
	}()
}

func (a *App) stopSystemPacGuard() {
	if a.systemPacGuardStop == nil {
		return
	}
	close(a.systemPacGuardStop)
	a.systemPacGuardStop = nil
}

func (a *App) ensureSystemPacOwnership() {
	if a.config == nil {
		return
	}
	cfg := a.config.Get()
	if !cfg.AutoEnableSystemPac {
		return
	}
	if err := a.ensurePacProxyChainReady(cfg); err != nil {
		a.lastError = err.Error()
		a.emitState()
		return
	}
	current, err := winproxy.ReadCurrentConfig()
	if err != nil {
		a.lastError = err.Error()
		a.emitState()
		return
	}
	expectedURL := "http://" + cfg.PacListenAddr + "/proxy.pac"
	if current.AutoConfigURL == expectedURL && !current.ProxyEnable && current.ProxyServer == "" {
		return
	}
	_ = a.EnableSystemPac()
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

	upstreamProxyReachable, upstreamProxyMessage := a.probeUpstreamProxy(cfg.UpstreamProxyAddr)
	pacReady := a.pacRunning && a.probePacServer(cfg) == nil
	proxyReady := a.proxyRunning && probeTCP(cfg.ProxyListenAddr) == nil

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
		InterfaceName:     cfg.TunInterfaceName,
		AddressCIDR:       cfg.TunAddressCIDR,
		MTU:               cfg.TunMTU,
		AppProfiles:       cfg.TunAppProfiles,
		IncludedApps:      flattenTunTransparentAppProfileQueries(cfg.TunAppProfiles, cfg.TunIncludedApps),
		UpstreamProxyAddr: cfg.UpstreamProxyAddr,
		UpstreamProxyType: cfg.UpstreamProxyType,
		ProxyInterface:    cfg.ProxyInterfaceName,
		DirectInterface:   cfg.DirectInterfaceName,
		Rules:             cfg.Rules,
	})

	return model.AppState{
		Config: cfg,
		Status: model.ServiceStatus{
			PacRunning:                pacReady,
			PacURL:                    "http://" + cfg.PacListenAddr + "/proxy.pac",
			ProxyRunning:              proxyReady,
			ProxyAddr:                 cfg.ProxyListenAddr,
			UpstreamProxyRouteApplied: a.upstreamProxyRouteStatus.Applied,
			UpstreamProxyRouteMessage: a.upstreamProxyRouteStatus.Message,
			UpstreamProxyRouteCount:   a.upstreamProxyRouteStatus.RouteCount,
			ProxyGuardApplied:         proxyGuardStatus.Applied,
			ProxyGuardMessage:         proxyGuardStatus.Message,
			ProxyGuardProgramCount:    proxyGuardStatus.ProgramCount,
			TunRunning:                a.tunRunning && tunStatus.Running,
			TunAvailable:              tunStatus.Available,
			TunMessage:                tunStatus.Message,
			TunIncludedAppCount:       len(flattenTunTransparentAppProfileQueries(cfg.TunAppProfiles, cfg.TunIncludedApps)),
			ManagedAppCount:           len(managedSnapshot.ManagedApps),
			ManagedProcessCount:       managedSnapshot.ManagedProcessCount,
			ManagedConnectionCount:    managedSnapshot.ManagedConnectionCount,
			TunPacketCount:            tunStatus.PacketCount,
			TunByteCount:              tunStatus.ByteCount,
			SystemPacEnabled:          currentProxyCfg.AutoConfigURL == "http://"+cfg.PacListenAddr+"/proxy.pac",
			CurrentAutoConfigURL:      currentProxyCfg.AutoConfigURL,
			UpstreamProxyReachable:    upstreamProxyReachable,
			UpstreamProxyMessage:      upstreamProxyMessage,
			RuleCount:                 len(cfg.Rules),
			EnabledRuleCount:          enabledRules,
			ActiveConnectionCount:     a.logStore.ActiveCount(),
			RecentLogCount:            a.logStore.Count(),
			LastError:                 a.lastError,
		},
		Logs:                     a.logStore.List(),
		ManagedApps:              managedSnapshot.ManagedApps,
		AvailableNetworkAdapters: adapters,
	}
}

func (a *App) probeUpstreamProxy(addr string) (bool, string) {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return false, "上游代理地址为空"
	}
	host, port, err := net.SplitHostPort(trimmed)
	if err != nil {
		return false, "上游代理地址格式无效，应为 host:port"
	}
	if a.hasObservedUpstreamProxyConnection(host, port) {
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

func (a *App) hasObservedUpstreamProxyConnection(host, port string) bool {
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
	cfg := a.config.Get()
	if a.pacRunning {
		if err := a.probePacServer(cfg); err == nil {
			return nil
		}
		a.resetPacService(cfg)
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
	cfg := a.config.Get()
	if a.proxyRunning {
		if err := probeTCP(cfg.ProxyListenAddr); err == nil {
			return nil
		}
		a.resetProxyService(cfg)
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
	a.proxySrv = proxy.NewServer(cfg.ProxyListenAddr, cfg.UpstreamProxyAddr, cfg.DirectInterfaceName, a.matchRule, a.addLog, a.updateLog)
	a.proxyRunning = false
	a.emitState()
	return nil
}

func (a *App) StartTunService() error {
	cfg := a.config.Get()
	err := a.tunService.Start(model.TunOptions{
		InterfaceName:     cfg.TunInterfaceName,
		AddressCIDR:       cfg.TunAddressCIDR,
		MTU:               cfg.TunMTU,
		AppProfiles:       cfg.TunAppProfiles,
		IncludedApps:      flattenTunTransparentAppProfileQueries(cfg.TunAppProfiles, cfg.TunIncludedApps),
		UpstreamProxyAddr: cfg.UpstreamProxyAddr,
		UpstreamProxyType: cfg.UpstreamProxyType,
		ProxyInterface:    cfg.ProxyInterfaceName,
		DirectInterface:   cfg.DirectInterfaceName,
		Rules:             cfg.Rules,
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
	cfg.UpstreamProxyRouteEnabled = false
	if err := a.reconcileUpstreamProxyRoutes(cfg); err != nil {
		errs = append(errs, err)
	}
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
	if err := a.ensurePacProxyChainReady(cfg); err != nil {
		a.lastError = err.Error()
		a.emitState()
		return err
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

func (a *App) ensurePacProxyChainReady(cfg model.AppConfig) error {
	if err := a.StartPacService(); err != nil {
		return fmt.Errorf("PAC 服务启动失败: %w", err)
	}
	if err := a.StartProxyService(); err != nil {
		return fmt.Errorf("本地分流代理启动失败: %w", err)
	}
	if err := a.probePacServer(cfg); err != nil {
		return fmt.Errorf("PAC 服务未就绪: %w", err)
	}
	if err := probeTCP(cfg.ProxyListenAddr); err != nil {
		return fmt.Errorf("本地分流代理未就绪: %w", err)
	}
	if ok, message := a.probeUpstreamProxy(cfg.UpstreamProxyAddr); !ok {
		return fmt.Errorf("上游代理 上游不可用: %s", message)
	}
	return nil
}

func (a *App) resetPacService(cfg model.AppConfig) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if a.pacServer != nil {
		_ = a.pacServer.Stop(ctx)
	}
	a.pacServer = pac.NewServer(cfg.PacListenAddr, cfg.ProxyListenAddr)
	a.pacRunning = false
}

func (a *App) resetProxyService(cfg model.AppConfig) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if a.proxySrv != nil {
		_ = a.proxySrv.Stop(ctx)
	}
	a.proxySrv = proxy.NewServer(cfg.ProxyListenAddr, cfg.UpstreamProxyAddr, cfg.DirectInterfaceName, a.matchRule, a.addLog, a.updateLog)
	a.proxyRunning = false
}

func (a *App) probePacServer(cfg model.AppConfig) error {
	url := "http://" + cfg.PacListenAddr + "/proxy.pac"
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s returned %s", url, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return err
	}
	expected := "PROXY " + cfg.ProxyListenAddr
	if !strings.Contains(string(body), expected) {
		return fmt.Errorf("PAC does not point to %s", cfg.ProxyListenAddr)
	}
	return nil
}

func probeTCP(addr string) error {
	conn, err := net.DialTimeout("tcp", strings.TrimSpace(addr), 1200*time.Millisecond)
	if err != nil {
		return err
	}
	return conn.Close()
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
	cfg := a.config.Get()
	if cfg.UpstreamProxyRouteEnabled {
		if err := a.reconcileUpstreamProxyRoutes(cfg); err != nil {
			a.lastError = err.Error()
		}
	}
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
	before := a.config.Get()
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
		cfg.UpstreamProxyAddr = next.UpstreamProxyAddr
		cfg.UpstreamProxyType = next.UpstreamProxyType
		cfg.ProxyInterfaceName = next.ProxyInterfaceName
		cfg.UpstreamProxyRouteEnabled = next.UpstreamProxyRouteEnabled
		cfg.UpstreamProxyRouteInterface = next.UpstreamProxyRouteInterface
		cfg.UpstreamProxyRouteTargets = next.UpstreamProxyRouteTargets
		cfg.ProxyGuardEnabled = next.ProxyGuardEnabled
		cfg.ProxyGuardInterface = next.ProxyGuardInterface
		cfg.ProxyGuardProgramPaths = next.ProxyGuardProgramPaths
		cfg.DirectInterfaceName = next.DirectInterfaceName
		cfg.TunInterfaceName = next.TunInterfaceName
		cfg.TunAddressCIDR = next.TunAddressCIDR
		cfg.TunMTU = next.TunMTU
		cfg.TunAppProfiles = next.TunAppProfiles
		cfg.TunIncludedApps = flattenTunAppProfileQueries(next.TunAppProfiles, next.TunIncludedApps)
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
	if strings.TrimSpace(before.DirectInterfaceName) != strings.TrimSpace(next.DirectInterfaceName) ||
		strings.TrimSpace(before.ProxyInterfaceName) != strings.TrimSpace(next.ProxyInterfaceName) {
		netadapter.ClearAddressCache()
	}
	if a.appMonitor != nil {
		a.appMonitor.UpdateIncludedApps(flattenTunAppProfileQueries(next.TunAppProfiles, next.TunIncludedApps))
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
	if next.AutoEnableSystemPac {
		if !a.pacRunning {
			if err := a.StartPacService(); err != nil {
				return a.GetState(), err
			}
		}
		if !a.proxyRunning {
			if err := a.StartProxyService(); err != nil {
				return a.GetState(), err
			}
		}
		if err := a.EnableSystemPac(); err != nil {
			return a.GetState(), err
		}
	}
	if err := a.reconcileProxyGuard(a.config.Get()); err != nil {
		a.lastError = err.Error()
		return a.GetState(), err
	}
	if err := a.reconcileUpstreamProxyRoutes(a.config.Get()); err != nil {
		a.lastError = err.Error()
		return a.GetState(), err
	}
	a.lastError = ""
	return a.GetState(), nil
}

func (a *App) managedAppRouteHint(processName, processPath string) (model.RuleTarget, string) {
	if a.tunRunning {
		return model.RuleTargetProxy, "已识别到目标进程；当前应用级透明接管已启用，会优先识别 TLS SNI / HTTP Host 并按规则决定 PROXY 或 DIRECT，未识别主机名时默认回退到代理链"
	}
	return model.RuleTargetDirect, "进程级识别已启用；当前仅观测应用连接，透明接管尚未启动"
}

func flattenTunAppProfileQueries(profiles []model.TunAppProfile, legacy []string) []string {
	if len(profiles) == 0 {
		return normalizeQueryList(legacy)
	}
	values := make([]string, 0, len(profiles)*2)
	for _, profile := range profiles {
		if !profile.Enabled {
			continue
		}
		values = append(values, profile.Queries...)
	}
	return normalizeQueryList(values)
}

func flattenTunTransparentAppProfileQueries(profiles []model.TunAppProfile, legacy []string) []string {
	if len(profiles) == 0 {
		return normalizeQueryList(legacy)
	}
	values := make([]string, 0, len(profiles)*2)
	for _, profile := range profiles {
		if !profile.Enabled || profile.BypassTransparentProxy {
			continue
		}
		values = append(values, profile.Queries...)
	}
	return normalizeQueryList(values)
}

func normalizeQueryList(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	return out
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

func (a *App) reconcileUpstreamProxyRoutes(cfg model.AppConfig) error {
	status, err := netroute.ReconcileUpstreamProxyRoutes(netroute.UpstreamProxyRouteOptions{
		Enabled:         cfg.UpstreamProxyRouteEnabled,
		InterfaceAlias:  cfg.UpstreamProxyRouteInterface,
		FallbackAlias:   cfg.ProxyInterfaceName,
		UpstreamAddr:    cfg.UpstreamProxyAddr,
		ProgramPaths:    cfg.ProxyGuardProgramPaths,
		ManualTargets:   cfg.UpstreamProxyRouteTargets,
		PreviousTargets: a.upstreamProxyRouteStatus.Targets,
		PreviousGateway: a.upstreamProxyRouteStatus.Gateway,
	})
	a.upstreamProxyRouteStatus = status
	return err
}

func (a *App) clearUpstreamProxyRoutes() error {
	if len(a.upstreamProxyRouteStatus.Targets) == 0 {
		a.upstreamProxyRouteStatus = model.UpstreamProxyRouteStatus{Message: "未启用代理节点路由"}
		return nil
	}
	err := netroute.ClearUpstreamProxyRoutes(a.upstreamProxyRouteStatus.Targets, a.upstreamProxyRouteStatus.Gateway)
	a.upstreamProxyRouteStatus = model.UpstreamProxyRouteStatus{Message: "未启用代理节点路由"}
	return err
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
	netadapter.ClearAddressCache()
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
