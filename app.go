package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"proxy-rule-manager/internal/config"
	"proxy-rule-manager/internal/logs"
	"proxy-rule-manager/internal/model"
	"proxy-rule-manager/internal/pac"
	"proxy-rule-manager/internal/proxy"
	"proxy-rule-manager/internal/rules"
	"proxy-rule-manager/internal/winproxy"
)

type App struct {
	ctx          context.Context
	config       *config.Store
	ruleEngine   *rules.Engine
	logStore     *logs.Store
	pacServer    *pac.Server
	proxySrv     *proxy.Server
	pacRunning   bool
	proxyRunning bool
	lastError    string
}

func NewApp() *App {
	return &App{ruleEngine: rules.NewEngine()}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	store, err := config.NewStore()
	if err != nil {
		a.lastError = err.Error()
		return
	}
	a.config = store
	a.logStore = logs.NewStore(store.Get().MaxLogEntries)
	a.rebuildServices()

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
	a.pacRunning = false
	a.proxyRunning = false
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
	if a.config == nil {
		return model.AppState{}
	}

	cfg := a.config.Get()
	currentProxyCfg, err := winproxy.ReadCurrentConfig()
	if err != nil {
		a.lastError = err.Error()
	}

	fastLinkReachable := false
	fastLinkMessage := "FastLink 代理端口不可用，请检查 FastLink 是否已连接"
	conn, dialErr := net.DialTimeout("tcp", cfg.FastLinkProxyAddr, 800*time.Millisecond)
	if dialErr == nil {
		fastLinkReachable = true
		fastLinkMessage = "FastLink 本地代理可用"
		_ = conn.Close()
	}

	enabledRules := 0
	for _, rule := range cfg.Rules {
		if rule.Enabled {
			enabledRules++
		}
	}

	return model.AppState{
		Config: cfg,
		Status: model.ServiceStatus{
			PacRunning:            a.pacRunning,
			PacURL:                "http://" + cfg.PacListenAddr + "/proxy.pac",
			ProxyRunning:          a.proxyRunning,
			ProxyAddr:             cfg.ProxyListenAddr,
			SystemPacEnabled:      currentProxyCfg.AutoConfigURL == "http://"+cfg.PacListenAddr+"/proxy.pac",
			CurrentAutoConfigURL:  currentProxyCfg.AutoConfigURL,
			FastLinkReachable:     fastLinkReachable,
			FastLinkMessage:       fastLinkMessage,
			RuleCount:             len(cfg.Rules),
			EnabledRuleCount:      enabledRules,
			ActiveConnectionCount: a.logStore.ActiveCount(),
			RecentLogCount:        a.logStore.Count(),
			LastError:             a.lastError,
		},
		Logs: a.logStore.List(),
	}
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
	return a.GetState()
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
	if rule.ID == "" {
		rule.ID = uuid.NewString()
	}

	err := a.config.Update(func(cfg *model.AppConfig) error {
		insertAt := len(cfg.Rules) - 1
		for idx := range cfg.Rules {
			if cfg.Rules[idx].ID == rule.ID {
				cfg.Rules[idx] = rule
				a.mergeDuplicateRules(cfg, rule.ID)
				return nil
			}
		}
		for idx := range cfg.Rules {
			if rules.EquivalentRule(cfg.Rules[idx], rule) {
				cfg.Rules[idx].Enabled = rule.Enabled
				if strings.TrimSpace(rule.Remark) != "" {
					cfg.Rules[idx].Remark = mergeRemarks(cfg.Rules[idx].Remark, rule.Remark)
				}
				return nil
			}
		}
		cfg.Rules = append(cfg.Rules[:insertAt], append([]model.Rule{rule}, cfg.Rules[insertAt:]...)...)
		return nil
	})
	if err != nil {
		return a.GetState(), err
	}
	if err := a.config.Save(); err != nil {
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
		insertAt := len(cfg.Rules) - 1
		for _, raw := range items {
			rule, ok := rules.NormalizeRuleInput(raw, request.Target, request.Remark, request.Enabled)
			if !ok {
				skipped = append(skipped, model.BatchRuleItem{Raw: raw})
				continue
			}
			rule.ID = uuid.NewString()

			merged := false
			for idx := range cfg.Rules {
				if rules.EquivalentRule(cfg.Rules[idx], rule) {
					cfg.Rules[idx].Enabled = request.Enabled
					if strings.TrimSpace(request.Remark) != "" {
						cfg.Rules[idx].Remark = mergeRemarks(cfg.Rules[idx].Remark, request.Remark)
					}
					skipped = append(skipped, model.BatchRuleItem{
						Raw:       raw,
						Type:      rule.Type,
						Value:     rule.Value,
						Target:    rule.Target,
						Duplicate: true,
					})
					mergedCount++
					merged = true
					break
				}
			}
			if merged {
				continue
			}

			cfg.Rules = append(cfg.Rules[:insertAt], append([]model.Rule{rule}, cfg.Rules[insertAt:]...)...)
			insertAt++
			addedCount++
			added = append(added, model.BatchRuleItem{
				Raw:    raw,
				Type:   rule.Type,
				Value:  rule.Value,
				Target: rule.Target,
			})
		}
		return nil
	})
	if err != nil {
		return model.BatchRuleResult{State: a.GetState()}, err
	}
	if err := a.config.Save(); err != nil {
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
	return a.GetState(), nil
}

func (a *App) SaveSettings(next model.AppConfig) (model.AppState, error) {
	restartPac := a.pacRunning
	restartProxy := a.proxyRunning

	err := a.config.Update(func(cfg *model.AppConfig) error {
		cfg.PacListenAddr = next.PacListenAddr
		cfg.ProxyListenAddr = next.ProxyListenAddr
		cfg.FastLinkProxyAddr = next.FastLinkProxyAddr
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

	if restartPac {
		_ = a.StopPacService()
	}
	if restartProxy {
		_ = a.StopProxyService()
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
	return a.GetState(), nil
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
	return a.GetState(), nil
}

func (a *App) OpenConfigLocation() error {
	path := a.config.Path()
	wruntime.BrowserOpenURL(a.ctx, "file:///"+path)
	return nil
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
	rule.Remark = strings.TrimSpace(rule.Remark)
	return rule
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
