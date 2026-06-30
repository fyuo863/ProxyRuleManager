package config

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"

	"proxy-rule-manager/internal/model"
	"proxy-rule-manager/internal/prmfs"
	"proxy-rule-manager/internal/rules"
)

type Store struct {
	path string
	mu   sync.RWMutex
	cfg  model.AppConfig
}

var defaultTunIncludedApps = []string{
	"Codex.exe",
	"codex.exe",
	"codex-command-runner-*.exe",
}

var steamTunIncludedApps = []string{
	"steam.exe",
	"steamwebhelper.exe",
}

func defaultRules() []model.Rule {
	base := rules.CommonDomainRules()
	out := make([]model.Rule, 0, len(base)+1)
	for _, rule := range base {
		rule.ID = uuid.NewString()
		out = append(out, rule)
	}
	out = append(out, model.Rule{
		ID:      uuid.NewString(),
		Enabled: true,
		Type:    model.RuleTypeMatch,
		Value:   "MATCH",
		Target:  model.RuleTargetDirect,
		Folder:  "系统",
		Remark:  "Fallback rule",
	})
	return out
}

func defaultConfig() model.AppConfig {
	defaultProfiles := defaultTunAppProfiles()
	return model.AppConfig{
		Rules:                       defaultRules(),
		PacListenAddr:               "127.0.0.1:18088",
		ProxyListenAddr:             "127.0.0.1:18089",
		UpstreamProxyAddr:           "127.0.0.1:7892",
		UpstreamProxyType:           "http",
		ProxyInterfaceName:          "",
		UpstreamProxyRouteEnabled:   false,
		UpstreamProxyRouteInterface: "",
		UpstreamProxyRouteTargets:   []string{},
		ProxyGuardEnabled:           false,
		ProxyGuardInterface:         "",
		ProxyGuardProgramPaths:      []string{},
		DirectInterfaceName:         "",
		TunInterfaceName:            "ProxyRuleManagerTun",
		TunAddressCIDR:              "172.19.0.1/30",
		TunMTU:                      1500,
		TunAppProfiles:              defaultProfiles,
		TunIncludedApps:             flattenTunAppProfiles(defaultProfiles),
		AutoStartTunService:         false,
		AutoStartPacService:         false,
		AutoStartProxyService:       false,
		AutoEnableSystemPac:         false,
		DisableSystemPacOnExit:      false,
		MaxLogEntries:               500,
		SavedWindowsProxy:           nil,
	}
}

func configPath() (string, error) {
	return prmfs.ConfigPath()
}

func NewStore() (*Store, error) {
	if err := prmfs.EnsureLayout(); err != nil {
		return nil, err
	}
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	if err := migrateLegacyConfig(path); err != nil {
		return nil, err
	}
	s := &Store{path: path, cfg: defaultConfig()}
	loadErr := s.Load()
	if loadErr != nil && !errors.Is(loadErr, os.ErrNotExist) {
		return nil, loadErr
	}
	s.ensureInvariants()
	if errors.Is(loadErr, os.ErrNotExist) {
		if err := s.Save(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) Path() string {
	return s.path
}

func (s *Store) ensureInvariants() {
	if s.cfg.PacListenAddr == "" {
		s.cfg.PacListenAddr = "127.0.0.1:18088"
	}
	if s.cfg.ProxyListenAddr == "" {
		s.cfg.ProxyListenAddr = "127.0.0.1:18089"
	}
	if s.cfg.UpstreamProxyAddr == "" {
		s.cfg.UpstreamProxyAddr = "127.0.0.1:7892"
	}
	if s.cfg.UpstreamProxyType == "" {
		s.cfg.UpstreamProxyType = "http"
	}
	if s.cfg.ProxyInterfaceName == "" {
		s.cfg.ProxyInterfaceName = ""
	}
	s.cfg.UpstreamProxyRouteTargets = normalizeStringList(s.cfg.UpstreamProxyRouteTargets)
	if s.cfg.ProxyGuardInterface == "" {
		s.cfg.ProxyGuardInterface = ""
	}
	if s.cfg.ProxyGuardProgramPaths == nil {
		s.cfg.ProxyGuardProgramPaths = []string{}
	}
	if s.cfg.TunInterfaceName == "" {
		s.cfg.TunInterfaceName = "ProxyRuleManagerTun"
	}
	if s.cfg.TunAddressCIDR == "" {
		s.cfg.TunAddressCIDR = "172.19.0.1/30"
	}
	if s.cfg.TunMTU <= 0 {
		s.cfg.TunMTU = 1500
	}
	s.cfg.TunAppProfiles = migrateTunAppProfiles(s.cfg.TunAppProfiles, s.cfg.TunIncludedApps)
	s.cfg.TunIncludedApps = flattenTunAppProfiles(s.cfg.TunAppProfiles)
	if s.cfg.MaxLogEntries <= 0 {
		s.cfg.MaxLogEntries = 500
	}
	if len(s.cfg.Rules) == 0 {
		s.cfg.Rules = defaultRules()
	}

	filtered := make([]model.Rule, 0, len(s.cfg.Rules))
	var fallback *model.Rule
	for _, rule := range s.cfg.Rules {
		if rule.ID == "" {
			rule.ID = uuid.NewString()
		}
		rule.Folder = rules.DefaultFolderForRule(rule)
		rule.Remark = rules.DefaultRemarkForRule(rule)
		if rule.Type == model.RuleTypeMatch && rule.Target == model.RuleTargetDirect {
			copyRule := rule
			fallback = &copyRule
			continue
		}
		filtered = append(filtered, rule)
	}
	for _, builtin := range rules.CommonDomainRules() {
		exists := false
		for _, rule := range filtered {
			if rules.SameRulePattern(rule, builtin) {
				exists = true
				break
			}
		}
		if exists {
			continue
		}
		builtin.ID = uuid.NewString()
		filtered = append(filtered, builtin)
	}
	if fallback == nil {
		rule := model.Rule{ID: uuid.NewString(), Enabled: true, Type: model.RuleTypeMatch, Value: "MATCH", Target: model.RuleTargetDirect, Folder: "系统", Remark: "Fallback rule"}
		fallback = &rule
	}
	filtered = append(filtered, *fallback)
	s.cfg.Rules = filtered
}

func defaultTunIncludedAppsCopy() []string {
	out := make([]string, len(defaultTunIncludedApps))
	copy(out, defaultTunIncludedApps)
	return out
}

func defaultTunAppProfiles() []model.TunAppProfile {
	return []model.TunAppProfile{
		{
			ID:          uuid.NewString(),
			Name:        "Codex Desktop",
			Enabled:     true,
			Queries:     defaultTunIncludedAppsCopy(),
			RoutingMode: model.TunAppRoutingForceProxy,
			Remark:      "覆盖 Codex 桌面主进程、CLI 与命令执行子进程；默认全部走代理。",
		},
	}
}

func isLegacyTunIncludedApps(values []string) bool {
	normalized := normalizeTunIncludedApps(values)
	return len(normalized) == 1 && strings.EqualFold(normalized[0], "Codex.exe")
}

func normalizeTunIncludedApps(values []string) []string {
	return normalizeStringList(values)
}

func normalizeTunAppProfiles(values []model.TunAppProfile) []model.TunAppProfile {
	out := make([]model.TunAppProfile, 0, len(values))
	for index, value := range values {
		value.Name = strings.TrimSpace(value.Name)
		if value.Name == "" {
			value.Name = "应用 " + strings.TrimSpace(uuid.NewString()[:8])
		}
		if value.ID == "" {
			value.ID = uuid.NewString()
		}
		value.Queries = normalizeTunIncludedApps(value.Queries)
		if value.RoutingMode == "" {
			value.RoutingMode = model.TunAppRoutingRulesProxyFallback
		}
		switch value.RoutingMode {
		case model.TunAppRoutingRulesProxyFallback, model.TunAppRoutingRulesDirectFallback, model.TunAppRoutingForceProxy, model.TunAppRoutingForceDirect:
		default:
			value.RoutingMode = model.TunAppRoutingRulesProxyFallback
		}
		value.Remark = strings.TrimSpace(value.Remark)
		if !value.Enabled && len(value.Queries) == 0 {
			continue
		}
		if len(value.Queries) == 0 {
			value.Enabled = false
		}
		if index >= 0 {
			out = append(out, value)
		}
	}
	return out
}

func flattenTunAppProfiles(values []model.TunAppProfile) []string {
	queries := make([]string, 0, len(values)*2)
	for _, value := range values {
		if !value.Enabled {
			continue
		}
		queries = append(queries, value.Queries...)
	}
	return normalizeTunIncludedApps(queries)
}

func migrateTunAppProfiles(profiles []model.TunAppProfile, includedApps []string) []model.TunAppProfile {
	if len(profiles) > 0 {
		normalized := normalizeTunAppProfiles(profiles)
		if len(normalized) > 0 {
			return normalized
		}
	}

	normalizedApps := normalizeTunIncludedApps(includedApps)
	if len(normalizedApps) == 0 || isLegacyTunIncludedApps(normalizedApps) {
		return defaultTunAppProfiles()
	}

	remaining := append([]string(nil), normalizedApps...)
	result := make([]model.TunAppProfile, 0, 3)
	tryExtract := func(name string, routingMode model.TunAppRoutingMode, remark string, candidates []string) {
		matched := make([]string, 0, len(candidates))
		nextRemaining := make([]string, 0, len(remaining))
		for _, item := range remaining {
			hit := false
			for _, candidate := range candidates {
				if strings.EqualFold(item, candidate) {
					hit = true
					matched = append(matched, item)
					break
				}
			}
			if !hit {
				nextRemaining = append(nextRemaining, item)
			}
		}
		if len(matched) == 0 {
			return
		}
		remaining = nextRemaining
		result = append(result, model.TunAppProfile{
			ID:                     uuid.NewString(),
			Name:                   name,
			Enabled:                true,
			Queries:                matched,
			RoutingMode:            routingMode,
			BypassTransparentProxy: strings.EqualFold(name, "Steam Desktop"),
			Remark:                 remark,
		})
	}

	tryExtract("Codex Desktop", model.TunAppRoutingForceProxy, "从旧版本应用名单迁移；默认全部走代理。", defaultTunIncludedApps)
	tryExtract("Steam Desktop", model.TunAppRoutingRulesDirectFallback, "从旧版本应用名单迁移；商店/社区优先按规则走代理，其它未识别连接默认直连。", steamTunIncludedApps)

	if len(remaining) > 0 {
		result = append(result, model.TunAppProfile{
			ID:          uuid.NewString(),
			Name:        "迁移的应用",
			Enabled:     true,
			Queries:     remaining,
			RoutingMode: model.TunAppRoutingRulesProxyFallback,
			Remark:      "从旧版本透明接管应用名单自动迁移。",
		})
	}
	return normalizeTunAppProfiles(result)
}

func normalizeStringList(values []string) []string {
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

func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return err
		}
		return err
	}
	var cfg model.AppConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	applyLegacyUpstreamProxyConfig(data, &cfg)
	applyLegacyTunAppProfileDefaults(data, &cfg)
	s.cfg = cfg
	s.ensureInvariants()
	return nil
}

func applyLegacyUpstreamProxyConfig(data []byte, cfg *model.AppConfig) {
	var legacy map[string]json.RawMessage
	if err := json.Unmarshal(data, &legacy); err != nil {
		return
	}
	if cfg.UpstreamProxyAddr == "" {
		cfg.UpstreamProxyAddr = legacyString(legacy, legacyUpstreamKey("ProxyAddr"))
	}
	if cfg.UpstreamProxyType == "" {
		cfg.UpstreamProxyType = legacyString(legacy, legacyUpstreamKey("ProxyType"))
	}
	if !cfg.UpstreamProxyRouteEnabled && legacyBool(legacy, legacyUpstreamKey("RouteEnabled")) {
		cfg.UpstreamProxyRouteEnabled = true
	}
	if cfg.UpstreamProxyRouteInterface == "" {
		cfg.UpstreamProxyRouteInterface = legacyString(legacy, legacyUpstreamKey("RouteInterface"))
	}
	if len(cfg.UpstreamProxyRouteTargets) == 0 {
		cfg.UpstreamProxyRouteTargets = legacyStringSlice(legacy, legacyUpstreamKey("RouteTargets"))
	}
}

func applyLegacyTunAppProfileDefaults(data []byte, cfg *model.AppConfig) {
	var legacy map[string]json.RawMessage
	if err := json.Unmarshal(data, &legacy); err != nil {
		return
	}
	rawProfiles, ok := legacy["tunAppProfiles"]
	if !ok {
		return
	}
	var profiles []map[string]json.RawMessage
	if err := json.Unmarshal(rawProfiles, &profiles); err != nil {
		return
	}
	for idx, rawProfile := range profiles {
		if idx >= len(cfg.TunAppProfiles) {
			return
		}
		if _, exists := rawProfile["bypassTransparentProxy"]; exists {
			continue
		}
		if isSteamTunProfile(cfg.TunAppProfiles[idx]) {
			cfg.TunAppProfiles[idx].BypassTransparentProxy = true
		}
	}
}

func isSteamTunProfile(profile model.TunAppProfile) bool {
	if strings.Contains(strings.ToLower(profile.Name), "steam") {
		return true
	}
	for _, query := range profile.Queries {
		for _, candidate := range steamTunIncludedApps {
			if strings.EqualFold(query, candidate) {
				return true
			}
		}
	}
	return false
}

func legacyUpstreamKey(suffix string) string {
	return "fast" + "Link" + suffix
}

func legacyString(values map[string]json.RawMessage, key string) string {
	raw, ok := values[key]
	if !ok {
		return ""
	}
	var out string
	if err := json.Unmarshal(raw, &out); err != nil {
		return ""
	}
	return out
}

func legacyBool(values map[string]json.RawMessage, key string) bool {
	raw, ok := values[key]
	if !ok {
		return false
	}
	var out bool
	if err := json.Unmarshal(raw, &out); err != nil {
		return false
	}
	return out
}

func legacyStringSlice(values map[string]json.RawMessage, key string) []string {
	raw, ok := values[key]
	if !ok {
		return nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

func (s *Store) Save() error {
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o644)
}

func (s *Store) Get() model.AppConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *Store) Update(mutator func(*model.AppConfig) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := mutator(&s.cfg); err != nil {
		return err
	}
	s.ensureInvariants()
	return nil
}

func (s *Store) Replace(cfg model.AppConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
	s.ensureInvariants()
	return nil
}

func migrateLegacyConfig(targetPath string) error {
	if _, err := os.Stat(targetPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	legacyPath, err := prmfs.LegacyConfigPath()
	if err != nil {
		return err
	}
	if _, err := os.Stat(legacyPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}

	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return err
	}
	src, err := os.Open(legacyPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(targetPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	return dst.Close()
}
