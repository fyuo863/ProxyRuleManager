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
	return model.AppConfig{
		Rules:                  defaultRules(),
		PacListenAddr:          "127.0.0.1:18088",
		ProxyListenAddr:        "127.0.0.1:18089",
		FastLinkProxyAddr:      "127.0.0.1:7892",
		FastLinkProxyType:      "http",
		ProxyInterfaceName:     "",
		ProxyGuardEnabled:      false,
		ProxyGuardInterface:    "",
		ProxyGuardProgramPaths: []string{},
		DirectInterfaceName:    "",
		TunInterfaceName:       "ProxyRuleManagerTun",
		TunAddressCIDR:         "172.19.0.1/30",
		TunMTU:                 1500,
		TunIncludedApps:        defaultTunIncludedAppsCopy(),
		AutoStartTunService:    false,
		AutoStartPacService:    false,
		AutoStartProxyService:  false,
		AutoEnableSystemPac:    false,
		DisableSystemPacOnExit: false,
		MaxLogEntries:          500,
		SavedWindowsProxy:      nil,
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
	if s.cfg.FastLinkProxyAddr == "" {
		s.cfg.FastLinkProxyAddr = "127.0.0.1:7892"
	}
	if s.cfg.FastLinkProxyType == "" {
		s.cfg.FastLinkProxyType = "http"
	}
	if s.cfg.ProxyInterfaceName == "" {
		s.cfg.ProxyInterfaceName = ""
	}
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
	if s.cfg.TunIncludedApps == nil || isLegacyTunIncludedApps(s.cfg.TunIncludedApps) {
		s.cfg.TunIncludedApps = defaultTunIncludedAppsCopy()
	} else {
		s.cfg.TunIncludedApps = normalizeTunIncludedApps(s.cfg.TunIncludedApps)
	}
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

func isLegacyTunIncludedApps(values []string) bool {
	normalized := normalizeTunIncludedApps(values)
	return len(normalized) == 1 && strings.EqualFold(normalized[0], "Codex.exe")
}

func normalizeTunIncludedApps(values []string) []string {
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
	s.cfg = cfg
	s.ensureInvariants()
	return nil
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
