package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/google/uuid"

	"proxy-rule-manager/internal/model"
)

type Store struct {
	path string
	mu   sync.RWMutex
	cfg  model.AppConfig
}

func defaultRules() []model.Rule {
	return []model.Rule{
		{ID: uuid.NewString(), Enabled: true, Type: model.RuleTypeDomainSuffix, Value: "openai.com", Target: model.RuleTargetProxy, Remark: "OpenAI domains"},
		{ID: uuid.NewString(), Enabled: true, Type: model.RuleTypeDomainSuffix, Value: "chatgpt.com", Target: model.RuleTargetProxy, Remark: "ChatGPT domains"},
		{ID: uuid.NewString(), Enabled: true, Type: model.RuleTypeDomainSuffix, Value: "oaistatic.com", Target: model.RuleTargetProxy, Remark: "OpenAI static assets"},
		{ID: uuid.NewString(), Enabled: true, Type: model.RuleTypeDomainSuffix, Value: "oaiusercontent.com", Target: model.RuleTargetProxy, Remark: "OpenAI uploads/downloads"},
		{ID: uuid.NewString(), Enabled: true, Type: model.RuleTypeMatch, Value: "MATCH", Target: model.RuleTargetDirect, Remark: "Fallback rule"},
	}
}

func defaultConfig() model.AppConfig {
	return model.AppConfig{
		Rules:                  defaultRules(),
		PacListenAddr:          "127.0.0.1:18088",
		ProxyListenAddr:        "127.0.0.1:18089",
		FastLinkProxyAddr:      "127.0.0.1:7892",
		AutoStartPacService:    false,
		AutoStartProxyService:  false,
		AutoEnableSystemPac:    false,
		DisableSystemPacOnExit: false,
		MaxLogEntries:          500,
		SavedWindowsProxy:      nil,
	}
}

func configPath() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "ProxyRuleManager", "config.json"), nil
}

func NewStore() (*Store, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, cfg: defaultConfig()}
	if err := s.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s.ensureInvariants()
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
		if rule.Type == model.RuleTypeMatch && rule.Target == model.RuleTargetDirect {
			copyRule := rule
			fallback = &copyRule
			continue
		}
		filtered = append(filtered, rule)
	}
	if fallback == nil {
		rule := model.Rule{ID: uuid.NewString(), Enabled: true, Type: model.RuleTypeMatch, Value: "MATCH", Target: model.RuleTargetDirect, Remark: "Fallback rule"}
		fallback = &rule
	}
	filtered = append(filtered, *fallback)
	s.cfg.Rules = filtered
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
