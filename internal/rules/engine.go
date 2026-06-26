package rules

import (
	"net"
	"regexp"
	"strings"

	"proxy-rule-manager/internal/model"
)

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) Match(host string, ruleList []model.Rule) (model.Rule, model.MatchedRule) {
	host = normalizeHost(host)
	for idx, rule := range ruleList {
		if !rule.Enabled {
			continue
		}
		if matchRule(host, rule) {
			return rule, model.MatchedRule{
				Index: idx,
				Type:  rule.Type,
				Value: rule.Value,
			}
		}
	}
	fallback := model.Rule{Type: model.RuleTypeMatch, Value: "MATCH", Target: model.RuleTargetDirect}
	return fallback, model.MatchedRule{Index: len(ruleList) - 1, Type: model.RuleTypeMatch, Value: "MATCH"}
}

func normalizeHost(host string) string {
	return strings.Trim(strings.TrimSpace(strings.ToLower(host)), ".")
}

func matchRule(host string, rule model.Rule) bool {
	switch rule.Type {
	case model.RuleTypeDomain:
		return host == normalizeHost(rule.Value)
	case model.RuleTypeDomainSuffix:
		value := normalizeHost(rule.Value)
		return host == value || strings.HasSuffix(host, "."+value)
	case model.RuleTypeDomainKeyword:
		return strings.Contains(host, strings.ToLower(strings.TrimSpace(rule.Value)))
	case model.RuleTypeDomainRegex:
		pattern := strings.TrimSpace(rule.Value)
		re, err := regexp.Compile(pattern)
		return err == nil && re.MatchString(host)
	case model.RuleTypeIPCIDR:
		ip := net.ParseIP(host)
		if ip == nil {
			return false
		}
		_, network, err := net.ParseCIDR(strings.TrimSpace(rule.Value))
		return err == nil && network.Contains(ip)
	case model.RuleTypeMatch:
		return true
	default:
		return false
	}
}
