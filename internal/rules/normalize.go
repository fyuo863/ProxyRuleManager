package rules

import (
	"net"
	"net/url"
	"strings"

	"proxy-rule-manager/internal/model"
)

type BatchParseResult struct {
	Rule      model.Rule `json:"rule"`
	Raw       string     `json:"raw"`
	Duplicate bool       `json:"duplicate"`
}

func NormalizeRuleInput(raw string, fallbackTarget model.RuleTarget, fallbackRemark string, enabled bool) (model.Rule, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return model.Rule{}, false
	}

	ruleType, normalized := DetectRuleType(value)
	if ruleType == "" || normalized == "" || ruleType == model.RuleTypeMatch {
		return model.Rule{}, false
	}

	return model.Rule{
		Enabled: enabled,
		Type:    ruleType,
		Value:   normalized,
		Target:  fallbackTarget,
		Remark:  strings.TrimSpace(fallbackRemark),
	}, true
}

func DetectRuleType(raw string) (model.RuleType, string) {
	value := strings.TrimSpace(strings.ToLower(raw))
	if value == "" {
		return "", ""
	}

	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(value, prefix) {
			if parsed, err := url.Parse(value); err == nil {
				value = parsed.Hostname()
			}
			break
		}
	}

	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "*.")
	value = strings.TrimPrefix(value, ".")
	value = strings.TrimSuffix(value, "/")
	value = strings.Trim(value, "[]")

	switch {
	case strings.HasPrefix(value, "domain-suffix:"):
		return model.RuleTypeDomainSuffix, cleanHost(strings.TrimPrefix(value, "domain-suffix:"))
	case strings.HasPrefix(value, "suffix:"):
		return model.RuleTypeDomainSuffix, cleanHost(strings.TrimPrefix(value, "suffix:"))
	case strings.HasPrefix(value, "domain:"):
		return model.RuleTypeDomain, cleanHost(strings.TrimPrefix(value, "domain:"))
	case strings.HasPrefix(value, "keyword:"):
		return model.RuleTypeDomainKeyword, strings.TrimSpace(strings.TrimPrefix(value, "keyword:"))
	case strings.HasPrefix(value, "regex:"):
		return model.RuleTypeDomainRegex, strings.TrimSpace(strings.TrimPrefix(value, "regex:"))
	case strings.HasPrefix(value, "cidr:"):
		return model.RuleTypeIPCIDR, strings.TrimSpace(strings.TrimPrefix(value, "cidr:"))
	}

	if _, _, err := net.ParseCIDR(value); err == nil {
		return model.RuleTypeIPCIDR, value
	}
	if ip := net.ParseIP(value); ip != nil {
		if ip.To4() != nil {
			return model.RuleTypeIPCIDR, value + "/32"
		}
		return model.RuleTypeIPCIDR, value + "/128"
	}
	if looksLikeRegex(value) {
		return model.RuleTypeDomainRegex, raw
	}
	if strings.Contains(value, "*") {
		return model.RuleTypeDomainSuffix, cleanHost(strings.ReplaceAll(value, "*", ""))
	}
	if isLikelyHostname(value) {
		return model.RuleTypeDomainSuffix, cleanHost(value)
	}
	return model.RuleTypeDomainKeyword, strings.TrimSpace(raw)
}

func cleanHost(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimPrefix(value, "*.")
	value = strings.TrimPrefix(value, ".")
	return strings.TrimSuffix(value, "/")
}

func looksLikeRegex(value string) bool {
	regexHints := []string{"^", "$", "[", "]", "(", ")", "|", "\\", "+"}
	for _, hint := range regexHints {
		if strings.Contains(value, hint) {
			return true
		}
	}
	return false
}

func isLikelyHostname(value string) bool {
	return strings.Contains(value, ".") && !strings.Contains(value, " ")
}

func EquivalentRule(left, right model.Rule) bool {
	return left.Type == right.Type &&
		strings.EqualFold(strings.TrimSpace(left.Value), strings.TrimSpace(right.Value)) &&
		left.Target == right.Target
}
