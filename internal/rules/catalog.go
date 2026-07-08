package rules

import (
	"strings"

	"proxy-rule-manager/internal/model"
)

type DomainFamily struct {
	Key     string
	Folder  string
	Remark  string
	Domains []string
}

var commonDomainFamilies = []DomainFamily{
	{
		Key:    "openai",
		Folder: "AI / OpenAI",
		Remark: "OpenAI 常用域名",
		Domains: []string{
			"openai.com",
			"chatgpt.com",
			"oaistatic.com",
			"oaiusercontent.com",
		},
	},
	{
		Key:    "github",
		Folder: "开发 / GitHub",
		Remark: "GitHub 主站与静态资源域名",
		Domains: []string{
			"github.com",
			"githubassets.com",
			"githubusercontent.com",
			"github.dev",
		},
	},
	{
		Key:    "google",
		Folder: "AI / Google",
		Remark: "Google 与 Google AI 常用域名",
		Domains: []string{
			"google.com",
			"google.com.hk",
			"googleapis.com",
			"googleusercontent.com",
			"gstatic.com",
			"ggpht.com",
			"gvt1.com",
			"gvt2.com",
		},
	},
	{
		Key:    "anthropic",
		Folder: "AI / Anthropic",
		Remark: "Anthropic 与 Claude 常用域名",
		Domains: []string{
			"anthropic.com",
			"claude.ai",
		},
	},
	{
		Key:    "perplexity",
		Folder: "AI / Perplexity",
		Remark: "Perplexity 常用域名",
		Domains: []string{
			"perplexity.ai",
			"pplx.ai",
		},
	},
	{
		Key:    "xai",
		Folder: "AI / xAI",
		Remark: "xAI 与 Grok 常用域名",
		Domains: []string{
			"x.ai",
			"grok.com",
		},
	},
	{
		Key:    "microsoft-connectivity",
		Folder: "系统 / Microsoft",
		Remark: "Microsoft 连通性与消息推送域名",
		Domains: []string{
			"msftconnecttest.com",
			"cloudmessaging.edge.microsoft.com",
		},
	},
	{
		Key:    "steam",
		Folder: "游戏平台 / Steam",
		Remark: "Steam 商店、社区、账号与客户端 Web 域名；下载 CDN 仍保持兜底直连",
		Domains: []string{
			"steampowered.com",
			"steamcommunity.com",
			"steam-chat.com",
			"steamusercontent.com",
			"steamstatic.com",
			"store.steampowered.com",
			"help.steampowered.com",
			"api.steampowered.com",
		},
	},
}

func CommonDomainRules() []model.Rule {
	out := make([]model.Rule, 0, 32)
	for _, family := range commonDomainFamilies {
		for _, domain := range family.Domains {
			out = append(out, model.Rule{
				Enabled: true,
				Type:    model.RuleTypeDomainSuffix,
				Value:   domain,
				Target:  model.RuleTargetProxy,
				Folder:  family.Folder,
				Remark:  family.Remark,
			})
		}
	}
	return out
}

func MatchDomainFamily(raw string) *DomainFamily {
	value := cleanHost(raw)
	if value == "" {
		return nil
	}
	for idx := range commonDomainFamilies {
		family := &commonDomainFamilies[idx]
		for _, domain := range family.Domains {
			if value == domain || strings.HasSuffix(value, "."+domain) {
				return family
			}
		}
	}
	return nil
}

func ExpandRuleSiblings(rule model.Rule) []model.Rule {
	rule.Folder = strings.TrimSpace(rule.Folder)
	rule.Remark = strings.TrimSpace(rule.Remark)
	switch rule.Type {
	case model.RuleTypeDomain, model.RuleTypeDomainSuffix:
	default:
		return []model.Rule{rule}
	}

	family := MatchDomainFamily(rule.Value)
	if family == nil {
		return []model.Rule{rule}
	}

	out := make([]model.Rule, 0, len(family.Domains))
	for _, domain := range family.Domains {
		item := rule
		item.ID = ""
		item.Type = model.RuleTypeDomainSuffix
		item.Value = domain
		if item.Folder == "" {
			item.Folder = family.Folder
		}
		if item.Remark == "" {
			item.Remark = family.Remark
		}
		out = append(out, item)
	}
	return out
}

func DefaultFolderForRule(rule model.Rule) string {
	if strings.TrimSpace(rule.Folder) != "" {
		return strings.TrimSpace(rule.Folder)
	}
	if family := MatchDomainFamily(rule.Value); family != nil {
		return family.Folder
	}
	return ""
}

func DefaultRemarkForRule(rule model.Rule) string {
	if strings.TrimSpace(rule.Remark) != "" {
		return strings.TrimSpace(rule.Remark)
	}
	if family := MatchDomainFamily(rule.Value); family != nil {
		return family.Remark
	}
	return ""
}
