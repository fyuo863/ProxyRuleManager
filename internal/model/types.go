package model

type RuleTarget string

const (
	RuleTargetProxy  RuleTarget = "PROXY"
	RuleTargetDirect RuleTarget = "DIRECT"
	RuleTargetReject RuleTarget = "REJECT"
)

type RuleType string

const (
	RuleTypeDomain        RuleType = "DOMAIN"
	RuleTypeDomainSuffix  RuleType = "DOMAIN-SUFFIX"
	RuleTypeDomainKeyword RuleType = "DOMAIN-KEYWORD"
	RuleTypeDomainRegex   RuleType = "DOMAIN-REGEX"
	RuleTypeIPCIDR        RuleType = "IP-CIDR"
	RuleTypeMatch         RuleType = "MATCH"
)

type Rule struct {
	ID      string     `json:"id"`
	Enabled bool       `json:"enabled"`
	Type    RuleType   `json:"type"`
	Value   string     `json:"value"`
	Target  RuleTarget `json:"target"`
	Remark  string     `json:"remark"`
}

type BatchRuleRequest struct {
	Content string     `json:"content"`
	Target  RuleTarget `json:"target"`
	Remark  string     `json:"remark"`
	Enabled bool       `json:"enabled"`
}

type BatchRuleItem struct {
	Raw       string     `json:"raw"`
	Type      RuleType   `json:"type"`
	Value     string     `json:"value"`
	Target    RuleTarget `json:"target"`
	Duplicate bool       `json:"duplicate"`
}

type BatchRuleResult struct {
	State       AppState        `json:"state"`
	AddedCount  int             `json:"addedCount"`
	MergedCount int             `json:"mergedCount"`
	Skipped     []BatchRuleItem `json:"skipped"`
	Added       []BatchRuleItem `json:"added"`
}

type MatchedRule struct {
	Index int      `json:"index"`
	Type  RuleType `json:"type"`
	Value string   `json:"value"`
}

type TrafficStatus string

const (
	TrafficStatusActive TrafficStatus = "active"
	TrafficStatusClosed TrafficStatus = "closed"
	TrafficStatusError  TrafficStatus = "error"
)

type TrafficLog struct {
	ID               string        `json:"id"`
	Time             string        `json:"time"`
	Host             string        `json:"host"`
	Port             string        `json:"port"`
	Protocol         string        `json:"protocol"`
	MatchedRuleType  RuleType      `json:"matchedRuleType"`
	MatchedRuleValue string        `json:"matchedRuleValue"`
	MatchedRuleIndex int           `json:"matchedRuleIndex"`
	Target           RuleTarget    `json:"target"`
	Path             string        `json:"path"`
	UploadBytes      int64         `json:"uploadBytes"`
	DownloadBytes    int64         `json:"downloadBytes"`
	DurationMs       int64         `json:"durationMs"`
	Status           TrafficStatus `json:"status"`
	Error            string        `json:"error"`
}

type WindowsProxyConfig struct {
	AutoConfigURL string `json:"autoConfigURL"`
	ProxyEnable   bool   `json:"proxyEnable"`
	ProxyServer   string `json:"proxyServer"`
}

type AppConfig struct {
	Rules                  []Rule              `json:"rules"`
	PacListenAddr          string              `json:"pacListenAddr"`
	ProxyListenAddr        string              `json:"proxyListenAddr"`
	FastLinkProxyAddr      string              `json:"fastLinkProxyAddr"`
	AutoStartPacService    bool                `json:"autoStartPacService"`
	AutoStartProxyService  bool                `json:"autoStartProxyService"`
	AutoEnableSystemPac    bool                `json:"autoEnableSystemPac"`
	DisableSystemPacOnExit bool                `json:"disableSystemPacOnExit"`
	MaxLogEntries          int                 `json:"maxLogEntries"`
	SavedWindowsProxy      *WindowsProxyConfig `json:"savedWindowsProxyConfig"`
}

type ServiceStatus struct {
	PacRunning            bool   `json:"pacRunning"`
	PacURL                string `json:"pacUrl"`
	ProxyRunning          bool   `json:"proxyRunning"`
	ProxyAddr             string `json:"proxyAddr"`
	SystemPacEnabled      bool   `json:"systemPacEnabled"`
	CurrentAutoConfigURL  string `json:"currentAutoConfigURL"`
	FastLinkReachable     bool   `json:"fastLinkReachable"`
	FastLinkMessage       string `json:"fastLinkMessage"`
	RuleCount             int    `json:"ruleCount"`
	EnabledRuleCount      int    `json:"enabledRuleCount"`
	ActiveConnectionCount int    `json:"activeConnectionCount"`
	RecentLogCount        int    `json:"recentLogCount"`
	LastError             string `json:"lastError"`
}

type AppState struct {
	Config AppConfig     `json:"config"`
	Status ServiceStatus `json:"status"`
	Logs   []TrafficLog  `json:"logs"`
}
