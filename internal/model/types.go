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
	Folder  string     `json:"folder"`
	Remark  string     `json:"remark"`
}

type BatchRuleRequest struct {
	Content string     `json:"content"`
	Target  RuleTarget `json:"target"`
	Folder  string     `json:"folder"`
	Remark  string     `json:"remark"`
	Enabled bool       `json:"enabled"`
}

type BatchRuleItem struct {
	Raw       string     `json:"raw"`
	Type      RuleType   `json:"type"`
	Value     string     `json:"value"`
	Target    RuleTarget `json:"target"`
	Folder    string     `json:"folder"`
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
	Source           string        `json:"source"`
	Host             string        `json:"host"`
	Port             string        `json:"port"`
	Protocol         string        `json:"protocol"`
	ProcessID        uint32        `json:"processId"`
	ProcessName      string        `json:"processName"`
	ProcessPath      string        `json:"processPath"`
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
	Rules                       []Rule              `json:"rules"`
	PacListenAddr               string              `json:"pacListenAddr"`
	ProxyListenAddr             string              `json:"proxyListenAddr"`
	UpstreamProxyAddr           string              `json:"upstreamProxyAddr"`
	UpstreamProxyType           string              `json:"upstreamProxyType"`
	ProxyInterfaceName          string              `json:"proxyInterfaceName"`
	UpstreamProxyRouteEnabled   bool                `json:"upstreamProxyRouteEnabled"`
	UpstreamProxyRouteInterface string              `json:"upstreamProxyRouteInterface"`
	UpstreamProxyRouteTargets   []string            `json:"upstreamProxyRouteTargets"`
	ProxyGuardEnabled           bool                `json:"proxyGuardEnabled"`
	ProxyGuardInterface         string              `json:"proxyGuardInterface"`
	ProxyGuardProgramPaths      []string            `json:"proxyGuardProgramPaths"`
	DirectInterfaceName         string              `json:"directInterfaceName"`
	TunInterfaceName            string              `json:"tunInterfaceName"`
	TunAddressCIDR              string              `json:"tunAddressCidr"`
	TunMTU                      int                 `json:"tunMtu"`
	TunIncludedApps             []string            `json:"tunIncludedApps"`
	AutoStartTunService         bool                `json:"autoStartTunService"`
	AutoStartPacService         bool                `json:"autoStartPacService"`
	AutoStartProxyService       bool                `json:"autoStartProxyService"`
	AutoEnableSystemPac         bool                `json:"autoEnableSystemPac"`
	DisableSystemPacOnExit      bool                `json:"disableSystemPacOnExit"`
	MaxLogEntries               int                 `json:"maxLogEntries"`
	SavedWindowsProxy           *WindowsProxyConfig `json:"savedWindowsProxyConfig"`
}

type ManagedAppStatus struct {
	Query             string `json:"query"`
	Name              string `json:"name"`
	Path              string `json:"path"`
	Running           bool   `json:"running"`
	PIDCount          int    `json:"pidCount"`
	ActiveConnections int    `json:"activeConnections"`
}

type ServiceStatus struct {
	PacRunning                bool   `json:"pacRunning"`
	PacURL                    string `json:"pacUrl"`
	ProxyRunning              bool   `json:"proxyRunning"`
	ProxyAddr                 string `json:"proxyAddr"`
	UpstreamProxyRouteApplied bool   `json:"upstreamProxyRouteApplied"`
	UpstreamProxyRouteMessage string `json:"upstreamProxyRouteMessage"`
	UpstreamProxyRouteCount   int    `json:"upstreamProxyRouteCount"`
	ProxyGuardApplied         bool   `json:"proxyGuardApplied"`
	ProxyGuardMessage         string `json:"proxyGuardMessage"`
	ProxyGuardProgramCount    int    `json:"proxyGuardProgramCount"`
	TunRunning                bool   `json:"tunRunning"`
	TunAvailable              bool   `json:"tunAvailable"`
	TunMessage                string `json:"tunMessage"`
	TunIncludedAppCount       int    `json:"tunIncludedAppCount"`
	ManagedAppCount           int    `json:"managedAppCount"`
	ManagedProcessCount       int    `json:"managedProcessCount"`
	ManagedConnectionCount    int    `json:"managedConnectionCount"`
	TunPacketCount            uint64 `json:"tunPacketCount"`
	TunByteCount              uint64 `json:"tunByteCount"`
	SystemPacEnabled          bool   `json:"systemPacEnabled"`
	CurrentAutoConfigURL      string `json:"currentAutoConfigURL"`
	UpstreamProxyReachable    bool   `json:"upstreamProxyReachable"`
	UpstreamProxyMessage      string `json:"upstreamProxyMessage"`
	RuleCount                 int    `json:"ruleCount"`
	EnabledRuleCount          int    `json:"enabledRuleCount"`
	ActiveConnectionCount     int    `json:"activeConnectionCount"`
	RecentLogCount            int    `json:"recentLogCount"`
	LastError                 string `json:"lastError"`
}

type ProxyGuardRuntimeStatus struct {
	Applied               bool   `json:"applied"`
	Message               string `json:"message"`
	ProgramCount          int    `json:"programCount"`
	BlockedInterfaceCount int    `json:"blockedInterfaceCount"`
}

type UpstreamProxyRouteStatus struct {
	Applied        bool     `json:"applied"`
	Message        string   `json:"message"`
	InterfaceAlias string   `json:"interfaceAlias"`
	Gateway        string   `json:"gateway"`
	RouteCount     int      `json:"routeCount"`
	Targets        []string `json:"targets"`
}

type NetworkAdapterOption struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

type NetworkRoute struct {
	IfIndex         int    `json:"ifIndex"`
	InterfaceAlias  string `json:"interfaceAlias"`
	Destination     string `json:"destination"`
	NextHop         string `json:"nextHop"`
	RouteMetric     int    `json:"routeMetric"`
	InterfaceMetric int    `json:"interfaceMetric"`
	State           string `json:"state"`
}

type DiagnosticPaths struct {
	RootDir          string `json:"rootDir"`
	ConfigPath       string `json:"configPath"`
	LegacyConfigPath string `json:"legacyConfigPath"`
	DiagnosticsPath  string `json:"diagnosticsPath"`
	TunRuntimeDir    string `json:"tunRuntimeDir"`
	TunConfigPath    string `json:"tunConfigPath"`
	TunLogPath       string `json:"tunLogPath"`
	CoreDir          string `json:"coreDir"`
	CoreExecutable   string `json:"coreExecutable"`
}

type AgentDiagnostics struct {
	GeneratedAt         string                   `json:"generatedAt"`
	Paths               DiagnosticPaths          `json:"paths"`
	State               AppState                 `json:"state"`
	ProxyGuard          ProxyGuardRuntimeStatus  `json:"proxyGuard"`
	UpstreamProxyRoute  UpstreamProxyRouteStatus `json:"upstreamProxyRoute"`
	TunStatus           TunRuntimeStatus         `json:"tunStatus"`
	NetworkAdapters     []NetworkAdapterOption   `json:"networkAdapters"`
	DefaultIPv4Routes   []NetworkRoute           `json:"defaultIpv4Routes"`
	CurrentWindowsProxy *WindowsProxyConfig      `json:"currentWindowsProxy,omitempty"`
	TunConfigPreview    string                   `json:"tunConfigPreview"`
	TunLogTail          string                   `json:"tunLogTail"`
	RecentLogs          []TrafficLog             `json:"recentLogs"`
	FullLogs            []TrafficLog             `json:"fullLogs"`
}

type AppState struct {
	Config                   AppConfig              `json:"config"`
	Status                   ServiceStatus          `json:"status"`
	Logs                     []TrafficLog           `json:"logs"`
	ManagedApps              []ManagedAppStatus     `json:"managedApps"`
	AvailableNetworkAdapters []NetworkAdapterOption `json:"availableNetworkAdapters"`
}
