package model

type TunOptions struct {
	InterfaceName     string          `json:"interfaceName"`
	AddressCIDR       string          `json:"addressCidr"`
	MTU               int             `json:"mtu"`
	AppProfiles       []TunAppProfile `json:"appProfiles"`
	IncludedApps      []string        `json:"includedApps"`
	UpstreamProxyAddr string          `json:"upstreamProxyAddr"`
	UpstreamProxyType string          `json:"upstreamProxyType"`
	ProxyInterface    string          `json:"proxyInterface"`
	DirectInterface   string          `json:"directInterface"`
	Rules             []Rule          `json:"rules"`
}

type TunRuntimeStatus struct {
	Running     bool   `json:"running"`
	Available   bool   `json:"available"`
	Message     string `json:"message"`
	PacketCount uint64 `json:"packetCount"`
	ByteCount   uint64 `json:"byteCount"`
}
