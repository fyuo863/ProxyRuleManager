package model

type TunOptions struct {
	InterfaceName   string   `json:"interfaceName"`
	AddressCIDR     string   `json:"addressCidr"`
	MTU             int      `json:"mtu"`
	IncludedApps    []string `json:"includedApps"`
	FastLinkAddr    string   `json:"fastLinkAddr"`
	FastLinkType    string   `json:"fastLinkType"`
	ProxyInterface  string   `json:"proxyInterface"`
	DirectInterface string   `json:"directInterface"`
	Rules           []Rule   `json:"rules"`
}

type TunRuntimeStatus struct {
	Running     bool   `json:"running"`
	Available   bool   `json:"available"`
	Message     string `json:"message"`
	PacketCount uint64 `json:"packetCount"`
	ByteCount   uint64 `json:"byteCount"`
}
