//go:build !windows

package netadapter

import (
	"fmt"
	"net"
)

func lookupIPv4(name string) (net.IP, error) {
	return nil, fmt.Errorf("网卡地址查询当前仅支持 Windows: %s", name)
}

func lookupFallbackIPv4(excludeName string) (net.IP, string, error) {
	return nil, "", fmt.Errorf("备用网卡地址查询当前仅支持 Windows: %s", excludeName)
}

func clearAddressCache() {}
