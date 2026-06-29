//go:build !windows

package netroute

import "proxy-rule-manager/internal/model"

func listDefaultIPv4Routes() ([]model.NetworkRoute, error) {
	return nil, nil
}

func discoverUpstreamProxyRemoteIPs(upstream string, programPaths []string) ([]string, error) {
	return nil, nil
}

func applyUpstreamProxyRoutes(interfaceAlias string, targets []string) (string, error) {
	return "", nil
}

func removeUpstreamProxyRoutes(targets []string, gateway string) error {
	return nil
}
