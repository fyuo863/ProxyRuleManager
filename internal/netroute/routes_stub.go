//go:build !windows

package netroute

import "proxy-rule-manager/internal/model"

func listDefaultIPv4Routes() ([]model.NetworkRoute, error) {
	return nil, nil
}

func discoverFastLinkRemoteIPs(upstream string, programPaths []string) ([]string, error) {
	return nil, nil
}

func applyFastLinkRoutes(interfaceAlias string, targets []string) (string, error) {
	return "", nil
}

func removeFastLinkRoutes(targets []string, gateway string) error {
	return nil
}
