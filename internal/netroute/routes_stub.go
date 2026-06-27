//go:build !windows

package netroute

import "proxy-rule-manager/internal/model"

func listDefaultIPv4Routes() ([]model.NetworkRoute, error) {
	return nil, nil
}
