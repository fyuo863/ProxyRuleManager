//go:build !windows

package netadapter

import "proxy-rule-manager/internal/model"

func list() ([]model.NetworkAdapterOption, error) {
	return nil, nil
}
