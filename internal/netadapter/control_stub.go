//go:build !windows

package netadapter

import "errors"

func setEnabled(name string, enabled bool) error {
	return errors.New("网卡启停当前仅支持 Windows")
}
