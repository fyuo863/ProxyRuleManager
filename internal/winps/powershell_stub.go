//go:build !windows

package winps

import (
	"fmt"
	"strings"
	"time"
)

const DefaultTimeout = 15 * time.Second

func Run(operation, script string, timeout time.Duration) (string, error) {
	label := strings.TrimSpace(operation)
	if label == "" {
		label = "PowerShell"
	}
	return "", fmt.Errorf("%s 当前仅支持 Windows", label)
}
