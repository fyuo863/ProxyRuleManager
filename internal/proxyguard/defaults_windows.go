//go:build windows

package proxyguard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type listeningProcess struct {
	Path string `json:"path"`
}

func suggestProgramPaths(upstream string) ([]string, error) {
	_, port, ok := loopbackUpstream(upstream)
	if !ok {
		return nil, nil
	}

	script := fmt.Sprintf(`
$ErrorActionPreference = 'Stop'
$port = %d
$items = @()
$pids = @(Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique)
foreach ($pid in $pids) {
  $proc = Get-CimInstance Win32_Process -Filter ("ProcessId = " + $pid) -ErrorAction SilentlyContinue
  if ($proc -and $proc.ExecutablePath) {
    $items += [pscustomobject]@{ path = $proc.ExecutablePath }
  }
}
$items | ConvertTo-Json -Compress
`, port)

	output, err := runPowerShell(script)
	if err != nil {
		return nil, fmt.Errorf("自动识别监听 %d 的本地代理进程失败: %w", port, err)
	}
	if strings.TrimSpace(output) == "" || strings.TrimSpace(output) == "null" {
		return nil, nil
	}

	var rawMany []listeningProcess
	if err := json.Unmarshal([]byte(output), &rawMany); err != nil {
		var single listeningProcess
		if singleErr := json.Unmarshal([]byte(output), &single); singleErr != nil {
			return nil, fmt.Errorf("解析本地代理进程信息失败: %w", err)
		}
		rawMany = []listeningProcess{single}
	}

	paths := make([]string, 0, len(rawMany))
	for _, item := range rawMany {
		trimmed := strings.TrimSpace(item.Path)
		if trimmed == "" {
			continue
		}
		if _, err := os.Stat(trimmed); err != nil {
			continue
		}
		paths = append(paths, trimmed)
	}
	paths = withSiblingProxyPrograms(paths)

	// Filter non-existent sibling guesses while preserving discovered paths.
	filtered := make([]string, 0, len(paths))
	for _, item := range paths {
		if _, err := os.Stat(item); err == nil {
			filtered = append(filtered, item)
			continue
		}
		// Keep the exact discovered listener path even if it briefly disappears.
		if strings.EqualFold(filepath.Base(item), "fastlinkcore.exe") || strings.EqualFold(filepath.Base(item), "fastlink.exe") {
			continue
		}
	}
	if len(filtered) > 0 {
		return normalizePaths(filtered), nil
	}
	return normalizePaths(paths), nil
}
