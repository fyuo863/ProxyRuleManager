//go:build windows

package netroute

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"proxy-rule-manager/internal/model"

	"golang.org/x/sys/windows"
)

type routeRecord struct {
	IfIndex         int    `json:"ifIndex"`
	InterfaceAlias  string `json:"InterfaceAlias"`
	Destination     string `json:"DestinationPrefix"`
	NextHop         string `json:"NextHop"`
	RouteMetric     int    `json:"RouteMetric"`
	InterfaceMetric int    `json:"InterfaceMetric"`
	State           string `json:"State"`
}

func listDefaultIPv4Routes() ([]model.NetworkRoute, error) {
	cmd := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy",
		"Bypass",
		"-Command",
		listRoutesScript(),
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			message = err.Error()
		}
		return nil, fmt.Errorf("枚举默认路由失败: %s", message)
	}

	raw := strings.TrimSpace(string(output))
	if raw == "" || raw == "null" {
		return []model.NetworkRoute{}, nil
	}

	var records []routeRecord
	if strings.HasPrefix(raw, "[") {
		if err := json.Unmarshal([]byte(raw), &records); err != nil {
			return nil, fmt.Errorf("解析默认路由失败: %w", err)
		}
	} else {
		var single routeRecord
		if err := json.Unmarshal([]byte(raw), &single); err != nil {
			return nil, fmt.Errorf("解析默认路由失败: %w", err)
		}
		records = []routeRecord{single}
	}

	out := make([]model.NetworkRoute, 0, len(records))
	for _, item := range records {
		out = append(out, model.NetworkRoute{
			IfIndex:         item.IfIndex,
			InterfaceAlias:  strings.TrimSpace(item.InterfaceAlias),
			Destination:     strings.TrimSpace(item.Destination),
			NextHop:         strings.TrimSpace(item.NextHop),
			RouteMetric:     item.RouteMetric,
			InterfaceMetric: item.InterfaceMetric,
			State:           strings.TrimSpace(item.State),
		})
	}
	return out, nil
}

func listRoutesScript() string {
	return "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n" +
		"$OutputEncoding = [Console]::OutputEncoding\n" +
		"$ErrorActionPreference = 'Stop'\n" +
		"Get-NetRoute -AddressFamily IPv4 |\n" +
		"Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } |\n" +
		"Sort-Object RouteMetric, InterfaceMetric |\n" +
		"Select-Object ifIndex, InterfaceAlias, DestinationPrefix, NextHop, RouteMetric, InterfaceMetric, State |\n" +
		"ConvertTo-Json -Compress\n"
}
