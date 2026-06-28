//go:build windows

package netadapter

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"proxy-rule-manager/internal/model"

	"golang.org/x/sys/windows"
)

type adapterRecord struct {
	Name                 string `json:"Name"`
	InterfaceDescription string `json:"InterfaceDescription"`
	Status               string `json:"Status"`
}

func list() ([]model.NetworkAdapterOption, error) {
	cmd := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy",
		"Bypass",
		"-Command",
		listAdaptersScript(),
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
		return nil, fmt.Errorf("枚举网卡失败: %s", message)
	}

	raw := strings.TrimSpace(string(output))
	if raw == "" || raw == "null" {
		return []model.NetworkAdapterOption{}, nil
	}

	var records []adapterRecord
	if strings.HasPrefix(raw, "[") {
		if err := json.Unmarshal([]byte(raw), &records); err != nil {
			return nil, fmt.Errorf("解析网卡列表失败: %w", err)
		}
	} else {
		var single adapterRecord
		if err := json.Unmarshal([]byte(raw), &single); err != nil {
			return nil, fmt.Errorf("解析网卡列表失败: %w", err)
		}
		records = []adapterRecord{single}
	}

	out := make([]model.NetworkAdapterOption, 0, len(records))
	for _, item := range records {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			continue
		}
		out = append(out, model.NetworkAdapterOption{
			Name:        name,
			Description: strings.TrimSpace(item.InterfaceDescription),
			Status:      strings.TrimSpace(item.Status),
		})
	}
	return out, nil
}

func listAdaptersScript() string {
	return "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n" +
		"$OutputEncoding = [Console]::OutputEncoding\n" +
		"$ErrorActionPreference = 'Stop'\n" +
		"Get-NetAdapter -ErrorAction SilentlyContinue |\n" +
		"Where-Object { $_.HardwareInterface -eq $true } |\n" +
		"Sort-Object @{ Expression = { if ($_.Status -eq 'Up') { 0 } elseif ($_.Status -eq 'Disconnected') { 1 } else { 2 } } }, Name |\n" +
		"Select-Object Name, InterfaceDescription, Status |\n" +
		"ConvertTo-Json -Compress\n"
}
