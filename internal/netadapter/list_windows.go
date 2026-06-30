//go:build windows

package netadapter

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"proxy-rule-manager/internal/model"
	"proxy-rule-manager/internal/winps"
)

type adapterRecord struct {
	Name                 string `json:"Name"`
	InterfaceDescription string `json:"InterfaceDescription"`
	Status               string `json:"Status"`
}

func list() ([]model.NetworkAdapterOption, error) {
	output, err := winps.Run("枚举网卡", listAdaptersScript(), 8*time.Second)
	if err != nil {
		return nil, err
	}

	raw := strings.TrimSpace(output)
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
