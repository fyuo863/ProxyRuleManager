//go:build windows

package netadapter

import (
	"fmt"
	"strings"
	"time"

	"proxy-rule-manager/internal/winps"
)

func setEnabled(name string, enabled bool) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return fmt.Errorf("网卡名称不能为空")
	}
	cmdlet := "Disable-NetAdapter"
	args := "-Confirm:$false"
	if enabled {
		cmdlet = "Enable-NetAdapter"
		args = "-Confirm:$false"
	}
	script := "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n" +
		"$OutputEncoding = [Console]::OutputEncoding\n" +
		"$ErrorActionPreference = 'Stop'\n" +
		"$name = '" + psLiteral(trimmed) + "'\n" +
		"$adapter = Get-NetAdapter -Name $name -ErrorAction SilentlyContinue\n" +
		"if (-not $adapter) { throw \"未找到指定网卡: $name\" }\n" +
		cmdlet + " -Name $name " + args + " | Out-Null\n"

	operation := "停用网卡"
	if enabled {
		operation = "启用网卡"
	}
	_, err := winps.Run(operation, script, 20*time.Second)
	return err
}

func psLiteral(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}
