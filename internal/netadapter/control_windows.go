//go:build windows

package netadapter

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
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

	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
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
		if enabled {
			return fmt.Errorf("启用网卡失败: %s", message)
		}
		return fmt.Errorf("停用网卡失败: %s", message)
	}
	return nil
}

func psLiteral(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}
