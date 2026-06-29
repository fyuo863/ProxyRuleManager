//go:build windows

package netadapter

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

type fallbackIPv4Record struct {
	Name string `json:"Name"`
	IP   string `json:"IP"`
}

func lookupIPv4(name string) (net.IP, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return nil, fmt.Errorf("网卡名称不能为空")
	}
	script := "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n" +
		"$OutputEncoding = [Console]::OutputEncoding\n" +
		"$ErrorActionPreference = 'Stop'\n" +
		"$name = '" + psLiteral(trimmed) + "'\n" +
		"$ip = @((Get-NetIPConfiguration -InterfaceAlias $name -ErrorAction Stop).IPv4Address | Where-Object { $_.IPAddress } | Select-Object -First 1 -ExpandProperty IPAddress)\n" +
		"if (-not $ip) { throw \"指定网卡没有可用的 IPv4 地址: $name\" }\n" +
		"Write-Output $ip\n"

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
		return nil, fmt.Errorf("查询网卡 IPv4 失败: %s", message)
	}
	ip := net.ParseIP(strings.TrimSpace(string(output)))
	if ip == nil {
		return nil, fmt.Errorf("解析网卡 IPv4 失败: %s", strings.TrimSpace(string(output)))
	}
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("指定网卡没有可用的 IPv4 地址: %s", trimmed)
	}
	return ip, nil
}

func lookupFallbackIPv4(excludeName string) (net.IP, string, error) {
	output, err := runAddressPowerShell(fallbackIPv4Script(excludeName))
	if err != nil {
		return nil, "", err
	}
	var record fallbackIPv4Record
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &record); err != nil {
		return nil, "", fmt.Errorf("解析备用网卡 IPv4 失败: %w", err)
	}
	ip := net.ParseIP(strings.TrimSpace(record.IP))
	if ip == nil {
		return nil, "", fmt.Errorf("解析备用网卡 IPv4 失败: %s", strings.TrimSpace(record.IP))
	}
	ip = ip.To4()
	if ip == nil {
		return nil, "", fmt.Errorf("备用网卡没有可用的 IPv4 地址: %s", strings.TrimSpace(record.Name))
	}
	return ip, strings.TrimSpace(record.Name), nil
}

func fallbackIPv4Script(excludeName string) string {
	return "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n" +
		"$OutputEncoding = [Console]::OutputEncoding\n" +
		"$ErrorActionPreference = 'Stop'\n" +
		"$exclude = '" + psLiteral(strings.TrimSpace(excludeName)) + "'\n" +
		"$routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Alive' })\n" +
		"$rows = @()\n" +
		"foreach ($cfg in @(Get-NetIPConfiguration -ErrorAction SilentlyContinue)) {\n" +
		"  $name = [string]$cfg.InterfaceAlias\n" +
		"  if ([string]::IsNullOrWhiteSpace($name)) { continue }\n" +
		"  if ($exclude -and $name -ieq $exclude) { continue }\n" +
		"  $ip = @($cfg.IPv4Address | Where-Object { $_.IPAddress -and $_.IPAddress -notmatch '^169\\.254\\.' } | Select-Object -First 1 -ExpandProperty IPAddress)\n" +
		"  if (-not $ip) { continue }\n" +
		"  $route = @($routes | Where-Object { $_.InterfaceAlias -eq $name } | Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1)\n" +
		"  $rows += [pscustomobject]@{\n" +
		"    Name = $name\n" +
		"    IP = [string]$ip\n" +
		"    HasDefaultRoute = [bool]$route\n" +
		"    RouteMetric = if ($route) { [int]$route.RouteMetric } else { [int]::MaxValue }\n" +
		"    InterfaceMetric = if ($route) { [int]$route.InterfaceMetric } else { [int]::MaxValue }\n" +
		"  }\n" +
		"}\n" +
		"$selected = $rows | Sort-Object @{ Expression = { if ($_.HasDefaultRoute) { 0 } else { 1 } } }, RouteMetric, InterfaceMetric, Name | Select-Object -First 1\n" +
		"if (-not $selected) { throw '没有可用的备用 IPv4 网卡' }\n" +
		"$selected | Select-Object Name, IP | ConvertTo-Json -Compress\n"
}

func runAddressPowerShell(script string) (string, error) {
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
		return "", fmt.Errorf("查询备用网卡 IPv4 失败: %s", message)
	}
	return strings.TrimSpace(string(output)), nil
}
