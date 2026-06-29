//go:build windows

package netroute

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

type applyRouteResult struct {
	Gateway string   `json:"gateway"`
	Targets []string `json:"targets"`
	Count   int      `json:"count"`
}

func discoverFastLinkRemoteIPs(upstream string, programPaths []string) ([]string, error) {
	output, err := runPowerShell(discoverFastLinkRemoteIPsScript(upstream, programPaths))
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(output)
	if raw == "" || raw == "null" {
		return nil, nil
	}
	var items []string
	if strings.HasPrefix(raw, "[") {
		if err := json.Unmarshal([]byte(raw), &items); err != nil {
			return nil, fmt.Errorf("解析 FastLink 节点连接失败: %w", err)
		}
	} else {
		var single string
		if err := json.Unmarshal([]byte(raw), &single); err != nil {
			return nil, fmt.Errorf("解析 FastLink 节点连接失败: %w", err)
		}
		items = []string{single}
	}
	return NormalizeIPv4Targets(items), nil
}

func applyFastLinkRoutes(interfaceAlias string, targets []string) (string, error) {
	if len(targets) == 0 {
		return "", nil
	}
	output, err := runPowerShell(applyFastLinkRoutesScript(interfaceAlias, targets))
	if err != nil {
		return "", err
	}
	var result applyRouteResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &result); err != nil {
		return "", fmt.Errorf("解析 FastLink 节点路由结果失败: %w", err)
	}
	return strings.TrimSpace(result.Gateway), nil
}

func removeFastLinkRoutes(targets []string, gateway string) error {
	if len(targets) == 0 {
		return nil
	}
	_, err := runPowerShell(removeFastLinkRoutesScript(targets, gateway))
	return err
}

func discoverFastLinkRemoteIPsScript(upstream string, programPaths []string) string {
	var b strings.Builder
	b.WriteString("[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n")
	b.WriteString("$OutputEncoding = [Console]::OutputEncoding\n")
	b.WriteString("$ErrorActionPreference = 'Stop'\n")
	b.WriteString("$upstream = '")
	b.WriteString(psLiteral(upstream))
	b.WriteString("'\n")
	b.WriteString("$paths = New-Object System.Collections.Generic.List[string]\n")
	b.WriteString("function Add-CandidatePath([string]$path) {\n")
	b.WriteString("  if ([string]::IsNullOrWhiteSpace($path)) { return }\n")
	b.WriteString("  $script:paths.Add($path)\n")
	b.WriteString("  $name = [System.IO.Path]::GetFileName($path)\n")
	b.WriteString("  $dir = [System.IO.Path]::GetDirectoryName($path)\n")
	b.WriteString("  if ($dir -and $name -ieq 'FastLinkCore.exe') { $script:paths.Add((Join-Path $dir 'FastLink.exe')) }\n")
	b.WriteString("  if ($dir -and $name -ieq 'FastLink.exe') { $script:paths.Add((Join-Path $dir 'FastLinkCore.exe')) }\n")
	b.WriteString("}\n")
	b.WriteString("$configured = @(")
	for i, path := range programPaths {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString("'")
		b.WriteString(psLiteral(path))
		b.WriteString("'")
	}
	b.WriteString(")\n")
	b.WriteString("foreach ($path in $configured) { Add-CandidatePath $path }\n")
	b.WriteString("$upstreamPort = $null\n")
	b.WriteString("try { $upstreamPort = [int](([uri]('tcp://' + $upstream)).Port) } catch {}\n")
	b.WriteString("if ($upstreamPort) {\n")
	b.WriteString("  $listeners = @(Get-NetTCPConnection -State Listen -LocalPort $upstreamPort -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique)\n")
	b.WriteString("  foreach ($listenerPid in $listeners) {\n")
	b.WriteString("    $proc = Get-CimInstance Win32_Process -Filter ('ProcessId = ' + $listenerPid) -ErrorAction SilentlyContinue\n")
	b.WriteString("    if ($proc -and $proc.ExecutablePath) { Add-CandidatePath $proc.ExecutablePath }\n")
	b.WriteString("  }\n")
	b.WriteString("}\n")
	b.WriteString("$resolved = @()\n")
	b.WriteString("foreach ($path in ($paths | Select-Object -Unique)) {\n")
	b.WriteString("  $item = Resolve-Path -LiteralPath $path -ErrorAction SilentlyContinue\n")
	b.WriteString("  if ($item) { $resolved += $item.Path }\n")
	b.WriteString("}\n")
	b.WriteString("$processes = @()\n")
	b.WriteString("if ($resolved.Count -gt 0) {\n")
	b.WriteString("  $processes += @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.ExecutablePath -and ($resolved -contains $_.ExecutablePath) })\n")
	b.WriteString("}\n")
	b.WriteString("if ($processes.Count -eq 0) {\n")
	b.WriteString("  $processes += @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @('FastLink.exe','FastLinkCore.exe') })\n")
	b.WriteString("}\n")
	b.WriteString("$pids = @($processes | Select-Object -ExpandProperty ProcessId -Unique)\n")
	b.WriteString("$items = @()\n")
	b.WriteString("if ($pids.Count -gt 0) {\n")
	b.WriteString("  $items = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |\n")
	b.WriteString("    Where-Object { $pids -contains $_.OwningProcess -and $_.RemoteAddress -match '^\\d{1,3}(\\.\\d{1,3}){3}$' } |\n")
	b.WriteString("    Where-Object { $_.RemoteAddress -notmatch '^(0\\.|127\\.|169\\.254\\.|224\\.|255\\.)' } |\n")
	b.WriteString("    Select-Object -ExpandProperty RemoteAddress -Unique)\n")
	b.WriteString("}\n")
	b.WriteString("$items | ConvertTo-Json -Compress\n")
	return b.String()
}

func applyFastLinkRoutesScript(interfaceAlias string, targets []string) string {
	var b strings.Builder
	b.WriteString("[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n")
	b.WriteString("$OutputEncoding = [Console]::OutputEncoding\n")
	b.WriteString("$ErrorActionPreference = 'Stop'\n")
	b.WriteString("$iface = '")
	b.WriteString(psLiteral(interfaceAlias))
	b.WriteString("'\n")
	writePowerShellArray(&b, "targets", targets)
	b.WriteString("$adapter = Get-NetAdapter -Name $iface -ErrorAction SilentlyContinue\n")
	b.WriteString("if (-not $adapter) { throw \"未找到指定网卡: $iface\" }\n")
	b.WriteString("$gateway = ((Get-NetIPConfiguration -InterfaceAlias $iface -ErrorAction Stop).IPv4DefaultGateway | Where-Object { $_.NextHop } | Select-Object -First 1 -ExpandProperty NextHop | Out-String).Trim()\n")
	b.WriteString("if ([string]::IsNullOrWhiteSpace($gateway)) { throw \"指定网卡没有 IPv4 默认网关: $iface\" }\n")
	b.WriteString("foreach ($target in $targets) {\n")
	b.WriteString("  $prefix = \"$target/32\"\n")
	b.WriteString("  $stale = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue | Where-Object { $_.NextHop -ne $gateway -or $_.InterfaceAlias -ne $iface })\n")
	b.WriteString("  if ($stale.Count -gt 0) { $stale | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }\n")
	b.WriteString("  $existing = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -InterfaceAlias $iface -NextHop $gateway -ErrorAction SilentlyContinue)\n")
	b.WriteString("  if ($existing.Count -eq 0) { New-NetRoute -DestinationPrefix $prefix -InterfaceAlias $iface -NextHop $gateway -RouteMetric 1 -PolicyStore ActiveStore | Out-Null }\n")
	b.WriteString("}\n")
	b.WriteString("[pscustomobject]@{ gateway = $gateway; count = $targets.Count; targets = $targets } | ConvertTo-Json -Compress\n")
	return b.String()
}

func removeFastLinkRoutesScript(targets []string, gateway string) string {
	var b strings.Builder
	b.WriteString("[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n")
	b.WriteString("$OutputEncoding = [Console]::OutputEncoding\n")
	b.WriteString("$ErrorActionPreference = 'Stop'\n")
	b.WriteString("$gateway = '")
	b.WriteString(psLiteral(gateway))
	b.WriteString("'\n")
	writePowerShellArray(&b, "targets", targets)
	b.WriteString("foreach ($target in $targets) {\n")
	b.WriteString("  $prefix = \"$target/32\"\n")
	b.WriteString("  $routes = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue)\n")
	b.WriteString("  if ($gateway) { $routes = @($routes | Where-Object { $_.NextHop -eq $gateway -and $_.RouteMetric -eq 1 }) }\n")
	b.WriteString("  else { $routes = @($routes | Where-Object { $_.RouteMetric -eq 1 }) }\n")
	b.WriteString("  if ($routes.Count -gt 0) { $routes | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue | Out-Null }\n")
	b.WriteString("}\n")
	return b.String()
}

func writePowerShellArray(builder *strings.Builder, name string, values []string) {
	builder.WriteString("$")
	builder.WriteString(name)
	builder.WriteString(" = @(")
	for i, value := range values {
		if i > 0 {
			builder.WriteString(",")
		}
		builder.WriteString("'")
		builder.WriteString(psLiteral(value))
		builder.WriteString("'")
	}
	builder.WriteString(")\n")
}

func psLiteral(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func runPowerShell(script string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			return "", err
		}
		return "", fmt.Errorf("%s", message)
	}
	return strings.TrimSpace(string(output)), nil
}
