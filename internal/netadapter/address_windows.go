//go:build windows

package netadapter

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"proxy-rule-manager/internal/winps"
)

const (
	addressCacheTTL          = 5 * time.Second
	addressPowerShellTimeout = 4 * time.Second
)

type fallbackIPv4Record struct {
	Name string `json:"Name"`
	IP   string `json:"IP"`
}

type addressCacheEntry struct {
	ip        net.IP
	name      string
	expiresAt time.Time
}

type addressCall struct {
	done  chan struct{}
	entry addressCacheEntry
	err   error
}

var addressState = struct {
	mu       sync.Mutex
	cache    map[string]addressCacheEntry
	inflight map[string]*addressCall
}{
	cache:    map[string]addressCacheEntry{},
	inflight: map[string]*addressCall{},
}

func lookupIPv4(name string) (net.IP, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return nil, fmt.Errorf("网卡名称不能为空")
	}
	key := "ipv4:" + strings.ToLower(trimmed)
	if entry, ok := cachedAddressEntry(key); ok {
		return cloneIP(entry.ip), nil
	}
	entry, err := addressSingleflight(key, func() (addressCacheEntry, error) {
		ip, err := queryIPv4(trimmed)
		if err != nil {
			return addressCacheEntry{}, err
		}
		return addressCacheEntry{ip: cloneIP(ip), expiresAt: time.Now().Add(addressCacheTTL)}, nil
	})
	if err != nil {
		return nil, err
	}
	return cloneIP(entry.ip), nil
}

func queryIPv4(name string) (net.IP, error) {
	script := "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n" +
		"$OutputEncoding = [Console]::OutputEncoding\n" +
		"$ErrorActionPreference = 'Stop'\n" +
		"$name = '" + psLiteral(name) + "'\n" +
		"$ip = @((Get-NetIPConfiguration -InterfaceAlias $name -ErrorAction Stop).IPv4Address | Where-Object { $_.IPAddress } | Select-Object -First 1 -ExpandProperty IPAddress)\n" +
		"if (-not $ip) { throw \"指定网卡没有可用的 IPv4 地址: $name\" }\n" +
		"Write-Output $ip\n"

	output, err := runAddressPowerShellRaw(script, "查询网卡 IPv4")
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(strings.TrimSpace(output))
	if ip == nil {
		return nil, fmt.Errorf("解析网卡 IPv4 失败: %s", strings.TrimSpace(output))
	}
	ip = ip.To4()
	if ip == nil {
		return nil, fmt.Errorf("指定网卡没有可用的 IPv4 地址: %s", name)
	}
	return ip, nil
}

func lookupFallbackIPv4(excludeName string) (net.IP, string, error) {
	trimmed := strings.TrimSpace(excludeName)
	key := "fallback:" + strings.ToLower(trimmed)
	if entry, ok := cachedAddressEntry(key); ok {
		return cloneIP(entry.ip), entry.name, nil
	}
	entry, err := addressSingleflight(key, func() (addressCacheEntry, error) {
		ip, name, err := queryFallbackIPv4(trimmed)
		if err != nil {
			return addressCacheEntry{}, err
		}
		return addressCacheEntry{ip: cloneIP(ip), name: name, expiresAt: time.Now().Add(addressCacheTTL)}, nil
	})
	if err != nil {
		return nil, "", err
	}
	return cloneIP(entry.ip), entry.name, nil
}

func queryFallbackIPv4(excludeName string) (net.IP, string, error) {
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
	return runAddressPowerShellRaw(script, "查询备用网卡 IPv4")
}

func runAddressPowerShellRaw(script string, operation string) (string, error) {
	return winps.Run(operation, script, addressPowerShellTimeout)
}

func cachedAddressEntry(key string) (addressCacheEntry, bool) {
	now := time.Now()
	addressState.mu.Lock()
	defer addressState.mu.Unlock()
	entry, ok := addressState.cache[key]
	if !ok || now.After(entry.expiresAt) {
		if ok {
			delete(addressState.cache, key)
		}
		return addressCacheEntry{}, false
	}
	entry.ip = cloneIP(entry.ip)
	return entry, true
}

func addressSingleflight(key string, fn func() (addressCacheEntry, error)) (addressCacheEntry, error) {
	addressState.mu.Lock()
	if entry, ok := addressState.cache[key]; ok && time.Now().Before(entry.expiresAt) {
		addressState.mu.Unlock()
		entry.ip = cloneIP(entry.ip)
		return entry, nil
	}
	if call, ok := addressState.inflight[key]; ok {
		addressState.mu.Unlock()
		<-call.done
		entry := call.entry
		entry.ip = cloneIP(entry.ip)
		return entry, call.err
	}
	call := &addressCall{done: make(chan struct{})}
	addressState.inflight[key] = call
	addressState.mu.Unlock()

	entry, err := fn()

	addressState.mu.Lock()
	if err == nil {
		entry.ip = cloneIP(entry.ip)
		addressState.cache[key] = entry
	}
	call.entry = entry
	call.err = err
	delete(addressState.inflight, key)
	close(call.done)
	addressState.mu.Unlock()

	entry.ip = cloneIP(entry.ip)
	return entry, err
}

func clearAddressCache() {
	addressState.mu.Lock()
	defer addressState.mu.Unlock()
	addressState.cache = map[string]addressCacheEntry{}
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}
