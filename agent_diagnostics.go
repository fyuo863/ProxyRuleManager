package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"proxy-rule-manager/internal/model"
	"proxy-rule-manager/internal/netroute"
	"proxy-rule-manager/internal/prmfs"
	"proxy-rule-manager/internal/tun"
	"proxy-rule-manager/internal/winproxy"
)

func (a *App) GetAgentDiagnostics() (model.AgentDiagnostics, error) {
	state := a.GetState()
	cfg := state.Config
	proxyGuardStatus := model.ProxyGuardRuntimeStatus{}
	if a.proxyGuard != nil {
		proxyGuardStatus = a.proxyGuard.Status()
	}
	tunStatus := a.tunService.Status(model.TunOptions{
		InterfaceName:   cfg.TunInterfaceName,
		AddressCIDR:     cfg.TunAddressCIDR,
		MTU:             cfg.TunMTU,
		IncludedApps:    cfg.TunIncludedApps,
		FastLinkAddr:    cfg.FastLinkProxyAddr,
		FastLinkType:    cfg.FastLinkProxyType,
		ProxyInterface:  cfg.ProxyInterfaceName,
		DirectInterface: cfg.DirectInterfaceName,
		Rules:           cfg.Rules,
	})

	paths := diagnosticPaths()
	artifacts := tun.RuntimeArtifactsSnapshot()
	paths.TunRuntimeDir = artifacts.RuntimeDir
	paths.TunConfigPath = artifacts.ConfigPath
	paths.TunLogPath = artifacts.LogPath
	paths.CoreDir = artifacts.CoreDir
	paths.CoreExecutable = artifacts.CoreExecutable

	routes, _ := netroute.ListDefaultIPv4Routes()
	currentProxy, proxyErr := winproxy.ReadCurrentConfig()
	var currentProxyPtr *model.WindowsProxyConfig
	if proxyErr == nil {
		currentProxyPtr = &currentProxy
	}

	diagnostics := model.AgentDiagnostics{
		GeneratedAt:         time.Now().Format(time.RFC3339),
		Paths:               paths,
		State:               state,
		ProxyGuard:          proxyGuardStatus,
		FastLinkRoute:       a.fastLinkRouteStatus,
		TunStatus:           tunStatus,
		NetworkAdapters:     state.AvailableNetworkAdapters,
		DefaultIPv4Routes:   routes,
		CurrentWindowsProxy: currentProxyPtr,
		TunConfigPreview:    readTextSnippet(paths.TunConfigPath, 8192, false),
		TunLogTail:          readTextSnippet(paths.TunLogPath, 16384, true),
		RecentLogs:          tailTrafficLogs(a.logStore.FullList(), 120),
		FullLogs:            a.logStore.FullList(),
	}
	return diagnostics, nil
}

func (a *App) ExportAgentDiagnostics() (string, error) {
	diagnostics, err := a.GetAgentDiagnostics()
	if err != nil {
		return "", err
	}
	path, err := prmfs.DiagnosticsFilePath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(diagnostics, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

func diagnosticPaths() model.DiagnosticPaths {
	paths := model.DiagnosticPaths{}
	if root, err := prmfs.RootDir(); err == nil {
		paths.RootDir = root
	}
	if path, err := prmfs.ConfigPath(); err == nil {
		paths.ConfigPath = path
	}
	if path, err := prmfs.LegacyConfigPath(); err == nil {
		paths.LegacyConfigPath = path
	}
	if path, err := prmfs.DiagnosticsFilePath(); err == nil {
		paths.DiagnosticsPath = path
	}
	return paths
}

func readTextSnippet(path string, maxBytes int, fromTail bool) string {
	if path == "" || maxBytes <= 0 {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return ""
	}
	if len(data) <= maxBytes {
		return string(data)
	}
	if fromTail {
		return string(data[len(data)-maxBytes:])
	}
	return string(data[:maxBytes])
}

func tailTrafficLogs(items []model.TrafficLog, limit int) []model.TrafficLog {
	if limit <= 0 || len(items) <= limit {
		return append([]model.TrafficLog(nil), items...)
	}
	return append([]model.TrafficLog(nil), items[len(items)-limit:]...)
}
