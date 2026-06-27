//go:build windows

package proxyguard

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"proxy-rule-manager/internal/model"

	"golang.org/x/sys/windows"
)

const firewallRuleGroup = "ProxyRuleManager Proxy Guard"

type WindowsService struct {
	mu     sync.RWMutex
	status model.ProxyGuardRuntimeStatus
}

func NewService() Service {
	return &WindowsService{
		status: model.ProxyGuardRuntimeStatus{Message: "未启用代理进程出口限制"},
	}
}

func (s *WindowsService) Reconcile(cfg model.AppConfig) error {
	if !cfg.ProxyGuardEnabled {
		if _, err := runPowerShell(removeRulesScript()); err != nil {
			s.setStatus(model.ProxyGuardRuntimeStatus{Message: "清理代理进程出口限制失败: " + err.Error()})
			return err
		}
		s.setStatus(model.ProxyGuardRuntimeStatus{Message: "未启用代理进程出口限制"})
		return nil
	}

	if !isAdministrator() {
		err := fmt.Errorf("代理进程出口限制需要管理员权限")
		s.setStatus(model.ProxyGuardRuntimeStatus{Message: err.Error()})
		return err
	}

	allowed := strings.TrimSpace(cfg.ProxyGuardInterface)
	if allowed == "" {
		err := fmt.Errorf("请填写代理进程出口网卡")
		s.setStatus(model.ProxyGuardRuntimeStatus{Message: err.Error()})
		return err
	}

	paths := normalizePaths(cfg.ProxyGuardProgramPaths)
	if len(paths) == 0 {
		err := fmt.Errorf("请至少填写一个受控代理进程路径")
		s.setStatus(model.ProxyGuardRuntimeStatus{Message: err.Error()})
		return err
	}

	blockedCount, err := s.applyRules(allowed, paths)
	if err != nil {
		s.setStatus(model.ProxyGuardRuntimeStatus{
			Message:      "应用代理进程出口限制失败: " + err.Error(),
			ProgramCount: len(paths),
		})
		return err
	}

	message := fmt.Sprintf("已限制 %d 个代理进程仅可经 %s 出站，已阻止 %d 个其它网卡", len(paths), allowed, blockedCount)
	s.setStatus(model.ProxyGuardRuntimeStatus{
		Applied:               true,
		Message:               message,
		ProgramCount:          len(paths),
		BlockedInterfaceCount: blockedCount,
	})
	return nil
}

func (s *WindowsService) Status() model.ProxyGuardRuntimeStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *WindowsService) setStatus(status model.ProxyGuardRuntimeStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status = status
}

func (s *WindowsService) applyRules(allowed string, paths []string) (int, error) {
	result, err := runPowerShell(applyRulesScript(allowed, paths))
	if err != nil {
		return 0, err
	}
	lines := strings.FieldsFunc(result, func(r rune) bool {
		return r == '\r' || r == '\n'
	})
	if len(lines) == 0 {
		return 0, nil
	}
	last := strings.TrimSpace(lines[len(lines)-1])
	if last == "" {
		return 0, nil
	}
	var blockedCount int
	if _, scanErr := fmt.Sscanf(last, "%d", &blockedCount); scanErr != nil {
		return 0, fmt.Errorf("无法解析防火墙规则结果: %s", last)
	}
	return blockedCount, nil
}

func normalizePaths(paths []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(paths))
	for _, item := range paths {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func applyRulesScript(allowed string, paths []string) string {
	var builder strings.Builder
	builder.WriteString("$ErrorActionPreference = 'Stop'\n")
	builder.WriteString("$group = '")
	builder.WriteString(psLiteral(firewallRuleGroup))
	builder.WriteString("'\n")
	builder.WriteString("Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null\n")
	builder.WriteString("$allowed = '")
	builder.WriteString(psLiteral(allowed))
	builder.WriteString("'\n")
	builder.WriteString("$programs = @(")
	for i, item := range paths {
		if i > 0 {
			builder.WriteString(",")
		}
		builder.WriteString("'")
		builder.WriteString(psLiteral(item))
		builder.WriteString("'")
	}
	builder.WriteString(")\n")
	builder.WriteString("$resolvedPrograms = @()\n")
	builder.WriteString("foreach ($program in $programs) {\n")
	builder.WriteString("  $resolved = Resolve-Path -LiteralPath $program -ErrorAction Stop\n")
	builder.WriteString("  $resolvedPrograms += $resolved.Path\n")
	builder.WriteString("}\n")
	builder.WriteString("$allowedAdapter = Get-NetAdapter -Name $allowed -ErrorAction SilentlyContinue\n")
	builder.WriteString("if (-not $allowedAdapter) { throw \"未找到指定网卡: $allowed\" }\n")
	builder.WriteString("$blockedAliases = @(Get-NetAdapter | Where-Object { $_.Name -ne $allowed -and $_.Status -ne 'Disabled' -and $_.HardwareInterface -eq $true } | Select-Object -ExpandProperty Name)\n")
	builder.WriteString("foreach ($program in $resolvedPrograms) {\n")
	builder.WriteString("  if ($blockedAliases.Count -gt 0) {\n")
	builder.WriteString("    $display = 'ProxyRuleManager Proxy Guard - ' + [System.IO.Path]::GetFileName($program)\n")
	builder.WriteString("    New-NetFirewallRule -DisplayName $display -Group $group -Direction Outbound -Action Block -Enabled True -Profile Any -Program $program -InterfaceAlias $blockedAliases | Out-Null\n")
	builder.WriteString("  }\n")
	builder.WriteString("}\n")
	builder.WriteString("Write-Output $blockedAliases.Count\n")
	return builder.String()
}

func removeRulesScript() string {
	return "$group = '" + psLiteral(firewallRuleGroup) + "'\n" +
		"Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null\n"
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

func isAdministrator() bool {
	token := windows.GetCurrentProcessToken()
	adminSid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	member, err := token.IsMember(adminSid)
	return err == nil && member
}
