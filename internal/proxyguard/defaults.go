package proxyguard

import (
	"fmt"
	"net"
	"strings"

	"proxy-rule-manager/internal/model"
)

// PrepareConfig fills in scheme-1 friendly defaults so a loopback upstream
// can be paired with proxyguard without requiring the user to hand-enter
// upstream proxy executable paths every time.
func PrepareConfig(cfg model.AppConfig) (model.AppConfig, error) {
	if !cfg.ProxyGuardEnabled {
		return cfg, nil
	}

	if strings.TrimSpace(cfg.ProxyGuardInterface) == "" {
		cfg.ProxyGuardInterface = strings.TrimSpace(cfg.ProxyInterfaceName)
	}

	cfg.ProxyGuardProgramPaths = normalizePaths(cfg.ProxyGuardProgramPaths)
	if len(cfg.ProxyGuardProgramPaths) > 0 {
		return cfg, nil
	}

	paths, err := suggestProgramPaths(cfg.UpstreamProxyAddr)
	if err != nil {
		return cfg, err
	}
	cfg.ProxyGuardProgramPaths = normalizePaths(paths)
	return cfg, nil
}

func loopbackUpstream(addr string) (string, int, bool) {
	host, portText, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", 0, false
	}
	if !isLoopbackHost(host) {
		return "", 0, false
	}
	port, err := net.LookupPort("tcp", portText)
	if err != nil {
		return "", 0, false
	}
	return host, port, true
}

func isLoopbackHost(host string) bool {
	trimmed := strings.Trim(strings.TrimSpace(host), "[]")
	if trimmed == "" {
		return false
	}
	if strings.EqualFold(trimmed, "localhost") {
		return true
	}
	ip := net.ParseIP(trimmed)
	return ip != nil && ip.IsLoopback()
}

func missingProgramPathsMessage(upstream string) error {
	if _, port, ok := loopbackUpstream(upstream); ok {
		return fmt.Errorf("未找到本地上游代理进程: %s。已尝试按监听端口 %d 自动识别，请先启动代理客户端，或手动填写受控代理进程路径", upstream, port)
	}
	return fmt.Errorf("请至少填写一个受控代理进程路径")
}
