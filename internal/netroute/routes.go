package netroute

import (
	"fmt"
	"net"
	"strings"

	"proxy-rule-manager/internal/model"
)

type UpstreamProxyRouteOptions struct {
	Enabled         bool
	InterfaceAlias  string
	FallbackAlias   string
	UpstreamAddr    string
	ProgramPaths    []string
	ManualTargets   []string
	PreviousTargets []string
	PreviousGateway string
}

func ListDefaultIPv4Routes() ([]model.NetworkRoute, error) {
	return listDefaultIPv4Routes()
}

func ReconcileUpstreamProxyRoutes(options UpstreamProxyRouteOptions) (model.UpstreamProxyRouteStatus, error) {
	if len(options.PreviousTargets) > 0 {
		if err := removeUpstreamProxyRoutes(NormalizeIPv4Targets(options.PreviousTargets), options.PreviousGateway); err != nil {
			return model.UpstreamProxyRouteStatus{Message: "清理旧代理节点路由失败: " + err.Error()}, err
		}
	}

	if !options.Enabled {
		return model.UpstreamProxyRouteStatus{Message: "未启用代理节点路由"}, nil
	}

	iface := strings.TrimSpace(options.InterfaceAlias)
	if iface == "" {
		iface = strings.TrimSpace(options.FallbackAlias)
	}
	if iface == "" {
		return model.UpstreamProxyRouteStatus{Message: "请先选择上游代理出口网卡"}, fmt.Errorf("upstream proxy route interface is empty")
	}

	targets := NormalizeIPv4Targets(options.ManualTargets)
	discovered, discoverErr := discoverUpstreamProxyRemoteIPs(options.UpstreamAddr, options.ProgramPaths)
	targets = NormalizeIPv4Targets(append(targets, discovered...))
	if len(targets) == 0 {
		message := "未发现可添加的代理节点 IPv4；请先让上游代理建立连接，或手动填写节点 IP"
		if discoverErr != nil {
			message += ": " + discoverErr.Error()
		}
		return model.UpstreamProxyRouteStatus{
			Message:        message,
			InterfaceAlias: iface,
		}, nil
	}

	gateway, err := applyUpstreamProxyRoutes(iface, targets)
	if err != nil {
		return model.UpstreamProxyRouteStatus{
			Message:        "应用代理节点路由失败: " + err.Error(),
			InterfaceAlias: iface,
			Targets:        targets,
			RouteCount:     len(targets),
		}, err
	}

	return model.UpstreamProxyRouteStatus{
		Applied:        true,
		Message:        fmt.Sprintf("已将 %d 个代理节点 IPv4 固定到 %s 出站", len(targets), iface),
		InterfaceAlias: iface,
		Gateway:        gateway,
		RouteCount:     len(targets),
		Targets:        targets,
	}, nil
}

func ClearUpstreamProxyRoutes(targets []string, gateway string) error {
	return removeUpstreamProxyRoutes(NormalizeIPv4Targets(targets), gateway)
}

func NormalizeIPv4Targets(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		ip := normalizeIPv4Target(value)
		if ip == "" {
			continue
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	return out
}

func normalizeIPv4Target(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "/") {
		ip, network, err := net.ParseCIDR(trimmed)
		if err != nil || network == nil || ip == nil {
			return ""
		}
		ones, bits := network.Mask.Size()
		if bits != 32 || ones != 32 {
			return ""
		}
		trimmed = ip.String()
	}
	ip := net.ParseIP(strings.Trim(trimmed, "[]"))
	if ip == nil {
		return ""
	}
	ip = ip.To4()
	if ip == nil || isUnsafeRouteTarget(ip) {
		return ""
	}
	return ip.String()
}

func isUnsafeRouteTarget(ip net.IP) bool {
	return ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.Equal(net.IPv4bcast)
}
