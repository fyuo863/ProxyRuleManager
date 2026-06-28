package proxyguard

import (
	"strings"
	"testing"

	"proxy-rule-manager/internal/model"
)

func TestPrepareConfigUsesProxyInterfaceAsDefaultGuardInterface(t *testing.T) {
	cfg := model.AppConfig{
		FastLinkProxyAddr:   "127.0.0.1:7892",
		ProxyGuardEnabled:   true,
		ProxyInterfaceName:  "Wi-Fi",
		ProxyGuardInterface: "",
	}

	next, err := PrepareConfig(cfg)
	if err != nil && !strings.Contains(err.Error(), "自动识别") && !strings.Contains(err.Error(), "未找到本地上游代理进程") {
		t.Fatalf("unexpected error: %v", err)
	}
	if next.ProxyGuardInterface != "Wi-Fi" {
		t.Fatalf("expected proxy guard interface to default to Wi-Fi, got %q", next.ProxyGuardInterface)
	}
}

func TestLoopbackUpstream(t *testing.T) {
	host, port, ok := loopbackUpstream("127.0.0.1:7892")
	if !ok || host != "127.0.0.1" || port != 7892 {
		t.Fatalf("expected loopback upstream, got host=%q port=%d ok=%v", host, port, ok)
	}

	if _, _, ok := loopbackUpstream("192.168.1.2:7892"); ok {
		t.Fatalf("expected non-loopback upstream to be ignored")
	}
}
