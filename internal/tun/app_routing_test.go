package tun

import (
	"encoding/binary"
	"net"
	"testing"

	"proxy-rule-manager/internal/model"
)

func TestDetectHostFromTLSClientHello(t *testing.T) {
	payload := buildTLSClientHelloForTest("store.steampowered.com")
	host, source := detectHostFromInitialPayload(payload)
	if host != "store.steampowered.com" {
		t.Fatalf("expected TLS host, got %q", host)
	}
	if source != "tls-sni" {
		t.Fatalf("expected tls-sni source, got %q", source)
	}
}

func TestDetectHostFromHTTPHostHeader(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: steamcommunity.com\r\nUser-Agent: test\r\n\r\n")
	host, source := detectHostFromInitialPayload(payload)
	if host != "steamcommunity.com" {
		t.Fatalf("expected HTTP host, got %q", host)
	}
	if source != "http-host" {
		t.Fatalf("expected http-host source, got %q", source)
	}
}

func TestDetectHostFromHTTPConnectRequest(t *testing.T) {
	payload := []byte("CONNECT api.steampowered.com:443 HTTP/1.1\r\nProxy-Connection: Keep-Alive\r\n\r\n")
	host, source := detectHostFromInitialPayload(payload)
	if host != "api.steampowered.com" {
		t.Fatalf("expected CONNECT host, got %q", host)
	}
	if source != "http-host" {
		t.Fatalf("expected http-host source, got %q", source)
	}
}

func TestDecideAppRouteFallsBackToProxyWithoutHost(t *testing.T) {
	decision := decideAppRoute("", net.ParseIP("1.2.3.4"), []model.Rule{
		{Enabled: true, Type: model.RuleTypeMatch, Value: "MATCH", Target: model.RuleTargetDirect},
	}, model.TunAppRoutingRulesProxyFallback)
	if decision.Rule.Target != model.RuleTargetProxy {
		t.Fatalf("expected proxy fallback, got %s", decision.Rule.Target)
	}
	if decision.Basis != "fallback-proxy" {
		t.Fatalf("expected fallback-proxy basis, got %q", decision.Basis)
	}
}

func TestDecideAppRouteUsesRulesForDetectedHost(t *testing.T) {
	decision := decideAppRoute("steamcommunity.com", net.ParseIP("1.2.3.4"), []model.Rule{
		{Enabled: true, Type: model.RuleTypeDomainSuffix, Value: "steamcommunity.com", Target: model.RuleTargetProxy},
		{Enabled: true, Type: model.RuleTypeMatch, Value: "MATCH", Target: model.RuleTargetDirect},
	}, model.TunAppRoutingRulesDirectFallback)
	if decision.Rule.Target != model.RuleTargetProxy {
		t.Fatalf("expected proxy for detected host, got %s", decision.Rule.Target)
	}
	if decision.Basis != "host" {
		t.Fatalf("expected host basis, got %q", decision.Basis)
	}
}

func TestDecideAppRouteFallsBackToDirectWhenConfigured(t *testing.T) {
	decision := decideAppRoute("", net.ParseIP("1.2.3.4"), []model.Rule{
		{Enabled: true, Type: model.RuleTypeMatch, Value: "MATCH", Target: model.RuleTargetDirect},
	}, model.TunAppRoutingRulesDirectFallback)
	if decision.Rule.Target != model.RuleTargetDirect {
		t.Fatalf("expected direct fallback, got %s", decision.Rule.Target)
	}
	if decision.Basis != "fallback-direct" {
		t.Fatalf("expected fallback-direct basis, got %q", decision.Basis)
	}
}

func TestDecideAppRouteCanForceProxy(t *testing.T) {
	decision := decideAppRoute("example.com", net.ParseIP("1.2.3.4"), nil, model.TunAppRoutingForceProxy)
	if decision.Rule.Target != model.RuleTargetProxy {
		t.Fatalf("expected force proxy, got %s", decision.Rule.Target)
	}
	if decision.Basis != "profile-force-proxy" {
		t.Fatalf("expected profile-force-proxy basis, got %q", decision.Basis)
	}
}

func buildTLSClientHelloForTest(host string) []byte {
	serverName := []byte(host)
	serverNameItem := make([]byte, 3+len(serverName))
	serverNameItem[0] = 0
	binary.BigEndian.PutUint16(serverNameItem[1:3], uint16(len(serverName)))
	copy(serverNameItem[3:], serverName)

	serverNameList := make([]byte, 2+len(serverNameItem))
	binary.BigEndian.PutUint16(serverNameList[:2], uint16(len(serverNameItem)))
	copy(serverNameList[2:], serverNameItem)

	serverNameExt := make([]byte, 4+len(serverNameList))
	binary.BigEndian.PutUint16(serverNameExt[:2], 0)
	binary.BigEndian.PutUint16(serverNameExt[2:4], uint16(len(serverNameList)))
	copy(serverNameExt[4:], serverNameList)

	extensions := serverNameExt

	body := make([]byte, 0, 128)
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	body = append(body, 0x00, 0x02, 0x13, 0x01)
	body = append(body, 0x01, 0x00)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)

	handshake := make([]byte, 4+len(body))
	handshake[0] = 0x01
	handshake[1] = byte(len(body) >> 16)
	handshake[2] = byte(len(body) >> 8)
	handshake[3] = byte(len(body))
	copy(handshake[4:], body)

	record := make([]byte, 5+len(handshake))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)
	return record
}
