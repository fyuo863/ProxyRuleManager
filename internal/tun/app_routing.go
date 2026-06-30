package tun

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/url"
	"strings"

	"proxy-rule-manager/internal/model"
	"proxy-rule-manager/internal/rules"
)

type appRouteDecision struct {
	Rule      model.Rule
	Matched   model.MatchedRule
	Host      string
	MatchHost string
	Basis     string
}

func decideAppRoute(sniffedHost string, remoteIP net.IP, ruleList []model.Rule, mode model.TunAppRoutingMode) appRouteDecision {
	switch mode {
	case model.TunAppRoutingForceDirect:
		return forcedAppDecision(model.RuleTargetDirect, "profile-force-direct")
	case model.TunAppRoutingForceProxy:
		return forcedAppDecision(model.RuleTargetProxy, "profile-force-proxy")
	case "":
		mode = model.TunAppRoutingRulesProxyFallback
	}

	engine := rules.NewEngine()
	if host := normalizeDetectedHost(sniffedHost); host != "" {
		rule, matched := engine.Match(host, ruleList)
		return appRouteDecision{
			Rule:      rule,
			Matched:   matched,
			Host:      host,
			MatchHost: host,
			Basis:     "host",
		}
	}

	if ip := remoteIP.To4(); ip != nil {
		rule, matched := engine.Match(ip.String(), ruleList)
		if matched.Type == model.RuleTypeIPCIDR {
			return appRouteDecision{
				Rule:      rule,
				Matched:   matched,
				Host:      ip.String(),
				MatchHost: ip.String(),
				Basis:     "ip-cidr",
			}
		}
	}

	switch mode {
	case model.TunAppRoutingRulesDirectFallback:
		return fallbackAppDecision(model.RuleTargetDirect, "APP-FALLBACK-DIRECT", "fallback-direct")
	default:
		return fallbackAppDecision(model.RuleTargetProxy, "APP-FALLBACK-PROXY", "fallback-proxy")
	}
}

func forcedAppDecision(target model.RuleTarget, basis string) appRouteDecision {
	return appRouteDecision{
		Rule: model.Rule{
			Type:   model.RuleTypeMatch,
			Value:  "MATCH",
			Target: target,
		},
		Matched: model.MatchedRule{
			Index: -1,
			Type:  model.RuleTypeMatch,
			Value: "APP-PROFILE-" + string(target),
		},
		Basis: basis,
	}
}

func fallbackAppDecision(target model.RuleTarget, matchedValue string, basis string) appRouteDecision {
	return appRouteDecision{
		Rule: model.Rule{
			Type:   model.RuleTypeMatch,
			Value:  "MATCH",
			Target: target,
		},
		Matched: model.MatchedRule{
			Index: -1,
			Type:  model.RuleTypeMatch,
			Value: matchedValue,
		},
		Basis: basis,
	}
}

func detectHostFromInitialPayload(payload []byte) (string, string) {
	if host, ok := detectTLSServerName(payload); ok {
		return host, "tls-sni"
	}
	if host, ok := detectHTTPHost(payload); ok {
		return host, "http-host"
	}
	return "", ""
}

func detectTLSServerName(payload []byte) (string, bool) {
	if len(payload) < 5 || payload[0] != 0x16 {
		return "", false
	}
	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if recordLen <= 0 || len(payload) < 5+recordLen {
		return "", false
	}
	record := payload[5 : 5+recordLen]
	if len(record) < 4 || record[0] != 0x01 {
		return "", false
	}
	helloLen := int(record[1])<<16 | int(record[2])<<8 | int(record[3])
	if helloLen <= 0 || len(record) < 4+helloLen {
		return "", false
	}
	hello := record[4 : 4+helloLen]
	if len(hello) < 34 {
		return "", false
	}

	offset := 34
	if len(hello) < offset+1 {
		return "", false
	}
	sessionIDLen := int(hello[offset])
	offset++
	if len(hello) < offset+sessionIDLen+2 {
		return "", false
	}
	offset += sessionIDLen

	cipherSuitesLen := int(binary.BigEndian.Uint16(hello[offset : offset+2]))
	offset += 2
	if len(hello) < offset+cipherSuitesLen+1 {
		return "", false
	}
	offset += cipherSuitesLen

	compressionMethodsLen := int(hello[offset])
	offset++
	if len(hello) < offset+compressionMethodsLen+2 {
		return "", false
	}
	offset += compressionMethodsLen

	extensionsLen := int(binary.BigEndian.Uint16(hello[offset : offset+2]))
	offset += 2
	if len(hello) < offset+extensionsLen {
		return "", false
	}
	extensions := hello[offset : offset+extensionsLen]
	for len(extensions) >= 4 {
		extType := binary.BigEndian.Uint16(extensions[:2])
		extLen := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if len(extensions) < extLen {
			return "", false
		}
		if extType == 0 {
			host, ok := parseTLSServerNameExtension(extensions[:extLen])
			if ok {
				return host, true
			}
		}
		extensions = extensions[extLen:]
	}
	return "", false
}

func parseTLSServerNameExtension(ext []byte) (string, bool) {
	if len(ext) < 2 {
		return "", false
	}
	listLen := int(binary.BigEndian.Uint16(ext[:2]))
	if listLen <= 0 || len(ext) < 2+listLen {
		return "", false
	}
	items := ext[2 : 2+listLen]
	for len(items) >= 3 {
		nameType := items[0]
		nameLen := int(binary.BigEndian.Uint16(items[1:3]))
		items = items[3:]
		if len(items) < nameLen {
			return "", false
		}
		if nameType == 0 {
			host := normalizeDetectedHost(string(items[:nameLen]))
			if host != "" {
				return host, true
			}
		}
		items = items[nameLen:]
	}
	return "", false
}

func detectHTTPHost(payload []byte) (string, bool) {
	block := payload
	if idx := bytes.Index(block, []byte("\r\n\r\n")); idx >= 0 {
		block = block[:idx+4]
	} else if idx := bytes.Index(block, []byte("\n\n")); idx >= 0 {
		block = block[:idx+2]
	}
	lines := bytes.Split(block, []byte("\n"))
	if len(lines) == 0 {
		return "", false
	}

	requestLine := strings.TrimSpace(strings.TrimRight(string(lines[0]), "\r"))
	if !looksLikeHTTPRequestLine(requestLine) {
		return "", false
	}

	if host := extractHostFromRequestLine(requestLine); host != "" {
		return host, true
	}

	for _, raw := range lines[1:] {
		line := strings.TrimSpace(strings.TrimRight(string(raw), "\r"))
		if line == "" {
			break
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "host:") {
			host := normalizeDetectedHost(strings.TrimSpace(line[len("host:"):]))
			if host != "" {
				return host, true
			}
		}
	}
	return "", false
}

func looksLikeHTTPRequestLine(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	method := strings.ToUpper(fields[0])
	switch method {
	case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE":
		return true
	default:
		return false
	}
}

func extractHostFromRequestLine(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return ""
	}
	method := strings.ToUpper(fields[0])
	target := strings.TrimSpace(fields[1])
	if target == "" {
		return ""
	}

	if method == "CONNECT" {
		return normalizeDetectedHost(target)
	}
	if strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
		parsed, err := url.Parse(target)
		if err == nil {
			return normalizeDetectedHost(parsed.Hostname())
		}
	}
	return ""
}

func normalizeDetectedHost(raw string) string {
	value := strings.TrimSpace(strings.ToLower(raw))
	value = strings.Trim(value, "[]")
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return ""
	}
	if host, err := splitLooseHostPort(value); err == nil {
		value = host
	}
	return strings.Trim(strings.TrimSpace(value), ".")
}

func splitLooseHostPort(value string) (string, error) {
	if host, port, err := net.SplitHostPort(value); err == nil {
		if host == "" || port == "" {
			return "", err
		}
		return host, nil
	}
	if strings.Count(value, ":") == 1 && !strings.Contains(value, "]") {
		parts := strings.SplitN(value, ":", 2)
		if parts[0] != "" && parts[1] != "" {
			return parts[0], nil
		}
	}
	return "", net.InvalidAddrError("missing port")
}
