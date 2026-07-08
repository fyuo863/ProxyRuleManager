package model

import (
	"encoding/json"
	"testing"
)

func TestTunAppProfileUnmarshalForcesSteamBypass(t *testing.T) {
	var profile TunAppProfile
	err := json.Unmarshal([]byte(`{
		"name":"Steam Desktop",
		"enabled":true,
		"queries":["steam.exe","steamwebhelper.exe"],
		"routingMode":"RULES_DIRECT_FALLBACK",
		"bypassTransparentProxy":false
	}`), &profile)
	if err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if !profile.BypassTransparentProxy {
		t.Fatalf("expected Steam profile to bypass transparent proxy")
	}
}

func TestTunAppProfileUnmarshalForcesSteamLibraryBypass(t *testing.T) {
	var profile TunAppProfile
	err := json.Unmarshal([]byte(`{
		"name":"Game capture",
		"enabled":true,
		"queries":["steam-library-games:"],
		"routingMode":"FORCE_DIRECT",
		"bypassTransparentProxy":false
	}`), &profile)
	if err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if !profile.BypassTransparentProxy {
		t.Fatalf("expected Steam library game profile to bypass transparent proxy")
	}
}

func TestTunAppProfileUnmarshalKeepsNonSteamProfilesConfigurable(t *testing.T) {
	var profile TunAppProfile
	err := json.Unmarshal([]byte(`{
		"name":"Codex Desktop",
		"enabled":true,
		"queries":["Codex.exe"],
		"routingMode":"FORCE_PROXY",
		"bypassTransparentProxy":false
	}`), &profile)
	if err != nil {
		t.Fatalf("UnmarshalJSON() error = %v", err)
	}
	if profile.BypassTransparentProxy {
		t.Fatalf("expected non-Steam profile to keep transparent proxy enabled")
	}
}
