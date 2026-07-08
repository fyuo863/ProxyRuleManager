package model

import (
	"encoding/json"
	"strings"
)

const steamLibraryGamesProfileQuery = "steam-library-games:"

// UnmarshalJSON applies safety defaults for app profiles that are known to be
// sensitive to transparent capture. Steam keeps downloads, achievements,
// overlay, cloud sync, friends and game networking on a mix of client, game,
// TCP and UDP paths, so these profiles are monitor-only by default.
func (p *TunAppProfile) UnmarshalJSON(data []byte) error {
	type alias TunAppProfile
	var raw alias
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*p = TunAppProfile(raw)
	p.ApplySafetyDefaults()
	return nil
}

// ApplySafetyDefaults normalizes profiles that should never enter the
// transparent proxy data plane unless a future implementation can preserve all
// related TCP/UDP paths safely.
func (p *TunAppProfile) ApplySafetyDefaults() {
	if !isSteamRelatedTunProfile(*p) {
		return
	}
	p.BypassTransparentProxy = true
	if p.RoutingMode == "" {
		p.RoutingMode = TunAppRoutingRulesDirectFallback
	}
}

func isSteamRelatedTunProfile(profile TunAppProfile) bool {
	if strings.Contains(strings.ToLower(strings.TrimSpace(profile.Name)), "steam") {
		return true
	}
	for _, raw := range profile.Queries {
		query := strings.ToLower(strings.TrimSpace(raw))
		if query == "" {
			continue
		}
		switch query {
		case "steam.exe", "steamwebhelper.exe", steamLibraryGamesProfileQuery:
			return true
		}
		normalizedPath := strings.ReplaceAll(query, "/", `\`)
		if strings.Contains(normalizedPath, `\steamapps\common\`) {
			return true
		}
	}
	return false
}
