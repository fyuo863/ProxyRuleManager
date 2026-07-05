package procmatch

import (
	"path"
	"strings"
)

const (
	steamLibraryGamesQuery = "steam-library-games:"
	pathPrefixQuery        = "path-prefix:"
	steamCommonMarker      = `\steamapps\common\`
)

// MatchProcess returns the first query that matches a process name or path.
func MatchProcess(processName, processPath string, queries []string) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(processName))
	path := normalizeProcessPath(processPath)
	for _, raw := range queries {
		query := strings.ToLower(strings.TrimSpace(raw))
		if query == "" {
			continue
		}
		switch {
		case query == steamLibraryGamesQuery:
			if strings.Contains(path, steamCommonMarker) {
				return raw, true
			}
			continue
		case strings.HasPrefix(query, pathPrefixQuery):
			if matchesPathPrefix(path, strings.TrimSpace(query[len(pathPrefixQuery):])) {
				return raw, true
			}
			continue
		case strings.ContainsAny(query, "*?"):
			if matchesProcessPattern(query, name, path) {
				return raw, true
			}
			continue
		case isPathLikeQuery(query):
			normalizedQuery := normalizeProcessPath(query)
			if path != "" && (path == normalizedQuery || strings.HasSuffix(path, normalizedQuery)) {
				return raw, true
			}
			if strings.HasSuffix(name, baseName(normalizedQuery)) {
				return raw, true
			}
			continue
		case name == query:
			return raw, true
		}
	}
	return "", false
}

func matchesPathPrefix(path, prefix string) bool {
	if path == "" {
		return false
	}
	prefix = strings.TrimRight(normalizeProcessPath(prefix), `\`)
	if prefix == "" {
		return false
	}
	return path == prefix || strings.HasPrefix(path, prefix+`\`)
}

func matchesProcessPattern(pattern, name, procPath string) bool {
	pattern = normalizeProcessPath(pattern)
	matchPattern := normalizeWildcardPath(pattern)
	matchPath := normalizeWildcardPath(procPath)
	if ok, _ := path.Match(matchPattern, name); ok {
		return true
	}
	if procPath != "" {
		if ok, _ := path.Match(matchPattern, matchPath); ok {
			return true
		}
		if ok, _ := path.Match(baseName(pattern), name); ok {
			return true
		}
	}
	return false
}

func isPathLikeQuery(query string) bool {
	return strings.Contains(query, `\`) || strings.Contains(query, "/") || strings.Contains(query, ":")
}

func normalizeProcessPath(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.ReplaceAll(value, "/", `\`)
}

func normalizeWildcardPath(value string) string {
	return strings.ReplaceAll(value, `\`, "/")
}

func baseName(value string) string {
	parts := strings.Split(value, `\`)
	return parts[len(parts)-1]
}
