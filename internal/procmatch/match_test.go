package procmatch

import "testing"

func TestMatchProcessSteamLibraryGames(t *testing.T) {
	query, ok := MatchProcess("Game.exe", `D:\SteamLibrary\steamapps\common\Half-Life 2\hl2.exe`, []string{"steam-library-games:"})
	if !ok || query != "steam-library-games:" {
		t.Fatalf("MatchProcess() = %q, %v; want steam-library-games match", query, ok)
	}

	if query, ok := MatchProcess("steam.exe", `C:\Program Files (x86)\Steam\steam.exe`, []string{"steam-library-games:"}); ok {
		t.Fatalf("MatchProcess() = %q, %v; want no Steam client match", query, ok)
	}
}

func TestMatchProcessPathPrefix(t *testing.T) {
	query, ok := MatchProcess("game.exe", `D:\Games\Steam\game.exe`, []string{`path-prefix:D:\Games\Steam`})
	if !ok || query != `path-prefix:D:\Games\Steam` {
		t.Fatalf("MatchProcess() = %q, %v; want path-prefix match", query, ok)
	}

	if query, ok := MatchProcess("game.exe", `D:\Games\SteamLibrary\game.exe`, []string{`path-prefix:D:\Games\Steam`}); ok {
		t.Fatalf("MatchProcess() = %q, %v; want no sibling-prefix match", query, ok)
	}
}

func TestMatchProcessExactProcessName(t *testing.T) {
	query, ok := MatchProcess("Steam.exe", `C:\Program Files (x86)\Steam\steam.exe`, []string{"steam.exe"})
	if !ok || query != "steam.exe" {
		t.Fatalf("MatchProcess() = %q, %v; want steam.exe process-name match", query, ok)
	}
}

func TestMatchProcessWildcard(t *testing.T) {
	query, ok := MatchProcess("codex-command-runner-123.exe", `C:\Users\me\AppData\Local\Codex\codex-command-runner-123.exe`, []string{"codex-command-runner-*.exe"})
	if !ok || query != "codex-command-runner-*.exe" {
		t.Fatalf("MatchProcess() = %q, %v; want wildcard process-name match", query, ok)
	}
}
