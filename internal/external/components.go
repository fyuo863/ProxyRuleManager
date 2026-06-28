package external

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"proxy-rule-manager/internal/prmfs"
)

type component struct {
	name      string
	files     []string
	targetDir func() (string, error)
	// Optional bootstrap source under cwd/exe dir for first-run seeding into .PRM.
	bundledRel string
	// Optional download URLs keyed by filename for first-run seeding into .PRM.
	urls map[string]string
}

var components = []component{
	{
		name:       "windivert",
		files:      []string{"WinDivert.dll", "WinDivert64.sys"},
		targetDir:  prmfs.TunRuntimeDir,
		bundledRel: filepath.Join("third_party", "windivert"),
		urls: map[string]string{
			// public WinDivert releases are not hosted at a stable single-file URL;
			// provide placeholders — user can edit URLs in code or supply files manually.
			"WinDivert.dll":   "https://reqrypt.org/downloads/WinDivert.dll",
			"WinDivert64.sys": "https://reqrypt.org/downloads/WinDivert64.sys",
		},
	},
	{
		name:       "wintun",
		files:      []string{"wintun.dll"},
		targetDir:  prmfs.TunRuntimeDir,
		bundledRel: filepath.Join("third_party", "wintun"),
		urls: map[string]string{
			"wintun.dll": "https://www.wintun.net/wintun.dll",
		},
	},
	{
		name:       "sing-box",
		files:      []string{"sing-box.exe"},
		targetDir:  prmfs.CoreRootDir,
		bundledRel: filepath.Join("third_party", "sing-box"),
		urls: map[string]string{
			"sing-box.exe": "https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-windows-amd64.exe",
		},
	},
}

// EnsureComponents ensures required external components are present in user .PRM folders.
// The .PRM layout is the runtime source of truth. If a component is missing there,
// startup may seed it from a nearby bundled copy or download URL on first run.
func EnsureComponents() error {
	if err := prmfs.EnsureLayout(); err != nil {
		return err
	}
	for _, c := range components {
		if err := ensureComponent(c); err != nil {
			// do not stop on single component failure; return aggregated error later
			return fmt.Errorf("component %s: %w", c.name, err)
		}
	}
	return nil
}

func ensureComponent(c component) error {
	targetRoot, err := c.targetDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(targetRoot, 0o755); err != nil {
		return err
	}

	// check all files exist
	missing := []string{}
	for _, f := range c.files {
		if _, err := os.Stat(filepath.Join(targetRoot, f)); err != nil {
			missing = append(missing, f)
		}
	}
	if len(missing) == 0 {
		return nil
	}

	// Try copying from bundled third_party relative to cwd or exe dir
	// candidate: cwd/ + bundledRel  OR exeDir/ + bundledRel
	// We'll try to copy any missing files from there
	exeCandidates := []string{}
	if cwd, err := os.Getwd(); err == nil {
		exeCandidates = append(exeCandidates, filepath.Join(cwd, c.bundledRel))
	}
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		exeCandidates = append(exeCandidates, filepath.Join(exeDir, c.bundledRel), filepath.Join(exeDir, "third_party", c.name))
	}

	for _, cand := range exeCandidates {
		ok := true
		for _, f := range missing {
			if _, err := os.Stat(filepath.Join(cand, f)); err != nil {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		// copy all missing
		for _, f := range missing {
			src := filepath.Join(cand, f)
			dst := filepath.Join(targetRoot, f)
			if err := copyFile(src, dst); err != nil {
				return err
			}
		}
		return nil
	}

	// Attempt downloads for missing files
	for _, f := range missing {
		url, ok := c.urls[f]
		if !ok || url == "" {
			return fmt.Errorf("missing %s and no download URL configured", f)
		}
		if err := downloadToFile(url, filepath.Join(targetRoot, f)); err != nil {
			return fmt.Errorf("download %s failed: %w", f, err)
		}
	}
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

func downloadToFile(url, dst string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.New("bad status: " + resp.Status)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
