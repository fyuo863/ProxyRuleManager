package prmfs

import (
	"os"
	"path/filepath"
)

const (
	rootFolderName = ".PRM"
	coreFolderName = "core"
	tunFolderName  = "tun-runtime"
	diagFolderName = "diagnostics"
)

func RootDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, rootFolderName), nil
}

func ConfigPath() (string, error) {
	root, err := RootDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "config.json"), nil
}

func CoreRootDir() (string, error) {
	root, err := RootDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, coreFolderName), nil
}

func TunRuntimeDir() (string, error) {
	root, err := RootDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, tunFolderName), nil
}

func DiagnosticsDir() (string, error) {
	root, err := RootDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, diagFolderName), nil
}

func DiagnosticsFilePath() (string, error) {
	dir, err := DiagnosticsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "agent-diagnostics.json"), nil
}

func LegacyConfigPath() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "ProxyRuleManager", "config.json"), nil
}

func EnsureLayout() error {
	root, err := RootDir()
	if err != nil {
		return err
	}
	coreDir, err := CoreRootDir()
	if err != nil {
		return err
	}
	tunDir, err := TunRuntimeDir()
	if err != nil {
		return err
	}
	diagDir, err := DiagnosticsDir()
	if err != nil {
		return err
	}
	for _, dir := range []string{root, coreDir, tunDir, diagDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	return nil
}
