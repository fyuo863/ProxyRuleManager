//go:build windows

package tun

import "path/filepath"

func RuntimeArtifactsSnapshot() RuntimeArtifacts {
	artifacts := RuntimeArtifacts{}
	if dir, err := runtimeDir(); err == nil {
		artifacts.RuntimeDir = dir
		artifacts.ConfigPath = filepath.Join(dir, "transparent-runtime.json")
		artifacts.LogPath = filepath.Join(dir, transparentLogName)
	}
	if dir, err := driverDir(); err == nil {
		artifacts.CoreDir = dir
	}
	if dllPath, err := winDivertRuntimeDir(); err == nil {
		artifacts.CoreExecutable = filepath.Join(dllPath, "WinDivert.dll")
	}
	return artifacts
}
