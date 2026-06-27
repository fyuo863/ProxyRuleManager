//go:build !windows

package tun

func RuntimeArtifactsSnapshot() RuntimeArtifacts {
	return RuntimeArtifacts{}
}
