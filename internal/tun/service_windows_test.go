//go:build windows

package tun

import "testing"

func TestIPv4FromMapped(t *testing.T) {
	t.Run("extracts non-loopback ipv4 mapped address", func(t *testing.T) {
		got := ipv4FromMapped([4]uint32{0x0a0c0f55, 0x0000ffff, 0, 0})
		if got == nil || got.String() != "10.12.15.85" {
			t.Fatalf("expected 10.12.15.85, got %v", got)
		}
	})

	t.Run("extracts loopback ipv4 mapped address", func(t *testing.T) {
		got := ipv4FromMapped([4]uint32{0x7f000001, 0x0000ffff, 0, 0})
		if got == nil || got.String() != "127.0.0.1" {
			t.Fatalf("expected 127.0.0.1, got %v", got)
		}
	})

	t.Run("rejects non-mapped ipv6 address", func(t *testing.T) {
		if got := ipv4FromMapped([4]uint32{0, 0, 0, 1}); got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})
}
