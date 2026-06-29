package netroute

import (
	"reflect"
	"testing"
)

func TestNormalizeIPv4Targets(t *testing.T) {
	got := NormalizeIPv4Targets([]string{
		" 1.2.3.4 ",
		"1.2.3.4/32",
		"8.8.8.8/24",
		"127.0.0.1",
		"0.0.0.0",
		"169.254.1.1",
		"224.0.0.1",
		"not-an-ip",
		"5.6.7.8",
	})
	want := []string{"1.2.3.4", "5.6.7.8"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeIPv4Targets() = %#v, want %#v", got, want)
	}
}
