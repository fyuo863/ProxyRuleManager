package netadapter

import "net"

func LookupIPv4(name string) (net.IP, error) {
	return lookupIPv4(name)
}

func LookupFallbackIPv4(excludeName string) (net.IP, string, error) {
	return lookupFallbackIPv4(excludeName)
}

func ClearAddressCache() {
	clearAddressCache()
}
