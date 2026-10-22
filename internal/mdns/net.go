package mdns

import (
	"errors"
	"fmt"
	"net"
)

func interfaceIP(iface *net.Interface, wantV6 bool) net.IP {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() || ipNet.IP.IsLinkLocalUnicast() {
			continue
		}
		if (ipNet.IP.To4() == nil) == wantV6 {
			return ipNet.IP
		}
	}
	return nil
}

func resolveUDP(address string, ipv6 bool, iface *net.Interface) (*net.UDPAddr, error) {
	network := "udp4"
	if ipv6 {
		network = "udp6"
	}
	resolved, err := net.ResolveUDPAddr(network, address)
	if err != nil || resolved == nil {
		if err == nil {
			err = errors.New("resolved UDP address is nil")
		}
		return nil, fmt.Errorf("resolve UDP address %q: %w", address, err)
	}
	if ipv6 {
		resolved.Zone = iface.Name
	}
	return resolved, nil
}
