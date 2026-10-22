package main

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

func mustResolveUDP(address string) (*net.UDPAddr, error) {
	resolved, err := net.ResolveUDPAddr("udp4", address)
	if err != nil || resolved == nil {
		if err == nil {
			err = errors.New("resolved UDP address is nil")
		}
		return nil, fmt.Errorf("resolve UDP address %q: %w", address, err)
	}
	return resolved, nil
}

func mustResolveUDPForNetwork(address string, ipv6 bool, iface *net.Interface) (*net.UDPAddr, error) {
	if !ipv6 {
		return mustResolveUDP(address)
	}
	resolved, err := net.ResolveUDPAddr("udp6", address)
	if err != nil || resolved == nil {
		if err == nil {
			err = errors.New("resolved UDP address is nil")
		}
		return nil, fmt.Errorf("resolve UDP address %q: %w", address, err)
	}
	resolved.Zone = iface.Name
	return resolved, nil
}
