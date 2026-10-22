package main

import (
	"net"
	"testing"
)

// When 5353 is already owned the socket must fall back to an ephemeral port
// instead of losing mDNS discovery.
func TestOpenMDNSSocketFallsBackWhenPortBusy(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var iface *net.Interface
	for i := range interfaces {
		if interfaces[i].Flags&net.FlagUp != 0 {
			iface = &interfaces[i]
			break
		}
	}
	if iface == nil || interfaceIP(iface, false) == nil {
		t.Skip("no IPv4 interface available")
	}
	_, network, _ := net.ParseCIDR("192.168.1.0/24")

	blocker, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	busyPort := blocker.LocalAddr().(*net.UDPAddr).Port

	socket, err := openMDNSSocket(iface, network, busyPort)
	if err != nil {
		t.Fatalf("fallback failed: %v", err)
	}
	defer socket.conn.Close()
	if !socket.unicast {
		t.Fatal("expected unicast fallback when the mDNS port is occupied")
	}
	if socket.conn.LocalAddr().(*net.UDPAddr).Port == busyPort {
		t.Fatal("fallback reused the busy port")
	}
}
