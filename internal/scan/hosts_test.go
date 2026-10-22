package scan

import (
	"net"
	"strings"
	"testing"
)

func TestEnumerateHostsSkipsIPv4NetworkAndBroadcast(t *testing.T) {
	_, network, err := net.ParseCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	got := enumerateHosts(network)
	want := []string{"192.168.1.1", "192.168.1.2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestHostsCoversEveryHost(t *testing.T) {
	_, network, err := net.ParseCIDR("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := Hosts(network)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(hosts, ",") != "192.168.1.1,192.168.1.2" {
		t.Fatalf("unexpected hosts: %v", hosts)
	}
}

func TestHostsRejectsHugeCIDR(t *testing.T) {
	_, network, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Hosts(network); err == nil {
		t.Fatal("expected huge CIDR to be rejected")
	}
}

func TestHostsKeepsPointToPointRange(t *testing.T) {
	_, network, err := net.ParseCIDR("192.168.1.0/31")
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := Hosts(network)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(hosts, ",") != "192.168.1.0,192.168.1.1" {
		t.Fatalf("unexpected hosts: %v", hosts)
	}
}

func TestServiceForPort(t *testing.T) {
	for _, tc := range []struct {
		port int
		want string
	}{{21, "ftp"}, {22, "ssh"}, {80, "http"}, {445, "smb"}, {548, "afp"}, {443, "https"}, {9999, "tcp"}} {
		if got := ServiceForPort(tc.port); got != tc.want {
			t.Errorf("ServiceForPort(%d) = %q, want %q", tc.port, got, tc.want)
		}
	}
}
