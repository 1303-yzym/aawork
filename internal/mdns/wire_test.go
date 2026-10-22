package mdns

import (
	"bytes"
	"testing"
)

func TestBuildQueryContainsPTRQuestions(t *testing.T) {
	packet := buildQuery([]string{"_http._tcp.local"}, false)
	records, err := parseMessage(append(packet, 0, 0, 0, 0, 0, 0))
	if err != nil {
		t.Fatalf("parseMessage returned error: %v", err)
	}

	if len(records) != 0 {
		t.Fatalf("query should not contain records: %v", records)
	}
	if !bytes.Contains(packet, []byte("_http")) {
		t.Fatalf("query does not contain service name: %x", packet)
	}
}

func TestParseMessagePreservesRecordValues(t *testing.T) {
	packet := []byte{
		0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0,
		4, 'h', 'o', 's', 't', 5, 'l', 'o', 'c', 'a', 'l', 0,
		0, 1, 0, 1, 0, 0, 0, 10, 0, 4, 192, 168, 1, 10,
		0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 10, 0, 16,
		0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
		0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 10, 0, 12,
		4, 'h', 'o', 's', 't', 5, 'l', 'o', 'c', 'a', 'l', 0,
		0xc0, 0x0c, 0, 33, 0, 1, 0, 0, 0, 10, 0, 8,
		0, 0, 0, 0, 0, 80, 0xc0, 0x0c,
	}
	records, err := parseMessage(packet)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 4 {
		t.Fatalf("got %d records, want 4", len(records))
	}
	want := []struct {
		kind  uint16
		value string
		port  int
	}{
		{TypeA, "192.168.1.10", 0},
		{TypeAAAA, "fe80::1", 0},
		{TypePTR, "host.local", 0},
		{TypeSRV, "host.local", 80},
	}
	for i, expected := range want {
		if records[i].Type != expected.kind || records[i].Value != expected.value || records[i].Port != expected.port {
			t.Errorf("record %d = %#v, want type=%d value=%q port=%d", i, records[i], expected.kind, expected.value, expected.port)
		}
	}
}

func TestBuildQueryUnicastResponseBit(t *testing.T) {
	multicast := buildQuery([]string{"_http._tcp.local"}, false)
	unicast := buildQuery([]string{"_http._tcp.local"}, true)
	multicastClass := multicast[len(multicast)-4:]
	unicastClass := unicast[len(unicast)-4:]
	if multicastClass[2] != 0x00 || multicastClass[3] != 0x01 {
		t.Fatalf("multicast class = %x, want 0001", multicastClass[2:])
	}
	if unicastClass[2] != 0x80 || unicastClass[3] != 0x01 {
		t.Fatalf("unicast class = %x, want 8001", unicastClass[2:])
	}
}

func TestIsServiceTypeRejectsInstanceNames(t *testing.T) {
	if !IsServiceType("_http._tcp.local") {
		t.Error(`IsServiceType("_http._tcp.local") = false`)
	}
	// Instance names and the DNS-SD enumeration type are not service types.
	for _, name := range []string{"slw-nas._http._tcp.local", "_http._tcp.example.com", "http._tcp.local", "_services._dns-sd._udp.local"} {
		if IsServiceType(name) {
			t.Errorf("IsServiceType(%q) = true", name)
		}
	}
}

func TestInstanceName(t *testing.T) {
	got := InstanceName("slw-nas._qdiscover._tcp.local", "qdiscover")
	if got != "slw-nas" {
		t.Fatalf("got %q, want %q", got, "slw-nas")
	}
}

func TestServiceType(t *testing.T) {
	if got := ServiceType("_afpovertcp._tcp.local"); got != "afpovertcp" {
		t.Fatalf("ServiceType = %q", got)
	}
}
