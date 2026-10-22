package main

import (
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestFindIPv4ForName(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.168.1.0/24")
	records := []dnsRecord{{Name: "host.local", Type: 1, Value: "192.168.1.10"}}
	if got := findIPv4ForName(records, "host.local", network); got != "192.168.1.10" {
		t.Fatalf("got %q", got)
	}
}

func TestBuildAssetsKeepsMultipleServicesAndDeviceInfo(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.168.10.0/24")
	records := []dnsRecord{
		{Name: "nas.local", Type: 1, Value: "192.168.10.5"},
		{Name: "NAS._http._tcp.local", Type: 33, Value: "nas.local", Port: 5000},
		{Name: "NAS._qdiscover._tcp.local", Type: 33, Value: "nas.local", Port: 5000},
		{Name: "_device-info._tcp.local", Type: 12, Value: "NAS(AFP)._device-info._tcp.local"},
		{Name: "NAS(AFP)._device-info._tcp.local", Type: 16, TXT: map[string]string{"model": "Xserve"}},
	}
	assets := buildAssets([]mdnsResult{{Records: records}}, network, []int{5000})
	seen := map[string]bool{}
	for _, asset := range assets {
		seen[asset.Service+":"+strconv.Itoa(asset.Port)] = true
	}
	for _, key := range []string{"http:5000", "qdiscover:5000", "device-info:0"} {
		if !seen[key] {
			t.Errorf("missing service %s in %#v", key, assets)
		}
	}
}

func TestWorkstationNameIncludesMAC(t *testing.T) {
	_, network, _ := net.ParseCIDR("192.168.10.0/24")
	records := []dnsRecord{
		{Name: "nas.local", Type: 1, Value: "192.168.10.5"},
		{Name: "NAS._workstation._tcp.local", Type: 33, Value: "nas.local", Port: 9},
		{Name: "NAS._workstation._tcp.local", Type: 16, TXT: map[string]string{"mac": "24-5e-be-69-a3-13"}},
	}
	assets := buildAssets([]mdnsResult{{Records: records}}, network, []int{9})
	if len(assets) != 1 || assets[0].Name != "NAS [24:5e:be:69:a3:13]" {
		t.Fatalf("unexpected workstation identity: %#v", assets)
	}
}

func TestCollectAnswersExcludesInstanceNames(t *testing.T) {
	responses := []mdnsResult{{Records: []dnsRecord{
		{Name: "_services._dns-sd._udp.local", Type: 12, Value: "_http._tcp.local"},
		{Name: "_services._dns-sd._udp.local", Type: 12, Value: "_services._dns-sd._udp.local"},
		{Name: "_http._tcp.local", Type: 12, Value: "slw-nas._http._tcp.local"},
		{Name: "_smb._tcp.local", Type: 12, Value: "slw-nas._smb._tcp.local"},
		{Name: "_ipp._tcp.local", Type: 12, Value: "printer._ipp._tcp.local"},
	}}}
	got := strings.Join(collectAnswers(responses), ",")
	want := "_http._tcp.local"
	if got != want {
		t.Fatalf("collectAnswers = %q, want %q", got, want)
	}
}

func TestMACKeyPredicateMatchesExtraction(t *testing.T) {
	// Any key macFromTXT can read a MAC from must also be filtered by
	// visibleTXT, otherwise the MAC is printed twice.
	for _, key := range []string{"mac", "mac_addr", "macaddr", "MACAddress", "address", "hwaddr"} {
		if !isMACKey(key) {
			t.Errorf("isMACKey(%q) = false", key)
		}
		asset := Asset{MAC: "24:5e:be:69:a3:13", TXT: map[string]string{key: "24:5e:be:69:a3:13"}}
		if keys, _ := visibleTXT(asset); len(keys) != 0 {
			t.Errorf("key %q still visible: %v", key, keys)
		}
	}
	for _, key := range []string{"model", "path", "accessType", "device"} {
		if isMACKey(key) {
			t.Errorf("isMACKey(%q) = true", key)
		}
	}
}

func TestTXTDoesNotLeakAcrossServices(t *testing.T) {
	assets := buildAssets([]mdnsResult{{Records: loadReferenceRecords(t)}}, referenceNetwork(t), []int{9, 445, 548, 5000})
	for _, asset := range assets {
		if asset.Service == "qdiscover" {
			continue
		}
		for key := range asset.TXT {
			switch strings.ToLower(key) {
			case "accesstype", "accessport", "displaymodel", "fwver", "fwbuildnum":
				t.Errorf("service %s leaked qdiscover TXT %s", asset.Service, key)
			}
		}
	}
}
