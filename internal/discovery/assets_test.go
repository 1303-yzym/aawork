package discovery

import (
	"strconv"
	"strings"
	"testing"

	"github.com/1303-yzym/mdns-go/internal/mdns"
)

func TestBuildAssetsKeepsMultipleServicesAndDeviceInfo(t *testing.T) {
	records := []mdns.Record{
		{Name: "nas.local", Type: mdns.TypeA, Value: "192.168.10.5"},
		{Name: "NAS._http._tcp.local", Type: mdns.TypeSRV, Value: "nas.local", Port: 5000},
		{Name: "NAS._qdiscover._tcp.local", Type: mdns.TypeSRV, Value: "nas.local", Port: 5000},
		{Name: "_device-info._tcp.local", Type: mdns.TypePTR, Value: "NAS(AFP)._device-info._tcp.local"},
		{Name: "NAS(AFP)._device-info._tcp.local", Type: mdns.TypeTXT, TXT: map[string]string{"model": "Xserve"}},
	}
	assets := BuildAssets([]mdns.Result{{Records: records}}, []int{5000})
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
	records := []mdns.Record{
		{Name: "nas.local", Type: mdns.TypeA, Value: "192.168.10.5"},
		{Name: "NAS._workstation._tcp.local", Type: mdns.TypeSRV, Value: "nas.local", Port: 9},
		{Name: "NAS._workstation._tcp.local", Type: mdns.TypeTXT, TXT: map[string]string{"mac": "24-5e-be-69-a3-13"}},
	}
	assets := BuildAssets([]mdns.Result{{Records: records}}, []int{9})
	if len(assets) != 1 || assets[0].Name != "NAS [24:5e:be:69:a3:13]" {
		t.Fatalf("unexpected workstation identity: %#v", assets)
	}
}

func TestBuildAssetsSkipsPortsOutsideScope(t *testing.T) {
	records := []mdns.Record{
		{Name: "nas.local", Type: mdns.TypeA, Value: "192.168.10.5"},
		{Name: "NAS._http._tcp.local", Type: mdns.TypeSRV, Value: "nas.local", Port: 5000},
	}
	if assets := BuildAssets([]mdns.Result{{Records: records}}, []int{80}); len(assets) != 0 {
		t.Fatalf("out-of-scope service kept: %#v", assets)
	}
}

func TestCollectAnswersExcludesInstanceNames(t *testing.T) {
	responses := []mdns.Result{{Records: []mdns.Record{
		{Name: "_services._dns-sd._udp.local", Type: mdns.TypePTR, Value: "_http._tcp.local"},
		{Name: "_services._dns-sd._udp.local", Type: mdns.TypePTR, Value: "_services._dns-sd._udp.local"},
		{Name: "_http._tcp.local", Type: mdns.TypePTR, Value: "slw-nas._http._tcp.local"},
		{Name: "_smb._tcp.local", Type: mdns.TypePTR, Value: "slw-nas._smb._tcp.local"},
		{Name: "_ipp._tcp.local", Type: mdns.TypePTR, Value: "printer._ipp._tcp.local"},
	}}}
	got := strings.Join(CollectAnswers(responses), ",")
	want := "_http._tcp.local"
	if got != want {
		t.Fatalf("CollectAnswers = %q, want %q", got, want)
	}
}

func TestTXTDoesNotLeakAcrossServices(t *testing.T) {
	assets := BuildAssets([]mdns.Result{{Records: loadReferenceRecords(t)}}, []int{9, 445, 548, 5000})
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
