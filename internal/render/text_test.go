package render

import (
	"strings"
	"testing"

	"github.com/1303-yzym/mdns-go/internal/model"
)

func TestTextIncludesDeepFields(t *testing.T) {
	var output strings.Builder
	err := Text(&output, []model.Asset{{
		IP: "192.168.1.10", Port: 5000, Service: "qdiscover",
		Name: "slw-nas", Hostname: "slw-nas.local", TTL: 10,
		TXT: map[string]string{"model": "TS-464C"},
	}}, []string{"_qdiscover._tcp.local"}, true, nil)
	if err != nil {
		t.Fatalf("Text returned error: %v", err)
	}

	for _, expected := range []string{"5000/tcp qdiscover:", "IP=192.168.1.10", "Hostname=slw-nas.local", "model=TS-464C"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("output does not contain %q:\n%s", expected, output.String())
		}
	}
}

func TestTextGroupsPTRAnswers(t *testing.T) {
	var output strings.Builder
	if err := Text(&output, nil, []string{"_http._tcp.local", "_smb._tcp.local"}, false, nil); err != nil {
		t.Fatal(err)
	}
	want := "answers:\nPTR:\n_http._tcp.local\n_smb._tcp.local\n"
	if !strings.Contains(output.String(), want) {
		t.Fatalf("unexpected answers output:\n%s", output.String())
	}
}

func TestTextReportsScanErrors(t *testing.T) {
	var output strings.Builder
	if err := Text(&output, nil, nil, false, []string{"eth0: no matching mDNS response"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "error: eth0: no matching mDNS response") {
		t.Fatalf("scan error missing:\n%s", output.String())
	}
}

func TestVisibleTXTHidesEveryMACKeyVariant(t *testing.T) {
	// Any key model.MACFromTXT can read a MAC from must also be hidden here,
	// otherwise the MAC is printed twice.
	const mac = "24:5e:be:69:a3:13"
	for _, key := range []string{"mac", "mac_addr", "macaddr", "MACAddress", "address", "hwaddr"} {
		if !model.IsMACKey(key) {
			t.Errorf("model.IsMACKey(%q) = false", key)
		}
		asset := model.Asset{MAC: mac, TXT: map[string]string{key: mac}}
		if keys, _ := visibleTXT(asset); len(keys) != 0 {
			t.Errorf("key %q still visible: %v", key, keys)
		}
	}
	for _, key := range []string{"model", "path", "accessType", "device"} {
		if model.IsMACKey(key) {
			t.Errorf("model.IsMACKey(%q) = true", key)
		}
	}
}

func TestVisibleTXTKeepsPreferredOrder(t *testing.T) {
	asset := model.Asset{TXT: map[string]string{
		"fwVer": "5.2.9", "model": "TS-X64", "path": "/", "zzz": "last",
	}}
	keys, _ := visibleTXT(asset)
	if got := strings.Join(keys, ","); got != "path,model,fwVer,zzz" {
		t.Fatalf("key order = %s", got)
	}
}
