package discovery

import (
	"maps"
	"slices"
	"strings"

	"github.com/1303-yzym/mdns-go/internal/mdns"
	"github.com/1303-yzym/mdns-go/internal/model"
)

// BuildAssets turns decoded mDNS answers into one asset per service instance.
// Instances whose port is outside the scan scope are dropped; the portless
// device-info entry is always kept.
func BuildAssets(results []mdns.Result, ports []int) []model.Asset {
	records := flattenRecords(results)
	hosts := indexHosts(records)
	assets := buildServiceAssets(records, hosts, ports)
	assets = buildDeviceInfoAssets(records, hosts, assets)
	model.SortAssets(assets)
	return assets
}

func flattenRecords(results []mdns.Result) []mdns.Record {
	var records []mdns.Record
	for _, result := range results {
		records = append(records, result.Records...)
	}
	return records
}

// hostData is everything known about one mDNS host name.
type hostData struct {
	hostname   string
	ipv4, ipv6 []string
	ttl        uint32
}

// indexHosts maps every A/AAAA owner name to the addresses it advertises.
func indexHosts(records []mdns.Record) map[string]*hostData {
	hosts := map[string]*hostData{}
	for _, record := range records {
		if record.Type != mdns.TypeA && record.Type != mdns.TypeAAAA {
			continue
		}
		key := strings.ToLower(strings.TrimSuffix(record.Name, "."))
		host := hosts[key]
		if host == nil {
			host = &hostData{hostname: key}
			hosts[key] = host
		}
		host.ttl = record.TTL
		if record.Type == mdns.TypeA {
			if !slices.Contains(host.ipv4, record.Value) {
				host.ipv4 = append(host.ipv4, record.Value)
			}
			continue
		}
		if !slices.Contains(host.ipv6, record.Value) {
			host.ipv6 = append(host.ipv6, record.Value)
		}
	}
	return hosts
}

// buildServiceAssets creates one asset per SRV record whose target host was
// resolved and whose port is part of the scan.
func buildServiceAssets(records []mdns.Record, hosts map[string]*hostData, ports []int) []model.Asset {
	var assets []model.Asset
	for _, record := range records {
		if record.Type != mdns.TypeSRV || len(record.Value) == 0 {
			continue
		}
		target := strings.ToLower(strings.TrimSuffix(record.Value, "."))
		host := hosts[target]
		if host == nil {
			continue
		}
		ip := firstNonEmpty(host.ipv4...)
		if ip == "" {
			ip = firstNonEmpty(host.ipv6...)
		}
		if ip == "" {
			continue
		}
		if !slices.Contains(ports, record.Port) {
			continue
		}
		service := mdns.ServiceType(record.Name)
		name := mdns.InstanceName(record.Name, service)
		txt := mergeTXTForInstance(records, record.Name, target)
		mac := model.MACFromTXT(txt)
		if service == "afpovertcp" && !strings.HasSuffix(name, "(AFP)") {
			name += "(AFP)"
		}
		if mac != "" && service == "workstation" {
			name += " [" + mac + "]"
		}
		asset := model.Asset{
			IP: ip, Host: host.hostname, Port: record.Port, Service: service, Name: name,
			MAC: mac, Discovered: true,
			Hostname: host.hostname, IPv4: append([]string(nil), host.ipv4...),
			IPv6: append([]string(nil), host.ipv6...), TTL: host.ttl, TXT: txt,
		}
		assets = appendUniqueAsset(assets, asset)
	}
	return assets
}

// buildDeviceInfoAssets adds the portless device-info entries, which are
// published as PTR plus TXT without an SRV record.
func buildDeviceInfoAssets(records []mdns.Record, hosts map[string]*hostData, assets []model.Asset) []model.Asset {
	for _, record := range records {
		if record.Type != mdns.TypePTR || !strings.Contains(strings.ToLower(record.Name), "_device-info.") {
			continue
		}
		serviceName := strings.TrimSuffix(record.Value, ".")
		name := mdns.InstanceName(serviceName, "device-info")
		host := findHostByInstance(hosts, name)
		if host == nil {
			continue
		}
		txt := mergeTXTForInstance(records, serviceName, host.hostname)
		assets = appendUniqueAsset(assets, model.Asset{
			IP:   firstNonEmpty(append(append([]string{}, host.ipv4...), host.ipv6...)...),
			Host: host.hostname, Port: 0, Service: "device-info", Name: name,
			MAC: model.MACFromTXT(txt), Discovered: true, Hostname: host.hostname,
			IPv4: append([]string(nil), host.ipv4...), IPv6: append([]string(nil), host.ipv6...),
			TTL: host.ttl, TXT: txt,
		})
	}
	return assets
}

// appendUniqueAsset merges an asset into assets, combining TXT with any entry
// that already describes the same target and service.
func appendUniqueAsset(assets []model.Asset, asset model.Asset) []model.Asset {
	for i := range assets {
		if assets[i].IP == asset.IP && assets[i].Port == asset.Port && assets[i].Service == asset.Service && assets[i].Name == asset.Name {
			assets[i].TXT = mergeMaps(assets[i].TXT, asset.TXT)
			return assets
		}
	}
	return append(assets, asset)
}

func mergeTXTForInstance(records []mdns.Record, instance, target string) map[string]string {
	result := map[string]string{}
	ownerLower := strings.ToLower(strings.TrimSuffix(instance, "."))
	service := mdns.ServiceType(instance)
	base := strings.ToLower(strings.TrimSuffix(mdns.InstanceName(instance, service), "."))
	for _, record := range records {
		if record.Type != mdns.TypeTXT {
			continue
		}
		name := strings.ToLower(strings.TrimSuffix(record.Name, "."))
		if name == ownerLower {
			result = mergeMaps(result, record.TXT)
			continue
		}
		// Responders such as QNAP publish one instance's attributes under a
		// sibling service name. Merge only inside that service family so TXT
		// never leaks into unrelated services.
		if service != "qdiscover" || !strings.Contains(name, "_qdiscover.") {
			continue
		}
		if strings.ToLower(strings.TrimSuffix(mdns.InstanceName(name, "qdiscover"), ".")) == base {
			result = mergeMaps(result, record.TXT)
		}
	}
	return result
}

func findHostByInstance(hosts map[string]*hostData, instance string) *hostData {
	base := strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(instance, "(AFP)"), "."))
	for key, host := range hosts {
		if strings.HasPrefix(key, base) || strings.HasPrefix(base, strings.TrimSuffix(key, ".local")) {
			return host
		}
	}
	return nil
}

func mergeMaps(dst, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = map[string]string{}
	}
	maps.Copy(dst, src)
	return dst
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
