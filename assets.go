package main

import (
	"net"
	"sort"
	"strings"
)

func buildAssets(results []mdnsResult, network *net.IPNet, ports []int) []Asset {
	hosts := map[string]*hostData{}
	var records []dnsRecord
	var assets []Asset
	for _, result := range results {
		records = append(records, result.Records...)
	}
	for _, record := range records {
		if record.Type != 1 && record.Type != 28 {
			continue
		}
		key := strings.ToLower(strings.TrimSuffix(record.Name, "."))
		host := hosts[key]
		if host == nil {
			host = &hostData{hostname: key}
			hosts[key] = host
		}
		host.ttl = record.TTL
		if record.Type == 1 {
			host.ipv4 = appendUnique(host.ipv4, record.Value)
		} else {
			host.ipv6 = appendUnique(host.ipv6, record.Value)
		}
	}
	for _, record := range records {
		if record.Type != 33 || len(record.Value) == 0 {
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
		if !containsInt(ports, record.Port) {
			continue
		}
		service := serviceType(record.Name)
		name := instanceName(record.Name, service)
		txt := mergeTXTForInstance(records, record.Name, target)
		mac := macFromTXT(txt)
		if service == "afpovertcp" && !strings.HasSuffix(name, "(AFP)") {
			name += "(AFP)"
		}
		if mac != "" && service == "workstation" {
			name += " [" + mac + "]"
		}
		asset := Asset{
			IP: ip, Host: host.hostname, Port: record.Port, Service: service, Name: name,
			MAC: mac, Discovered: true,
			Hostname: host.hostname, IPv4: append([]string(nil), host.ipv4...),
			IPv6: append([]string(nil), host.ipv6...), TTL: host.ttl, TXT: txt,
		}
		assets = appendUniqueAsset(assets, asset)
	}
	for _, record := range records {
		if record.Type != 12 || !strings.Contains(strings.ToLower(record.Name), "_device-info.") {
			continue
		}
		serviceName := strings.TrimSuffix(record.Value, ".")
		name := instanceName(serviceName, "device-info")
		host := findHostByInstance(hosts, name)
		if host == nil {
			continue
		}
		txt := mergeTXTForInstance(records, serviceName, host.hostname)
		assets = appendUniqueAsset(assets, Asset{
			IP:   firstNonEmpty(append(append([]string{}, host.ipv4...), host.ipv6...)...),
			Host: host.hostname, Port: 0, Service: "device-info", Name: name,
			MAC: macFromTXT(txt), Discovered: true, Hostname: host.hostname,
			IPv4: append([]string(nil), host.ipv4...), IPv6: append([]string(nil), host.ipv6...),
			TTL: host.ttl, TXT: txt,
		})
	}
	sort.SliceStable(assets, func(i, j int) bool {
		if assets[i].IP != assets[j].IP {
			return assets[i].IP < assets[j].IP
		}
		ri, rj := serviceRank(assets[i].Service), serviceRank(assets[j].Service)
		if ri != rj {
			return ri < rj
		}
		if assets[i].Port != assets[j].Port {
			return assets[i].Port < assets[j].Port
		}
		return assets[i].Name < assets[j].Name
	})
	return assets
}

// referenceServiceOrder keeps text output stable and matches the documented
// example ordering: workstation, http, smb, qdiscover, device-info, afp.
var referenceServiceOrder = []string{
	"workstation", "http", "smb", "qdiscover", "device-info", "afpovertcp",
}

func serviceRank(service string) int {
	for i, known := range referenceServiceOrder {
		if strings.EqualFold(service, known) {
			return i
		}
	}
	return len(referenceServiceOrder)
}

func appendUniqueAsset(assets []Asset, asset Asset) []Asset {
	for i := range assets {
		if assets[i].IP == asset.IP && assets[i].Port == asset.Port && assets[i].Service == asset.Service && assets[i].Name == asset.Name {
			assets[i].TXT = mergeMaps(assets[i].TXT, asset.TXT)
			return assets
		}
	}
	return append(assets, asset)
}

func mergeTXTForInstance(records []dnsRecord, instance, target string) map[string]string {
	result := map[string]string{}
	ownerLower := strings.ToLower(strings.TrimSuffix(instance, "."))
	service := serviceType(instance)
	base := strings.ToLower(strings.TrimSuffix(instanceName(instance, service), "."))
	for _, record := range records {
		if record.Type != 16 {
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
		if strings.ToLower(strings.TrimSuffix(instanceName(name, "qdiscover"), ".")) == base {
			result = mergeMaps(result, record.TXT)
		}
	}
	return result
}

// isMACKey is the single source of truth for "this TXT key may carry a MAC
// address". macFromTXT and visibleTXT must agree, otherwise the same MAC is
// emitted both inside Name and as a duplicate TXT line.
func isMACKey(key string) bool {
	lower := strings.ToLower(key)
	return strings.Contains(lower, "mac") ||
		strings.Contains(lower, "hwaddr") ||
		lower == "address"
}

func macFromTXT(values map[string]string) string {
	for key, value := range values {
		if !isMACKey(key) {
			continue
		}
		if normalized := normalizeMAC(value); normalized != "" {
			return normalized
		}
	}
	return ""
}

func normalizeMAC(value string) string {
	value = strings.NewReplacer("-", ":", ".", ":", " ", "").Replace(strings.TrimSpace(value))
	parts := strings.Split(value, ":")
	if len(parts) != 6 {
		return ""
	}
	for i := range parts {
		if len(parts[i]) != 2 {
			return ""
		}
	}
	return strings.ToLower(strings.Join(parts, ":"))
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

func findIPForName(records []dnsRecord, name string, network *net.IPNet) string {
	for _, record := range records {
		if (record.Type == 1 || record.Type == 28) && strings.EqualFold(record.Name, name) && network.Contains(net.ParseIP(record.Value)) {
			return record.Value
		}
	}
	return ""
}

func findIPv4ForName(records []dnsRecord, name string, network *net.IPNet) string {
	for _, record := range records {
		if record.Type == 1 && strings.EqualFold(record.Name, name) && network.Contains(net.ParseIP(record.Value)) {
			return record.Value
		}
	}
	return ""
}

func findTXT(records []dnsRecord, name string) map[string]string {
	for _, record := range records {
		if record.Type == 16 && strings.EqualFold(record.Name, name) {
			return record.TXT
		}
	}
	return nil
}
