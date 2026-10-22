package main

import (
	"strings"
)

// isServiceType reports whether name has the shape _service._tcp.local /
// _service._udp.local. Instance names and the _services enumeration pseudo
// type are rejected.
func isServiceType(name string) bool {
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(name), "."), ".")
	if len(labels) != 3 {
		return false
	}
	if !strings.HasPrefix(labels[0], "_") || len(labels[0]) < 2 {
		return false
	}
	if labels[1] != "_tcp" && labels[1] != "_udp" {
		return false
	}
	return labels[2] == "local"
}

func serviceType(name string) string {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i, label := range labels {
		if strings.EqualFold(label, "_tcp") || strings.EqualFold(label, "_udp") {
			if i > 0 {
				return strings.TrimPrefix(labels[i-1], "_")
			}
		}
	}
	return "unknown"
}

func instanceName(name, service string) string {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	for i, label := range labels {
		isProto := strings.EqualFold(label, "_tcp") || strings.EqualFold(label, "_udp")
		if isProto && i > 0 {
			if i > 1 && strings.EqualFold(strings.TrimPrefix(labels[i-1], "_"), service) {
				return strings.Join(labels[:i-1], ".")
			}
			return strings.Join(labels[:i], ".")
		}
	}
	return strings.TrimSuffix(name, ".")
}
