package model

import "strings"

// IsMACKey is the single source of truth for "this TXT key may carry a MAC
// address". MACFromTXT and the renderer must agree, otherwise the same MAC is
// emitted both inside Name and as a duplicate TXT line.
func IsMACKey(key string) bool {
	lower := strings.ToLower(key)
	return strings.Contains(lower, "mac") ||
		strings.Contains(lower, "hwaddr") ||
		lower == "address"
}

// MACFromTXT returns the first TXT value that normalises to a MAC address.
func MACFromTXT(values map[string]string) string {
	for key, value := range values {
		if !IsMACKey(key) {
			continue
		}
		if normalized := NormalizeMAC(value); normalized != "" {
			return normalized
		}
	}
	return ""
}

// NormalizeMAC converts the common separator styles to lower-case colon form,
// returning "" when the value is not a six-octet address.
func NormalizeMAC(value string) string {
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
