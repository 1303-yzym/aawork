package scan

import (
	"encoding/binary"
	"strings"
)

// ProtocolFor resolves the wire protocol spoken on a port, preferring the
// mDNS service name over the well-known port when both are available.
func ProtocolFor(port int, service string) string {
	s := strings.ToLower(service)
	switch {
	case strings.Contains(s, "https") || port == 443 || port == 8443:
		return "https"
	case strings.Contains(s, "qdiscover"):
		return "qdiscover"
	case strings.Contains(s, "afpovertcp") || port == 548:
		return "afp"
	case strings.Contains(s, "http") || port == 80 || port == 8080 || port == 5000:
		return "http"
	case strings.Contains(s, "ssh") || port == 22:
		return "ssh"
	case strings.Contains(s, "ftp") || port == 21:
		return "ftp"
	case strings.Contains(s, "smb") || port == 139 || port == 445:
		return "smb"
	default:
		return "tcp"
	}
}

// ServiceForPort names a service for a port that has no mDNS answer.
func ServiceForPort(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 80, 8080:
		return "http"
	case 139, 445:
		return "smb"
	case 548:
		return "afp"
	case 443, 8443:
		return "https"
	default:
		return "tcp"
	}
}

// ParseHTTPHeaders extracts header fields from a raw HTTP response, skipping
// the status line.
func ParseHTTPHeaders(banner string) map[string]string {
	headers := map[string]string{}
	lines := strings.Split(banner, "\n")
	for _, line := range lines[1:] {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok {
			headers[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	return headers
}

func smbNegotiateRequest() []byte {
	// NetBIOS session packet + SMB2 NEGOTIATE request (dialects 2.0.2,
	// 2.1, 3.0, 3.0.2 and 3.1.1).
	p := make([]byte, 4+64+46)
	copy(p[4:], []byte{0xfe, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(p[68:70], 36)
	binary.LittleEndian.PutUint16(p[70:72], 5)
	copy(p[4+64+36:], []byte{0x02, 0x02, 0x10, 0x02, 0x22, 0x02, 0x24, 0x02, 0x02, 0x03})
	length := uint32(len(p) - 4)
	p[1] = byte(length >> 16)
	p[2] = byte(length >> 8)
	p[3] = byte(length)
	return p
}
