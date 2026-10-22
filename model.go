package main

type Asset struct {
	IP         string            `json:"ip"`
	Port       int               `json:"port"`
	Host       string            `json:"host"`
	Service    string            `json:"service,omitempty"`
	Name       string            `json:"name,omitempty"`
	MAC        string            `json:"mac,omitempty"`
	Hostname   string            `json:"hostname,omitempty"`
	IPv4       []string          `json:"ipv4,omitempty"`
	IPv6       []string          `json:"ipv6,omitempty"`
	TTL        uint32            `json:"ttl,omitempty"`
	Banner     string            `json:"banner,omitempty"`
	Probe      *ProbeResult      `json:"probe,omitempty"`
	TXT        map[string]string `json:"txt,omitempty"`
	Discovered bool              `json:"discovered,omitempty"`
}

type ProbeResult struct {
	Protocol string            `json:"protocol"`
	Status   string            `json:"status"`
	Success  bool              `json:"success"`
	Banner   string            `json:"banner,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	TLS      *TLSInfo          `json:"tls,omitempty"`
}

type TLSInfo struct {
	Version    string   `json:"version,omitempty"`
	Cipher     string   `json:"cipher,omitempty"`
	Negotiated string   `json:"negotiated_protocol,omitempty"`
	Subject    string   `json:"subject,omitempty"`
	Issuer     string   `json:"issuer,omitempty"`
	DNSNames   []string `json:"dns_names,omitempty"`
	NotAfter   string   `json:"not_after,omitempty"`
}

type ScanOutput struct {
	Services []Asset  `json:"services"`
	Answers  []string `json:"answers,omitempty"`
	Errors   []string `json:"errors,omitempty"`
}

type dnsRecord struct {
	Name, Value string
	Type        uint16
	TTL         uint32
	Port        int
	TXT         map[string]string
}

type hostData struct {
	hostname   string
	ipv4, ipv6 []string
	ttl        uint32
}

type mdnsResult struct {
	SourceIP string
	Records  []dnsRecord
	Err      error
}
