// Package mdns discovers services over multicast DNS: it encodes queries,
// decodes responses and owns the interface-scoped query socket.
package mdns

// DNS resource record types the discovery pipeline understands
// (RFC 1035, RFC 2782).
const (
	TypeA    uint16 = 1
	TypePTR  uint16 = 12
	TypeTXT  uint16 = 16
	TypeAAAA uint16 = 28
	TypeSRV  uint16 = 33
)

// Record is one decoded DNS answer. Only the types listed above are kept.
type Record struct {
	Name  string
	Value string
	Type  uint16
	TTL   uint32
	Port  int
	TXT   map[string]string
}

// Result is one interface's contribution to a discovery round.
type Result struct {
	// Source names the interface the query was sent from; it only appears in
	// error reporting.
	Source  string
	Records []Record
	Err     error
}
