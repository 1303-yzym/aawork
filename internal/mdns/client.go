package mdns

import (
	"context"
	"net"
	"time"
)

// CommonServices is the initial browse list: the DNS-SD enumeration name plus
// the service types this tool reports on.
var CommonServices = []string{
	"_services._dns-sd._udp.local",
	"_workstation._tcp.local", "_http._tcp.local", "_https._tcp.local",
	"_smb._tcp.local", "_afpovertcp._tcp.local", "_device-info._tcp.local",
	"_qdiscover._tcp.local", "_ssh._tcp.local", "_printer._tcp.local",
}

// QueryInterface browses mDNS on one interface until timeout elapses. A
// running query needs both the well-known port and the responder to answer,
// so the error explains which of the two failed.
func QueryInterface(ctx context.Context, iface *net.Interface, network *net.IPNet, timeout time.Duration) (Result, error) {
	q, err := openSocket(iface, network, queryPort)
	if err != nil {
		return Result{}, err
	}
	defer q.conn.Close()
	return q.run(ctx, timeout)
}
