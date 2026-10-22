package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const mdnsGroup = "224.0.0.251:5353"

var commonServices = []string{
	"_services._dns-sd._udp.local",
	"_workstation._tcp.local", "_http._tcp.local", "_https._tcp.local",
	"_smb._tcp.local", "_afpovertcp._tcp.local", "_device-info._tcp.local",
	"_qdiscover._tcp.local", "_ssh._tcp.local", "_printer._tcp.local",
}

// mdnsSocket is an interface-scoped mDNS query socket. unicast is set when
// the well-known port 5353 could not be claimed, in which case queries carry
// the QU (unicast-response) bit and replies arrive on an ephemeral port.
type mdnsSocket struct {
	conn        *net.UDPConn
	destination *net.UDPAddr
	unicast     bool
}

func queryInterface(ctx context.Context, iface *net.Interface, network *net.IPNet, timeout time.Duration) (mdnsResult, error) {
	socket, err := openMDNSSocket(iface, network, 5353)
	if err != nil {
		return mdnsResult{}, err
	}
	defer socket.conn.Close()
	return socket.run(ctx, timeout)
}

// openMDNSSocket prefers a multicast listener on mdnsPort. System mDNS
// daemons (Bonjour, Avahi, Windows Dnscache) commonly own 5353 exclusively,
// so binding failure falls back to an ephemeral port with QU queries instead
// of losing discovery entirely.
func openMDNSSocket(iface *net.Interface, network *net.IPNet, mdnsPort int) (*mdnsSocket, error) {
	networkIsV6 := network.IP.To4() == nil
	networkType, group, wildcard := "udp4", mdnsGroup, net.IPv4zero
	if networkIsV6 {
		networkType, group, wildcard = "udp6", "[ff02::fb]:5353", net.IPv6unspecified
	}
	listenIP := wildcard
	if addr := interfaceIP(iface, networkIsV6); addr != nil {
		listenIP = addr
	}
	destination, err := mustResolveUDPForNetwork(group, networkIsV6, iface)
	if err != nil {
		return nil, err
	}

	conn, multicastErr := net.ListenMulticastUDP(networkType, iface, &net.UDPAddr{IP: listenIP, Port: mdnsPort})
	if multicastErr == nil {
		return &mdnsSocket{conn: conn, destination: destination}, nil
	}

	local := &net.UDPAddr{Port: 0}
	if listenIP != nil && !listenIP.IsUnspecified() {
		local.IP = listenIP
	}
	fallback, err := net.ListenUDP(networkType, local)
	if err != nil {
		return nil, fmt.Errorf("bind udp port %d failed: %w; ephemeral fallback failed: %v", mdnsPort, multicastErr, err)
	}
	return &mdnsSocket{conn: fallback, destination: destination, unicast: true}, nil
}

func (q *mdnsSocket) send(services []string) error {
	_, err := q.conn.WriteToUDP(buildQuery(services, q.unicast), q.destination)
	return err
}

func (q *mdnsSocket) run(ctx context.Context, timeout time.Duration) (mdnsResult, error) {
	if err := q.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return mdnsResult{}, err
	}
	if err := q.send(commonServices); err != nil {
		return mdnsResult{}, err
	}

	var all []dnsRecord
	buffer := make([]byte, 65535)
	queried := map[string]bool{}
	for _, service := range commonServices {
		queried[strings.ToLower(service)] = true
	}
	queryServices := func(records []dnsRecord) error {
		var extra []string
		for _, record := range records {
			if record.Type == 12 && strings.HasPrefix(record.Value, "_") {
				service := strings.ToLower(record.Value)
				if !queried[service] {
					queried[service] = true
					extra = append(extra, service)
				}
			}
		}
		if len(extra) == 0 {
			return nil
		}
		return q.send(extra)
	}
	for {
		select {
		case <-ctx.Done():
			return mdnsResult{}, ctx.Err()
		default:
		}
		count, _, err := q.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			return mdnsResult{}, err
		}
		// Filter addresses from records below, not the packet source. mDNS
		// responders commonly reply from a link-local address while the
		// requested CIDR contains a global or private address.
		records, err := parseDNSMessage(buffer[:count])
		if err == nil {
			all = append(all, records...)
			if err := queryServices(records); err != nil {
				return mdnsResult{}, err
			}
		}
	}
	if len(all) == 0 {
		return mdnsResult{}, errors.New("no matching mDNS response")
	}
	return mdnsResult{SourceIP: "", Records: all}, nil
}
