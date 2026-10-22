package mdns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	groupAddress = "224.0.0.251:5353"
	queryPort    = 5353
)

// socket is an interface-scoped mDNS query socket. unicast is set when the
// well-known port 5353 could not be claimed, in which case queries carry the
// QU (unicast-response) bit and replies arrive on an ephemeral port.
type socket struct {
	conn        *net.UDPConn
	destination *net.UDPAddr
	unicast     bool
}

// openSocket prefers a multicast listener on port. System mDNS daemons
// (Bonjour, Avahi, Windows Dnscache) commonly own 5353 exclusively, so binding
// failure falls back to an ephemeral port with QU queries instead of losing
// discovery entirely.
func openSocket(iface *net.Interface, network *net.IPNet, port int) (*socket, error) {
	networkIsV6 := network.IP.To4() == nil
	networkType, group, wildcard := "udp4", groupAddress, net.IPv4zero
	if networkIsV6 {
		networkType, group, wildcard = "udp6", "[ff02::fb]:5353", net.IPv6unspecified
	}
	listenIP := wildcard
	if addr := interfaceIP(iface, networkIsV6); addr != nil {
		listenIP = addr
	}
	destination, err := resolveUDP(group, networkIsV6, iface)
	if err != nil {
		return nil, err
	}

	conn, multicastErr := net.ListenMulticastUDP(networkType, iface, &net.UDPAddr{IP: listenIP, Port: port})
	if multicastErr == nil {
		return &socket{conn: conn, destination: destination}, nil
	}

	local := &net.UDPAddr{Port: 0}
	if listenIP != nil && !listenIP.IsUnspecified() {
		local.IP = listenIP
	}
	fallback, err := net.ListenUDP(networkType, local)
	if err != nil {
		return nil, fmt.Errorf("bind udp port %d failed: %w; ephemeral fallback failed: %v", port, multicastErr, err)
	}
	return &socket{conn: fallback, destination: destination, unicast: true}, nil
}

func (q *socket) send(services []string) error {
	_, err := q.conn.WriteToUDP(buildQuery(services, q.unicast), q.destination)
	return err
}

func (q *socket) run(ctx context.Context, timeout time.Duration) (Result, error) {
	if err := q.conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return Result{}, err
	}
	if err := q.send(CommonServices); err != nil {
		return Result{}, err
	}

	var all []Record
	buffer := make([]byte, 65535)
	queried := map[string]bool{}
	for _, service := range CommonServices {
		queried[strings.ToLower(service)] = true
	}
	queryServices := func(records []Record) error {
		var extra []string
		for _, record := range records {
			if record.Type == TypePTR && strings.HasPrefix(record.Value, "_") {
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
			return Result{}, ctx.Err()
		default:
		}
		count, _, err := q.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			return Result{}, err
		}
		// Filter addresses from records below, not the packet source. mDNS
		// responders commonly reply from a link-local address while the
		// requested CIDR contains a global or private address.
		records, err := parseMessage(buffer[:count])
		if err == nil {
			all = append(all, records...)
			if err := queryServices(records); err != nil {
				return Result{}, err
			}
		}
	}
	if len(all) == 0 {
		return Result{}, errors.New("no matching mDNS response")
	}
	return Result{Records: all}, nil
}
