// Package scan enumerates hosts, probes TCP endpoints and knows how the
// supported services are spoken on the wire.
package scan

import (
	"errors"
	"fmt"
	"net"
)

const maxScanHosts = uint64(65536)

// Hosts lists the scannable addresses of a CIDR, rejecting ranges that are too
// large to enumerate.
func Hosts(network *net.IPNet) ([]string, error) {
	hostCount, err := networkHostCount(network)
	if err != nil {
		return nil, err
	}
	if hostCount > maxScanHosts {
		return nil, fmt.Errorf("CIDR contains %d scannable hosts; maximum is %d (split the range)", hostCount, maxScanHosts)
	}
	return enumerateHosts(network), nil
}

func networkHostCount(network *net.IPNet) (uint64, error) {
	ones, bits := network.Mask.Size()
	if ones < 0 {
		return 0, errors.New("invalid CIDR mask")
	}
	hostBits := bits - ones
	if hostBits >= 63 {
		return maxScanHosts + 1, nil
	}
	count := uint64(1) << uint(hostBits)
	if bits == 32 && hostBits > 1 {
		count -= 2
	}
	return count, nil
}

func enumerateHosts(network *net.IPNet) []string {
	var hosts []string
	ip := append(net.IP(nil), network.IP...)
	ones, bits := network.Mask.Size()
	for network.Contains(ip) {
		isNetwork := len(ip) == net.IPv4len && ip.Equal(network.IP)
		next := incIP(ip)
		isBroadcast := false
		if len(ip) == net.IPv4len {
			last := append(net.IP(nil), network.IP...)
			for i := range last {
				last[i] |= ^network.Mask[i]
			}
			isBroadcast = ip.Equal(last)
		}
		pointToPoint := bits == 32 && ones >= 31
		if !(isNetwork || isBroadcast) || pointToPoint {
			hosts = append(hosts, ip.String())
		}
		ip = next
	}
	return hosts
}

func incIP(ip net.IP) net.IP {
	next := append(net.IP(nil), ip...)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}
