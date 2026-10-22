package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"
)

const maxScanHosts = uint64(65536)

func scanHosts(network *net.IPNet) ([]string, error) {
	hostCount, err := networkHostCount(network)
	if err != nil {
		return nil, err
	}
	if hostCount > maxScanHosts {
		return nil, fmt.Errorf("CIDR contains %d scannable hosts; maximum is %d (split the range)", hostCount, maxScanHosts)
	}
	return enumerateHosts(network), nil
}

// scanNetwork streams host/port targets into a bounded worker pool instead of
// materialising every pair, so /24 x 1-10000 does not exhaust memory. mDNS
// assets only enrich a target; they never gate the scan.
func scanNetwork(ctx context.Context, discovered []Asset, network *net.IPNet, ports []int, timeout time.Duration) ([]Asset, error) {
	hosts, err := scanHosts(network)
	if err != nil {
		return nil, err
	}
	discoveredByTarget := map[string][]Asset{}
	passthrough := make([]Asset, 0, 4)
	for _, asset := range discovered {
		if asset.Port == 0 {
			passthrough = appendUniqueAsset(passthrough, asset)
			continue
		}
		key := targetKey(asset.IP, asset.Port)
		discoveredByTarget[key] = appendUniqueAsset(discoveredByTarget[key], asset)
	}

	probed := runProbePool(ctx,
		func(ctx context.Context, jobs chan<- Asset) {
			for _, host := range hosts {
				for _, port := range ports {
					if ctx.Err() != nil {
						return
					}
					targets, ok := discoveredByTarget[targetKey(host, port)]
					if !ok {
						targets = []Asset{{IP: host, Host: host, Port: port, Service: serviceForPort(port)}}
					}
					for _, asset := range targets {
						// Never block forever if every worker already returned
						// after cancellation.
						select {
						case jobs <- asset:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		},
		func(asset *Asset) { probeAsset(ctx, asset, timeout) },
	)
	return append(passthrough, probed...), nil
}

func targetKey(ip string, port int) string {
	return net.JoinHostPort(ip, strconv.Itoa(port))
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

// sortAssets keeps the documented reference ordering: by address, then by
// service rank (workstation, http, smb, qdiscover, device-info, afp), then
// port. A plain port sort would move the portless device-info entry to the
// top and break the reference output.
func sortAssets(assets []Asset) {
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
}
