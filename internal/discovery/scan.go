package discovery

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/1303-yzym/mdns-go/internal/model"
	"github.com/1303-yzym/mdns-go/internal/scan"
)

// scanNetwork streams host/port targets into the shared bounded probe pool
// instead of materialising every pair, so /24 x 1-10000 does not exhaust
// memory. mDNS assets only enrich a target; they never gate the scan.
func scanNetwork(ctx context.Context, discovered []model.Asset, network *net.IPNet, ports []int, timeout time.Duration) ([]model.Asset, error) {
	hosts, err := scan.Hosts(network)
	if err != nil {
		return nil, err
	}
	discoveredByTarget := map[string][]model.Asset{}
	passthrough := make([]model.Asset, 0, 4)
	for _, asset := range discovered {
		if asset.Port == 0 {
			passthrough = appendUniqueAsset(passthrough, asset)
			continue
		}
		key := targetKey(asset.IP, asset.Port)
		discoveredByTarget[key] = appendUniqueAsset(discoveredByTarget[key], asset)
	}

	probed := scan.RunPool(ctx,
		func(ctx context.Context, jobs chan<- model.Asset) {
			for _, host := range hosts {
				for _, port := range ports {
					if ctx.Err() != nil {
						return
					}
					targets, ok := discoveredByTarget[targetKey(host, port)]
					if !ok {
						targets = []model.Asset{{IP: host, Host: host, Port: port, Service: scan.ServiceForPort(port)}}
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
		func(asset *model.Asset) { scan.ProbeAsset(ctx, asset, timeout) },
	)
	return append(passthrough, probed...), nil
}

func targetKey(ip string, port int) string {
	return net.JoinHostPort(ip, strconv.Itoa(port))
}
