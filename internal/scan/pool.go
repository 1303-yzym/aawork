package scan

import (
	"context"
	"sync"
	"time"

	"github.com/1303-yzym/mdns-go/internal/model"
)

const probeWorkers = 128

// RunPool feeds targets produced by next into a bounded worker pool and
// returns the probed assets that are worth reporting.
func RunPool(ctx context.Context, next func(context.Context, chan<- model.Asset), probe func(*model.Asset)) []model.Asset {
	jobs := make(chan model.Asset)
	results := make(chan model.Asset)
	var wg sync.WaitGroup
	for i := 0; i < probeWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for asset := range jobs {
				probe(&asset)
				if !keepProbedAsset(asset) {
					continue
				}
				select {
				case results <- asset:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		next(ctx, jobs)
	}()
	go func() {
		wg.Wait()
		close(results)
	}()
	var assets []model.Asset
	for asset := range results {
		assets = append(assets, asset)
	}
	return assets
}

// ProbeAssets probes an in-memory batch and returns the reportable results.
func ProbeAssets(ctx context.Context, assets []model.Asset, timeout time.Duration) []model.Asset {
	if len(assets) == 0 {
		return nil
	}
	return RunPool(ctx,
		func(ctx context.Context, jobs chan<- model.Asset) {
			for i := range assets {
				select {
				case jobs <- assets[i]:
				case <-ctx.Done():
					return
				}
			}
		},
		func(asset *model.Asset) { ProbeAsset(ctx, asset, timeout) },
	)
}

func keepProbedAsset(asset model.Asset) bool {
	return asset.Discovered || (asset.Probe != nil && asset.Probe.Success)
}
