package discovery

import (
	"github.com/1303-yzym/mdns-go/internal/mdns"
	"github.com/1303-yzym/mdns-go/internal/model"
)

// Replay renders a recorded dataset through the same asset pipeline the live
// scanner uses, so verification does not need real hardware.
func Replay(path string, ports []int) (model.ScanOutput, error) {
	records, err := mdns.LoadPacketFile(path)
	if err != nil {
		return model.ScanOutput{}, err
	}
	responses := []mdns.Result{{Records: records}}
	assets := BuildAssets(responses, ports)
	model.SortAssets(assets)
	return model.ScanOutput{Services: assets, Answers: CollectAnswers(responses)}, nil
}
