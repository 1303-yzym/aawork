package model

import (
	"sort"
	"strings"
)

// referenceServiceOrder keeps text output stable and matches the documented
// example ordering: workstation, http, smb, qdiscover, device-info, afp.
var referenceServiceOrder = []string{
	"workstation", "http", "smb", "qdiscover", "device-info", "afpovertcp",
}

// ServiceRank positions a service in the reference ordering; unknown services
// sort last.
func ServiceRank(service string) int {
	for i, known := range referenceServiceOrder {
		if strings.EqualFold(service, known) {
			return i
		}
	}
	return len(referenceServiceOrder)
}

// SortAssets orders assets by address, then service rank, then port and name.
// A plain port sort would move the portless device-info entry to the top and
// break the reference output.
func SortAssets(assets []Asset) {
	sort.SliceStable(assets, func(i, j int) bool {
		if assets[i].IP != assets[j].IP {
			return assets[i].IP < assets[j].IP
		}
		ri, rj := ServiceRank(assets[i].Service), ServiceRank(assets[j].Service)
		if ri != rj {
			return ri < rj
		}
		if assets[i].Port != assets[j].Port {
			return assets[i].Port < assets[j].Port
		}
		return assets[i].Name < assets[j].Name
	})
}
