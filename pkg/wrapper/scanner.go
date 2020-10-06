package wrapper

import (
	"github.com/Ullaakut/nmap"
	"context"
)

type NmapClientWrapper interface {
	Run([]string, context.Context) (*nmap.Run, []string, error)
}

type NmapSvc interface {
	CurrentScanResults() ([]byte, error)
	ParsePreviousScan([]byte) (map[string]map[uint16]bool, error)
	StartScan([]string) (map[string]map[uint16]bool, error)
	DiffScans(map[string] map[uint16]bool, map[string]map[uint16]bool) (map[string]map[uint16]bool, map[string]map[uint16]bool, error)
}
