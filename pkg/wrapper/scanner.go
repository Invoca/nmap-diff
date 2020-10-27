package wrapper

import (
	"context"

	"github.com/Ullaakut/nmap"
)

type NmapClientWrapper interface {
	Run([]string, context.Context) (*nmap.Run, []string, error)
}

type NmapSvc interface {
	CurrentScanResults() ([]byte, error)
	ParsePreviousScan([]byte) error
	StartScan(ipAddresses []string) error
	DiffScans() (map[string]PortMap, map[string]PortMap)
}

type PortMap map[uint16]bool
