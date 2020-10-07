package wrapper

import (
	"context"
<<<<<<< HEAD

=======
>>>>>>> 74163a4... Ran go fmt
	"github.com/Ullaakut/nmap"
)

type NmapClientWrapper interface {
	Run([]string, context.Context) (*nmap.Run, []string, error)
}

type NmapSvc interface {
	CurrentScanResults() ([]byte, error)
<<<<<<< HEAD
	ParsePreviousScan([]byte) error
	StartScan() error
	DiffScans() (map[string]PortMap, map[string]PortMap)
=======
	ParsePreviousScan([]byte) (map[string]map[uint16]bool, error)
	StartScan([]string) (map[string]map[uint16]bool, error)
	DiffScans(map[string]map[uint16]bool, map[string]map[uint16]bool) (map[string]map[uint16]bool, map[string]map[uint16]bool, error)
>>>>>>> 74163a4... Ran go fmt
}

type PortMap map[uint16]bool
