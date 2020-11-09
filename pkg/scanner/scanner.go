package scanner

import (
	"context"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/Invoca/nmap-diff/pkg/wrapper"
	"github.com/Ullaakut/nmap"
	log "github.com/sirupsen/logrus"
)

type scanParser struct {
	currentInstances    map[string]wrapper.PortMap
	previousInstances   map[string]wrapper.PortMap
	newInstancesExposed map[string]wrapper.PortMap
	instancesRemoved    map[string]wrapper.PortMap
}

func newParser(previousInstances map[string]wrapper.PortMap, currentInstances map[string]wrapper.PortMap) *scanParser {
	p := &scanParser{}
	p.previousInstances = previousInstances
	p.currentInstances = currentInstances
	p.newInstancesExposed = make(map[string]wrapper.PortMap)
	p.instancesRemoved = make(map[string]wrapper.PortMap)
	return p
}

func (p *scanParser) ParseScans() (map[string]wrapper.PortMap, map[string]wrapper.PortMap) {
	// Iterate through all instances found in  the current scan.
	for host, ports := range p.currentInstances {
		// Check if the instance was found in a previous scan. If that is the case, add all ports exposed on this
		// instance since they were not found on the last scan. Otherwise compare the ports opened on the previous scan
		// with the current scan.
		if p.previousInstances[host] == nil {
			p.newInstancesExposed[host] = ports
		} else {
			p.checkPortsAdded(host)
			p.checkPortsRemoved(host)
		}
	}

	// Go through all of the instances of the previous scan and check if any were present in the last scan but not this
	// one.
	for host, ports := range p.previousInstances {
		if p.currentInstances[host] == nil {
			p.instancesRemoved[host] = ports
		}
	}
	return p.newInstancesExposed, p.instancesRemoved
}

// checkPortsAdded goes through all ports found on the current scan and checks to see if they were present on the last
// scan.
func (p *scanParser) checkPortsAdded(host string) {
	portsAdded := make(wrapper.PortMap)
	for port, _ := range p.currentInstances[host] {
		if p.previousInstances[host][port] == false {
			portsAdded[port] = true
		}
	}
	// Check if any ports were added or removed to the current instance.
	if len(portsAdded) > 0 {
		p.instancesRemoved[host] = portsAdded
	}
}

// checkPortsRemoved goes through all of the opened ports on the last scan of the host and checks if they were closed on
// the last scan.
func (p *scanParser) checkPortsRemoved(host string) {
	portsRemoved := make(wrapper.PortMap)
	for port, _ := range p.previousInstances[host] {
		if p.currentInstances[host][port] == false {
			portsRemoved[port] = true
		}
	}
	// Check if any ports were added or removed to the current instance.
	if len(portsRemoved) > 0 {
		p.instancesRemoved[host] = portsRemoved
	}
}

type nmapWrapper struct{}

func (n *nmapWrapper) Run(ipAddresses []string, ctx context.Context) (result *nmap.Run, warnings []string, err error) {
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(ipAddresses...),
		nmap.WithContext(ctx),
		nmap.WithSkipHostDiscovery(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create scanner scanner: %v", err)
	}
	return scanner.Run()
}

type NmapSvc interface {
	ParsePreviousScan(scanBytes []byte) (map[string]map[uint16]bool, error)
	SetupScan() error
	SetupNmap(ipAddresses []string) (nmapStruct, error)
	StartScan() (map[string]map[uint16]bool, error)
	DiffScans(instancesFromCurrentScan map[string]map[uint16]bool, instancesFromPreviousScan map[string]map[uint16]bool) (map[string]map[uint16]bool, map[string]map[uint16]bool, error)
}

type nmapStruct struct {
	ctx               context.Context
	cancel            context.CancelFunc
	nmapClientSvc     wrapper.NmapClientWrapper
	currentInstances  map[string]wrapper.PortMap
	previousInstances map[string]wrapper.PortMap
	scanParser        *scanParser
	currentScanSlice  []byte
}

func New() *nmapStruct {
	n := &nmapStruct{}
	n.ctx, n.cancel = context.WithTimeout(context.Background(), 5*time.Hour)
	n.nmapClientSvc = &nmapWrapper{}
	n.currentInstances = make(map[string]wrapper.PortMap)
	n.previousInstances = make(map[string]wrapper.PortMap)
	n.scanParser = newParser(n.previousInstances, n.currentInstances)
	return n
}

func (n *nmapStruct) ParsePreviousScan(scanBytes []byte) error {
	previousResult, err := nmap.Parse(scanBytes)
	if err != nil {
		return fmt.Errorf("error parsing buffer %s", err)
	}

	for _, host := range previousResult.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		hostMap := make(wrapper.PortMap)

		fmt.Printf("Host %q:\n", host.Addresses[0])

		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
			if port.State.String() == "open" {
				hostMap[port.ID] = true
			}
		}
		n.previousInstances[host.Addresses[0].Addr] = hostMap
	}
	return nil
}

func (n *nmapStruct) CurrentScanResults() ([]byte, error) {
	if n.currentScanSlice == nil {
		return nil, fmt.Errorf("CurrentScanResults: currentScanSlice is nil")
	}
	return n.currentScanSlice, nil
}

func (n *nmapStruct) StartScan(ipAddresses []string) error {
	newInstancesExposed := make(map[string]wrapper.PortMap)
	defer n.cancel()

	if n.nmapClientSvc == nil {
		return fmt.Errorf("StartScan: nmapClientSvc is nil")
	}

	log.Debug("Starting Scan")
	result, warnings, err := n.nmapClientSvc.Run(ipAddresses, n.ctx)

	if err != nil {
		return fmt.Errorf("StartScan: unable to run nmap scan: %s", err)
	}

	if warnings != nil {
		log.Warn("Warnings: \n", warnings)
	}

	currentScan, err := ioutil.ReadAll(result.ToReader())
	if err != nil {
		return fmt.Errorf("StartScan: Error reading previous scan %s", err)
	}

	n.currentScanSlice = currentScan

	// Add all ports that are open
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}
		hostEntry := make(wrapper.PortMap)

		for _, port := range host.Ports {
			if port.State.String() == "open" {
				hostEntry[port.ID] = true
			}
		}
		newInstancesExposed[host.Addresses[0].Addr] = hostEntry
	}
	n.currentInstances = newInstancesExposed
	return nil
}

// DiffScans takes a map of instances from a past scan and a current one. The function returns instances with ports
// that are were opened and closed. It does this by comparing the two maps that are passed to the function and iterating
// through each.
func (n *nmapStruct) DiffScans() (map[string]wrapper.PortMap, map[string]wrapper.PortMap) {
	log.WithFields(log.Fields{
		"previousInstanceCount": len(n.previousInstances),
		"currentInstanceCount":  len(n.currentInstances),
	}).Debug("Parsing Scan")
	return n.scanParser.ParseScans()
}
