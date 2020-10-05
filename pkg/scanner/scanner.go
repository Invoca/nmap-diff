package scanner

import (
	"context"
	"fmt"
	"github.com/Ullaakut/nmap"
	"github.com/port-scanner/pkg/wrapper"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"time"
)

type portMap map[uint16]bool

type scanParser struct {
	currentInstances    map[string]portMap
	previousInstances   map[string]portMap
	newInstancesExposed map[string]portMap
	instancesRemoved    map[string]portMap
}

func newParser(previousInstances map[string]portMap, currentInstances map[string]portMap) *scanParser {
	p := &scanParser{}
	p.previousInstances = previousInstances
	p.currentInstances = currentInstances
	p.newInstancesExposed = make(map[string]portMap)
	p.instancesRemoved = make(map[string]portMap)
	return p
}

func (p *scanParser) ParseScans() (map[string]portMap, map[string]portMap) {
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
	portsAdded := make(portMap)
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
	portsRemoved := make(portMap)
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
	ipAddresses       []string
	nmapClientSvc     wrapper.NmapClientWrapper
	CurrentScan       []byte
	currentInstances  map[string]portMap
	previousInstances map[string]portMap
	scanParser        *scanParser
}

func New(ipAddresses []string) (*nmapStruct, error) {
	n := &nmapStruct{}
	if ipAddresses == nil {
		return n, fmt.Errorf("New: Error Initializing nmapStruct interface. ipAddresses nil. ")
	}

	n.ctx, n.cancel = context.WithTimeout(context.Background(), 5*time.Hour)
	n.ipAddresses = ipAddresses
	n.currentInstances = make(map[string]portMap)
	n.previousInstances = make(map[string]portMap)
	n.scanParser = newParser(n.previousInstances, n.currentInstances)
	return n, nil
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

		hostMap := make(portMap)

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

//TODO: Put into content of  this function into SetupNmap
func (n *nmapStruct) SetupScan() error {
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(n.ipAddresses...),
		nmap.WithContext(n.ctx),
		nmap.WithSkipHostDiscovery(),
	)

	if err != nil {
		return fmt.Errorf("unable to create scanner scanner: %v", err)
	}
	n.nmapClientSvc = scanner
	return nil
}

func (n *nmapStruct) StartScan() error {
	newInstancesExposed := make(map[string]portMap)
	defer n.cancel()

	if n.nmapClientSvc == nil {
		return fmt.Errorf("StartScan: nmapClientSvc is nil")
	}

	log.Debug("Starting Scan")
	result, warnings, err := n.nmapClientSvc.Run()

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

	n.CurrentScan = currentScan

	// Add all ports that are open
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}
		hostEntry := make(portMap)

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
func (n *nmapStruct) DiffScans() (map[string]portMap, map[string]portMap) {
	log.WithFields(log.Fields{
		"previousInstanceCount": len(n.previousInstances),
		"currentInstanceCount":  len(n.currentInstances),
	}).Debug("Parsing Scan")
	return n.scanParser.ParseScans()
}
