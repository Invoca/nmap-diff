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

type nmapStruct struct {
	ctx           context.Context
	cancel        context.CancelFunc
	ipAddresses   []string
	nmapClientSvc wrapper.NmapClientWrapper
	CurrentScan   []byte
}

func SetupNmap(ipAddresses []string) (nmapStruct, error) {
	n := nmapStruct{}
	if ipAddresses == nil {
		return n, fmt.Errorf("SetupNmap: Error Initializing nmapStruct interface. ipAddresses nil. ")
	}

	n.ctx, n.cancel = context.WithTimeout(context.Background(), 5*time.Hour)
	n.ipAddresses = ipAddresses
	return n, nil
}

func (n *nmapStruct) ParsePreviousScan(scanBytes []byte) (map[string]map[uint16]bool, error) {
	instancesRemoved := make(map[string]map[uint16]bool)
	previousResult, err := nmap.Parse(scanBytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing buffer %s", err)
	}

	for _, host := range previousResult.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		hostMap := make(map[uint16]bool)

		fmt.Printf("Host %q:\n", host.Addresses[0])

		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
			if port.State.String() == "open" {
				hostMap[port.ID] = true
			}
		}
		instancesRemoved[host.Addresses[0].Addr] = hostMap
	}
	return instancesRemoved, nil
}

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

func (n *nmapStruct) StartScan() (map[string]map[uint16]bool, error) {
	newInstancesExposed := make(map[string]map[uint16]bool)
	defer n.cancel()

	if n.nmapClientSvc == nil {
		return nil, fmt.Errorf("StartScan: nmapClientSvc is nil")
	}

	log.Debug("Starting Scan")
	result, warnings, err := n.nmapClientSvc.Run()

	if err != nil {
		return nil, fmt.Errorf("StartScan: unable to run nmap scan: %s", err)
	}

	if warnings != nil {
		log.Warn("Warnings: \n", warnings)
	}

	currentScan, err := ioutil.ReadAll(result.ToReader())
	if err != nil {
		return nil, fmt.Errorf("StartScan: Error reading previous scan %s", err)
	}

	n.CurrentScan = currentScan

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}
		hostEntry := make(map[uint16]bool)

		for _, port := range host.Ports {
			if port.State.String() == "open" {
				hostEntry[port.ID] = true
			}
		}
		newInstancesExposed[host.Addresses[0].Addr] = hostEntry
	}
	return newInstancesExposed, nil
}

//TODO: Find a different way. I don't like this.
func (n *nmapStruct) DiffScans(instancesFromCurrentScan map[string]map[uint16]bool, instancesFromPreviousScan map[string]map[uint16]bool) (map[string]map[uint16]bool, map[string]map[uint16]bool, error) {
	newInstancesExposed := make(map[string]map[uint16]bool)
	instancesRemoved := make(map[string]map[uint16]bool)
	for host, ports := range instancesFromCurrentScan {
		if instancesFromPreviousScan[host] == nil {
			newInstancesExposed[host] = ports
		} else if instancesFromPreviousScan[host] != nil {
			portsAdded := make(map[uint16]bool)
			portsRemoved := make(map[uint16]bool)
			for port, _ := range ports {
				if instancesFromPreviousScan[host][port] == false {
					portsAdded[port] = true
				}
			}
			for port, _ := range instancesFromPreviousScan[host] {
				if instancesFromCurrentScan[host][port] == false {
					portsRemoved[port] = true
				}
			}
			if len(portsAdded) > 0 {
				instancesRemoved[host] = portsAdded
			}
			if len(portsRemoved) > 0 {
				instancesRemoved[host] = portsRemoved
			}
		}
	}

	for host, ports := range instancesFromPreviousScan {
		if instancesFromCurrentScan[host] == nil {
			instancesRemoved[host] = ports
		}
	}
	return newInstancesExposed, instancesRemoved, nil
}
