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

type Nmap struct {
	CurrentExposed  map[string] map[uint16] bool
	PreviousExposed map[string] map[uint16] bool
	ctx             context.Context
	cancel          context.CancelFunc
	NewExposed  	map[string] map[uint16] bool
	RemovedExposed  map[string] map[uint16] bool
	ipAddresses 	[]string
	nmapClientSvc	wrapper.NmapClientWrapper
	CurrentScan     []byte
}

func SetupNmap(ipAddresses []string) (Nmap, error) {
	n := Nmap{}
	if ipAddresses == nil {
		return n, fmt.Errorf("Error Initializing Nmap interface. ipAddresses nil. ")
	}

	n.PreviousExposed = make(map[string] map[uint16] bool)
	n.CurrentExposed =  make(map[string] map[uint16] bool)
	n.NewExposed = make(map[string] map[uint16] bool)
	n.RemovedExposed = make(map[string] map[uint16] bool)
	n.ctx, n.cancel = context.WithTimeout(context.Background(), 5*time.Hour)
	n.ipAddresses = ipAddresses
	return n, nil
}

func (n *Nmap) ParsePreviousScan(scanBytes []byte) error {
	previousResult, err := nmap.Parse(scanBytes)
	if err != nil {
		return fmt.Errorf("error parsing buffer %s", err)
	}

	for _, host := range previousResult.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		hostMap := make(map[uint16]bool)


		fmt.Printf("Host %q:\n", host.Addresses[0])

		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
			hostMap[port.ID] = true
		}
		n.PreviousExposed[host.Addresses[0].Addr] = hostMap
	}
	return nil
}

func (n *Nmap) SetupScan() error {
	scanner, err := nmap.NewScanner(
				nmap.WithTargets(n.ipAddresses...),
				nmap.WithContext(n.ctx),
				nmap.WithSkipHostDiscovery(),
			)

	if err != nil {
		log.Fatalf("unable to create scanner scanner: %v", err)
	}
	n.nmapClientSvc = scanner
	return nil
}

func (n *Nmap) StartScan() error {
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

	n.CurrentScan =  currentScan

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}
		hostEntry := make(map[uint16]bool)

		for _, port := range host.Ports {
			hostEntry[port.ID] = true
		}
		n.CurrentExposed[host.Addresses[0].Addr] = hostEntry
	}
	return nil
}

//TODO: Find a different way. I don't like this.
func (n *Nmap) DiffScans() {
	for host, ports := range n.CurrentExposed {
		if n.PreviousExposed[host] == nil {
			n.NewExposed[host] = ports
		} else if n.PreviousExposed[host] != nil {
			portsAdded := make(map[uint16]bool)
			portsRemoved := make(map[uint16]bool)
			for port, _ := range ports {
				if n.PreviousExposed[host][port] == false {
					portsAdded[port] = true
				}
			}
			for port, _ := range n.PreviousExposed[host] {
				if n.CurrentExposed[host][port] == false {
					portsRemoved[port] = true
				}
			}
			if len(portsAdded) > 0 {
				n.NewExposed[host] = portsAdded
			}
			if len(portsRemoved) > 0 {
				n.RemovedExposed[host] = portsRemoved
			}
		}
	}

	for host, ports := range n.PreviousExposed {
		if n.CurrentExposed[host] == nil {
			n.RemovedExposed[host] = ports
		}
	}
}
