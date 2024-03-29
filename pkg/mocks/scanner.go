package mocks

import (
	"context"
	"github.com/Invoca/nmap-diff/pkg/wrapper"
	"github.com/Ullaakut/nmap"
	log "github.com/sirupsen/logrus"
)

type ScannerServiceMock interface {
	wrapper.NmapClientWrapper
}

type ScannerMock struct {
	ResettableMock
}

func (s *ScannerMock) Run([]string, context.Context) (*nmap.Run, []string, error) {
	args := s.Called(nil)
	if args.Get(0) == nil {
		return nil, []string{}, args.Error(1)
	} else if args.Get(1) == nil {
		return nil, []string{}, args.Error(1)
	} else {
		return args.Get(0).(*nmap.Run), args.Get(1).([]string), args.Error(2)
	}
}

type NmapScannerMock struct {
	ResettableMock
}

func (n *NmapScannerMock) CurrentScanResults() ([]byte, error) {
	args := n.Called(nil)
	return args.Get(0).([]byte), args.Error(1)
}

func (n *NmapScannerMock) ParsePreviousScan(scanBytes []byte) error {
	log.Debug("ParsePreviousScan Called")
	args := n.Called(nil)
	return args.Error(0)
}

func (n *NmapScannerMock) StartScan(ipAddresses []string) error {
	log.Debug("StartScan Called")
	args := n.Called(nil)
	return args.Error(0)
}

func (n *NmapScannerMock) DiffScans() map[string]wrapper.PortMap {
	args := n.Called(nil)
	if args.Get(0) == nil {
		return nil
	} else {
		return args.Get(0).(map[string]wrapper.PortMap)
	}
}
