package mocks

import (
	"context"
	"github.com/Ullaakut/nmap"
	"github.com/port-scanner/pkg/wrapper"
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

func (n *NmapScannerMock) ParsePreviousScan([]byte) (map[string]map[uint16]bool, error) {
	args := n.Called(nil)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	} else {
		return args.Get(0).(map[string]map[uint16]bool), args.Error(1)
	}
}

func (n *NmapScannerMock) StartScan([]string) (map[string]map[uint16]bool, error) {
	args := n.Called(nil)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	} else {
		return args.Get(0).(map[string]map[uint16]bool), args.Error(1)
	}
}

func (n *NmapScannerMock) DiffScans(map[string] map[uint16]bool, map[string]map[uint16]bool) (map[string]map[uint16]bool, map[string]map[uint16]bool, error) {
	args := n.Called(nil)
	if args.Get(0) == nil {
		return nil, nil, args.Get(0).(error)
	} else if args.Get(1) == nil {
		return nil, nil, args.Get(0).(error)
	} else {
		return args.Get(0).(map[string]map[uint16]bool), args.Get(1).(map[string]map[uint16]bool), args.Error(2)
	}
}