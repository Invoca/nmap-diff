package mocks

import (
	"github.com/Ullaakut/nmap"
	"github.com/port-scanner/pkg/wrapper"
)

type ScannerServiceMock interface {
	wrapper.NmapClientWrapper
}

type ScannerMock struct {
	ResettableMock
}

func (g *ScannerMock) Run() (result *nmap.Run, warnings []string, err error) {
	args := g.Called(nil)
	if args.Get(0) == nil {
		return nil, []string{}, args.Error(1)
	} else if args.Get(1) == nil {
		return nil, []string{}, args.Error(1)
	} else {
		return args.Get(0).(*nmap.Run), args.Get(1).([]string),args.Error(2)
	}
}
