package mocks

import "github.com/Invoca/nmap-diff/pkg/server"

type SlackInterfaceMock struct {
	ResettableMock
}

func (s *SlackInterfaceMock) PrintOpenedPorts(host server.Server, ports []uint16) error {
	args := s.Called(nil)
	if args.Get(0) == nil {
		return args.Error(0)
	} else {
		return args.Error(0)
	}
}

