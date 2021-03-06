package mocks

import (
	"fmt"
	"github.com/Invoca/nmap-diff/pkg/server"
	"github.com/Invoca/nmap-diff/pkg/wrapper"
	"google.golang.org/api/compute/v1"
)

type GCloudServiceMock interface {
	wrapper.GCloudWrapper
}

type GCloudMock struct {
	ResettableMock
}

func (g *GCloudMock) Zones() ([]string, error) {
	fmt.Println("Zones() Mock")
	args := g.Called(nil)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	} else {
		return args.Get(0).([]string), args.Error(1)
	}
}

func (g *GCloudMock) InstancesInRegion(region string) ([]compute.Instance, error) {
	fmt.Println("InstancesIPsInRegion() Mock")
	args := g.Called(region)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	} else {
		return args.Get(0).([]compute.Instance), args.Error(1)
	}
}

type GCloudInterfaceMock struct {
	ResettableMock
}

func (g *GCloudInterfaceMock) Instances(serversMap map[string]server.Server) error {
	args := g.Called(nil)
	if args.Get(0) == nil {
		return args.Error(0)
	} else {
		return args.Get(0).(error)
	}
}
