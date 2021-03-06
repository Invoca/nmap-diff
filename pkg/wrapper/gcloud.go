package wrapper

import (
	"github.com/Invoca/nmap-diff/pkg/server"
	"google.golang.org/api/compute/v1"
)

type GCloudWrapper interface {
	Zones() ([]string, error)
	InstancesInRegion(region string) ([]compute.Instance, error)
}

type GCloudSvc interface {
	Instances(serversMap map[string]server.Server) error
}
