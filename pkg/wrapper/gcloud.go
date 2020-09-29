package wrapper

import "google.golang.org/api/compute/v1"

type GCloudWrapper interface {
	Zones() ([]string, error)
	InstancesInRegion(region string) ([]compute.Instance, error)
}
