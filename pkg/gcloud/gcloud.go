package gcloud

import (
	"fmt"
	"github.com/port-scanner/pkg/wrapper"
	"github.com/port-scanner/pkg/config"
	"github.com/port-scanner/pkg/server"
	log "github.com/sirupsen/logrus"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	"strconv"
	"context"
)

type GCloud struct {
	IpAddresses    	[]string
	ServersMap		map[string] server.Server
	computeService wrapper.GCloudWrapper
}

func (g *GCloud) Setup(config config.BaseConfig) error {
	GCloudwrapper, err := createGCloudInterface(config)
	if err != nil {
		return fmt.Errorf("Setup: Error Creating GCloud Interface")
	}

	g.computeService = GCloudwrapper
	g.ServersMap = make(map[string] server.Server)
	return nil
}

func createGCloudInterface(baseConfig config.BaseConfig) (*GCloudWrapper, error) {
	options := option.WithCredentialsFile(baseConfig.GCloudConfig.ServiceAccountPath)

	computeService, err := compute.NewService(context.Background(), options)
	if err != nil {
		return nil, fmt.Errorf("SetupRunner: Error getting compute.Service object %s", err)
	}

	gCloudInterface, err := newCloudWrapper(computeService, baseConfig.GCloudConfig.ProjectName)
	if err != nil {
		return nil, fmt.Errorf("SetupRunner: Error creating GCloud wrapper %s", err)
	}
	return gCloudInterface, nil
}

func (g *GCloud) Instances() error {
	regionNames, err := g.computeService.Zones()
	if err != nil {
		return fmt.Errorf("GetInstances: Error Getting zones %s", err)
	}

	for _, region := range regionNames {
		instances, err := g.computeService.InstancesInRegion(region)
		if err != nil {
			return fmt.Errorf("GetInstances: Error listing Instances %s", err)
		}
		log.Debug(len(instances))

		for _, instance := range instances {
			newServer := server.Server{}
			newServer.Tags = make(map[string] string)
			newServer.Name = instance.Name
			newServer.Address = instance.NetworkInterfaces[0].AccessConfigs[0].NatIP
			for index, key := range instance.Tags.Items {
				newServer.Tags[strconv.FormatInt(int64(index), 10)] = key
			}
			g.IpAddresses = append(g.IpAddresses, newServer.Address)
			g.ServersMap[newServer.Address] = newServer
		}
	}
	return nil
}

type GCloudWrapper struct {
	computeService *compute.Service
	project        string
}

func newCloudWrapper(computeService *compute.Service, project string) (*GCloudWrapper, error) {
	if computeService == nil {
		return nil, fmt.Errorf("computeService: computeService cannot be nil")
	}

	if project == "" {
		return nil, fmt.Errorf("computeService: project cannot be empty")
	}

	return &GCloudWrapper{computeService: computeService, project: project}, nil
}

func (g *GCloudWrapper) Zones() ([]string, error) {
	var regionNames []string
	listRegions := g.computeService.Zones.List(g.project)
	regions, err := listRegions.Do()

	if regions == nil {
		return nil, fmt.Errorf("Zones: No Zones Available")
	}

	if err != nil {
		return nil, fmt.Errorf("Zones: Error Getting zones %s", err)
	}

	for _, region := range regions.Items {
		regionNames = append(regionNames, region.Name)
	}

	return regionNames, nil
}

func (g *GCloudWrapper) InstancesInRegion(region string) ([]compute.Instance, error) {
	if region == "" {
		return nil, fmt.Errorf("InstancesIPsInRegion: region cannot be nil")
	}

	var instances []compute.Instance

	listInstances := g.computeService.Instances.List(g.project, region)

	resList, err := listInstances.Do()

	if err != nil {
		return nil, fmt.Errorf("InstancesIPsInRegion: Error getting instances %s", err)
	}

	for _, resItem := range resList.Items {
		instances = append(instances, *resItem)
	}
	return instances, nil
}
