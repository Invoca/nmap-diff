package gcloud

import (
	"context"
	"fmt"
	"github.com/port-scanner/pkg/config"
	"github.com/port-scanner/pkg/server"
	"github.com/port-scanner/pkg/wrapper"
	log "github.com/sirupsen/logrus"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	"strconv"
)

type gCloudSvc struct {
	computeService wrapper.GCloudWrapper
}

func Setup(config config.BaseConfig) (*gCloudSvc, error) {
	gCloudWrapper, err := createGCloudInterface(config)
	if err != nil {
		return nil, fmt.Errorf("Setup: Error Creating gCloudSvc Interface %s", err)
	}

	g := gCloudSvc{}
	g.computeService = gCloudWrapper

	return &g, nil
}

func createGCloudInterface(baseConfig config.BaseConfig) (*gCloudWrapper, error) {
	options := option.WithCredentialsFile(baseConfig.GCloudConfig.ServiceAccountPath)

	computeService, err := compute.NewService(context.Background(), options)
	if err != nil {
		return nil, fmt.Errorf("SetupRunner: Error creating compute.Service object %s", err)
	}

	gCloudInterface, err := newCloudWrapper(computeService, baseConfig.GCloudConfig.ProjectName)
	if err != nil {
		return nil, fmt.Errorf("SetupRunner: Error creating gCloudSvc wrapper %s", err)
	}
	return gCloudInterface, nil
}

func (g *gCloudSvc) Instances(serversMap map[string]server.Server) error {
	regionNames, err := g.computeService.Zones()
	if err != nil {
		return fmt.Errorf("Instances: Error Getting zones %s", err)
	}

	for _, region := range regionNames {
		instances, err := g.computeService.InstancesInRegion(region)
		if err != nil {
			return fmt.Errorf("Instances: Error listing Instances %s", err)
		}
		log.Debug(len(instances))

		for _, instance := range instances {
			newServer := server.Server{}
			newServer.Tags = make(map[string]string)
			newServer.Name = instance.Name
			newServer.Address = instance.NetworkInterfaces[0].AccessConfigs[0].NatIP
			for index, key := range instance.Tags.Items {
				newServer.Tags[strconv.FormatInt(int64(index), 10)] = key
			}
			serversMap[newServer.Address] = newServer
		}
	}
	return nil
}

type gCloudWrapper struct {
	computeService *compute.Service
	project        string
}

func newCloudWrapper(computeService *compute.Service, project string) (*gCloudWrapper, error) {
	if computeService == nil {
		return nil, fmt.Errorf("computeService: computeService cannot be nil")
	}

	if project == "" {
		return nil, fmt.Errorf("computeService: project cannot be empty")
	}

	return &gCloudWrapper{computeService: computeService, project: project}, nil
}

func (g *gCloudWrapper) Zones() ([]string, error) {
	var regionNames []string
	if g.computeService == nil {
		return nil, fmt.Errorf("Zones: computeService cannot be nil")
	}

	listRegionsCall := g.computeService.Zones.List(g.project)
	regions, err := listRegionsCall.Do()

	if err != nil {
		return nil, fmt.Errorf("Zones: Error Getting zones %s", err)
	}
	if regions == nil {
		return nil, fmt.Errorf("Zones: No Zones Available")
	}

	for _, region := range regions.Items {
		regionNames = append(regionNames, region.Name)
	}

	return regionNames, nil
}

func (g *gCloudWrapper) InstancesInRegion(region string) ([]compute.Instance, error) {
	var instances []compute.Instance

	if region == "" {
		return nil, fmt.Errorf("InstancesInRegion: region cannot be nil")
	}
	if g.computeService == nil {
		return nil, fmt.Errorf("InstancesInRegion: computeService cannot be nil")
	}

	listInstancesCall := g.computeService.Instances.List(g.project, region)
	gcloudInstances, err := listInstancesCall.Do()
	if err != nil {
		return nil, fmt.Errorf("InstancesIPsInRegion: Error getting instances %s", err)
	}

	for _, computeInstance := range gcloudInstances.Items {
		instances = append(instances, *computeInstance)
	}
	return instances, nil
}
