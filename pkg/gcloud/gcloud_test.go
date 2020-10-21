package gcloud

import (
	"fmt"
	"github.com/Invoca/nmap-diff/pkg/mocks"
	"github.com/Invoca/nmap-diff/pkg/server"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/api/compute/v1"
	"strconv"
	"testing"
)

type getInstancesTestCase struct {
	desc        string
	setup       func()
	shouldError bool
}

func TestGetInstances(t *testing.T) {

	serviceMock := mocks.GCloudMock{}
	gcloud := gCloudSvc{}
	gcloud.computeService = &serviceMock
	serversMap := make(map[string]server.Server)

	regions := []string{
		"Never",
		"Eat",
		"Soggy",
		"Waffles",
	}

	resp := []compute.Instance{
		{
			Name: "Instance 1",
			NetworkInterfaces: []*compute.NetworkInterface{
				{
					AccessConfigs: []*compute.AccessConfig{
						{
							NatIP: "1.1.1.1",
						},
					},
				},
			},
			Tags: &compute.Tags{
				Items: []string{
					"Tag1",
				},
			},
		},
		{
			Name: "Instance 2",
			NetworkInterfaces: []*compute.NetworkInterface{
				{
					AccessConfigs: []*compute.AccessConfig{
						{
							NatIP: "2.2.2.2",
						},
					},
				},
			},
			Tags: &compute.Tags{
				Items: []string{
					"Tag2",
				},
			},
		},
	}

	testCases := []getInstancesTestCase{
		{
			desc: "Able to get all instances without error",
			setup: func() {
				serviceMock.Reset()
				serviceMock.On("Zones", mock.Anything).Return(regions, nil)
				serviceMock.On("InstancesInRegion", mock.Anything).Return(resp, nil)
			},
			shouldError: false,
		},
		{
			desc: "Error returned by region retrieval",
			setup: func() {
				serviceMock.Reset()
				serviceMock.On("Zones", mock.Anything).Return(regions, fmt.Errorf("error"))
				serviceMock.On("InstancesInRegion", mock.Anything).Return(nil, nil)
			},
			shouldError: true,
		},
		{
			desc: "Error returned by instance retrieval",
			setup: func() {
				serviceMock.Reset()
				serviceMock.On("Zones", mock.Anything).Return(regions, nil)
				serviceMock.On("InstancesInRegion", mock.Anything).Return(resp, fmt.Errorf("error"))
			},
			shouldError: true,
		},
	}

	for index, testCase := range testCases {
		log.WithFields(log.Fields{
			"desc":        testCase.desc,
			"shouldError": testCase.shouldError,
		}).Debug("Starting testCase " + strconv.Itoa(index))

		testCase.setup()

		err := gcloud.Instances(serversMap)

		if testCase.shouldError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}
