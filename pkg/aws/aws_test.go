package aws

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/port-scanner/pkg/mocks"
	"github.com/port-scanner/pkg/server"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"io/ioutil"
	"strconv"
	"strings"
	"testing"
)

type awsTestCase struct {
	desc        string
	setup       func()
	shouldError bool
}

func TestGetAWSInstances(t *testing.T) {

	log.SetLevel(log.DebugLevel)

	mockEc2 := &mocks.MockEC2API{}
	serversMap := make(map[string]server.Server)

	runningCode := int64(16)
	runningState := ec2.InstanceState{Code: &runningCode}

	resp := ec2.DescribeInstancesOutput{
		Reservations: []*ec2.Reservation{
			{
				ReservationId: aws.String("123ABC"),
				Instances: []*ec2.Instance{
					{
						InstanceId:       aws.String("Instance 1"),
						PublicIpAddress:  aws.String("6.6.6.6"),
						PrivateIpAddress: aws.String("1.1.1.1"),
						State:            &runningState,
					},
					{
						InstanceId:       aws.String("Instance 2"),
						PublicIpAddress:  aws.String("6.6.6.7"),
						PrivateIpAddress: aws.String("2.2.2.2"),
						State:            &runningState,
					},
					{
						InstanceId:       aws.String("Instance 3"),
						PublicIpAddress:  aws.String("6.6.6.8"),
						PrivateIpAddress: aws.String("3.3.3.3"),
						State:            &runningState,
					},
				},
			},
		},
	}

	testCases := []awsTestCase{
		{
			desc: "successful ip retrieval",
			setup: func() {
				mockEc2.Reset()
				mockEc2.On("DescribeInstances", mock.AnythingOfType("*ec2.DescribeInstancesInput")).Return(&resp, nil)
			},
			shouldError: false,
		},
		{
			desc: "error returned by ip retrieval",
			setup: func() {
				mockEc2.Reset()
				mockEc2.On("DescribeInstances", mock.AnythingOfType("*ec2.DescribeInstancesInput")).Return(&resp, fmt.Errorf("error"))
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

		ec2api := awsSvc{}
		ec2api.ec2svc = mockEc2

		err := ec2api.getInstancesInRegion(mockEc2, serversMap)

		mockEc2.AssertExpectations(t)

		if testCase.shouldError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}

	t.Logf("TestGetAWSInstances: pass nil object to getInstances")

	ec2api := awsSvc{}
	err := ec2api.getInstancesInRegion(nil, serversMap)
	assert.Error(t, err)

}

func TestGetAWSRegions(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	regions := []string{
		"Never",
		"Eat",
		"Soggy",
		"Waffles",
	}

	mockEc2 := &mocks.MockEC2API{}

	resp := ec2.DescribeRegionsOutput{
		Regions: []*ec2.Region{
			{
				RegionName: &regions[0],
			},
			{
				RegionName: &regions[1],
			},
			{
				RegionName: &regions[2],
			},
			{
				RegionName: &regions[3],
			},
		},
	}

	testCases := []awsTestCase{
		{
			desc: "successful region retrieval",
			setup: func() {
				mockEc2.Reset()
				mockEc2.On("DescribeRegions", mock.AnythingOfType("*ec2.DescribeRegionsInput")).Return(&resp, nil)
			},
			shouldError: false,
		},
		{
			desc: "error returned by region retrieval",
			setup: func() {
				mockEc2.Reset()
				mockEc2.On("DescribeRegions", mock.AnythingOfType("*ec2.DescribeRegionsInput")).Return(&resp, fmt.Errorf("error"))
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

		ec2api := awsSvc{}
		ec2api.ec2svc = mockEc2

		err := ec2api.getRegions()

		mockEc2.AssertExpectations(t)

		if testCase.shouldError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}

	t.Logf("TestGetAWSRegions: pass nil object to getRegions")

	ec2api := awsSvc{}
	err := ec2api.getRegions()
	assert.Error(t, err)

}

func TestGetS3Object(t *testing.T) {
	body := ioutil.NopCloser(strings.NewReader("I am string"))

	returnValue := s3.GetObjectOutput{
		Body: body,
	}

	mockS3 := &mocks.MockS3API{}

	testCases := []awsTestCase{
		{
			desc: "successful object retrieval",
			setup: func() {
				mockS3.Reset()
				mockS3.On("GetObject", mock.AnythingOfType("*s3.GetObjectInput")).Return(&returnValue, nil)
			},
			shouldError: false,
		},
		{
			desc: "error returned by object retrieval",
			setup: func() {
				mockS3.Reset()
				mockS3.On("GetObject", mock.AnythingOfType("*s3.GetObjectInput")).Return(&returnValue, fmt.Errorf("error"))
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

		ec2api := awsSvc{}
		ec2api.s3svc = mockS3

		_, err := ec2api.GetFileFromS3("file")

		mockS3.AssertExpectations(t)

		if testCase.shouldError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}
