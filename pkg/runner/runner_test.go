package runner

import (
	"fmt"
	"github.com/port-scanner/pkg/config"
	"github.com/port-scanner/pkg/mocks"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"strconv"
	"testing"
)

type runnerTestCase struct {
	desc        string
	setup       func()
	shouldError bool
}

func TestRun(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	configObject := config.BaseConfig{}
	nmapMock := mocks.NmapScannerMock{}
	awsMock := mocks.MockAWSWrapper{}
	gcloudMock := mocks.GCloudInterfaceMock{}
	slackMock := mocks.SlackInterfaceMock{}

	testRunner := runner{
		awsSvc:    &awsMock,
		gCloudSvc: &gcloudMock,
		slackSvc:  &slackMock,
		nmapSvc:   &nmapMock,
	}

	testCases := []runnerTestCase{
		{
			desc: "Run without error if other packages return successfully",
			setup: func() {
				currentScanSlice := make([]byte, 0)
				oldInstances := make(map[string]map[uint16]bool)
				newInstances := make(map[string]map[uint16]bool)
				instancesExposed := make(map[string]map[uint16]bool)
				instancesRemoved := make(map[string]map[uint16]bool)
				nmapMock.Reset()
				awsMock.Reset()
				gcloudMock.Reset()
				slackMock.Reset()
				awsMock.On("Instances", mock.Anything).Return(nil)
				gcloudMock.On("Instances", mock.Anything).Return(nil)
				awsMock.On("GetFileFromS3", mock.Anything).Return(nil, nil)
				nmapMock.On("ParsePreviousScan", mock.Anything).Return(oldInstances, nil)
				nmapMock.On("StartScan", mock.Anything).Return(newInstances, nil)
				nmapMock.On("DiffScans", mock.Anything).Return(instancesExposed, instancesRemoved, nil)
				nmapMock.On("CurrentScanResults", mock.Anything).Return(currentScanSlice, nil)
				awsMock.On("UploadObjectToS3", mock.Anything).Return(nil)
				slackMock.On("PrintOpenedPorts", mock.Anything).Return(nil)
				slackMock.On("PrintClosedPorts", mock.Anything).Return(nil)
			},
			shouldError: false,
		},
		{
			desc: "Error if Instances are not able to fetched from AWS",
			setup: func() {
				nmapMock.Reset()
				awsMock.Reset()
				gcloudMock.Reset()
				slackMock.Reset()
				awsMock.On("Instances", mock.Anything).Return(fmt.Errorf("Error"))
			},
			shouldError: true,
		},
		{
			desc: "Error if Instances are not able to fetched from Google Cloud",
			setup: func() {
				nmapMock.Reset()
				awsMock.Reset()
				gcloudMock.Reset()
				slackMock.Reset()
				awsMock.On("Instances", mock.Anything).Return(nil)
				gcloudMock.On("Instances", mock.Anything).Return(fmt.Errorf("Error"))
			},
			shouldError: true,
		},
		{
			desc: "Error if the previous report was not able to be fetched from S3",
			setup: func() {
				nmapMock.Reset()
				awsMock.Reset()
				gcloudMock.Reset()
				slackMock.Reset()
				awsMock.On("Instances", mock.Anything).Return(nil)
				gcloudMock.On("Instances", mock.Anything).Return(nil)
				awsMock.On("GetFileFromS3", mock.Anything).Return(nil, fmt.Errorf("Error"))
			},
			shouldError: true,
		},
		{
			desc: "Error if the previous report was not able to be parsed",
			setup: func() {
				oldInstances := make(map[string]map[uint16]bool)
				nmapMock.Reset()
				awsMock.Reset()
				gcloudMock.Reset()
				slackMock.Reset()
				awsMock.On("Instances", mock.Anything).Return(nil)
				gcloudMock.On("Instances", mock.Anything).Return(nil)
				awsMock.On("GetFileFromS3", mock.Anything).Return(nil, nil)
				nmapMock.On("ParsePreviousScan", mock.Anything).Return(oldInstances, fmt.Errorf("Error"))
			},
			shouldError: true,
		},
		{
			desc: "Error if the scan was not able to be started",
			setup: func() {
				oldInstances := make(map[string]map[uint16]bool)
				newInstances := make(map[string]map[uint16]bool)
				nmapMock.Reset()
				awsMock.Reset()
				gcloudMock.Reset()
				slackMock.Reset()
				awsMock.On("Instances", mock.Anything).Return(nil)
				gcloudMock.On("Instances", mock.Anything).Return(nil)
				awsMock.On("GetFileFromS3", mock.Anything).Return(nil, nil)
				nmapMock.On("ParsePreviousScan", mock.Anything).Return(oldInstances, nil)
				nmapMock.On("StartScan", mock.Anything).Return(newInstances, fmt.Errorf("Error"))
			},
			shouldError: true,
		},
		{
			desc: "Error if the previous the scan was not able to be compared with the current one",
			setup: func() {
				oldInstances := make(map[string]map[uint16]bool)
				newInstances := make(map[string]map[uint16]bool)
				instancesExposed := make(map[string]map[uint16]bool)
				instancesRemoved := make(map[string]map[uint16]bool)
				nmapMock.Reset()
				awsMock.Reset()
				gcloudMock.Reset()
				slackMock.Reset()
				awsMock.On("Instances", mock.Anything).Return(nil)
				gcloudMock.On("Instances", mock.Anything).Return(nil)
				awsMock.On("GetFileFromS3", mock.Anything).Return(nil, nil)
				nmapMock.On("ParsePreviousScan", mock.Anything).Return(oldInstances, nil)
				nmapMock.On("StartScan", mock.Anything).Return(newInstances, nil)
				nmapMock.On("DiffScans", mock.Anything).Return(instancesExposed, instancesRemoved, fmt.Errorf("Error"))
			},
			shouldError: true,
		},
		{
			desc: "Error if the byte slice of the current scan is not able to be retrieved",
			setup: func() {
				currentScanSlice := make([]byte, 0)
				oldInstances := make(map[string]map[uint16]bool)
				newInstances := make(map[string]map[uint16]bool)
				instancesExposed := make(map[string]map[uint16]bool)
				instancesRemoved := make(map[string]map[uint16]bool)
				nmapMock.Reset()
				awsMock.Reset()
				gcloudMock.Reset()
				slackMock.Reset()
				awsMock.On("Instances", mock.Anything).Return(nil)
				gcloudMock.On("Instances", mock.Anything).Return(nil)
				awsMock.On("GetFileFromS3", mock.Anything).Return(nil, nil)
				nmapMock.On("ParsePreviousScan", mock.Anything).Return(oldInstances, nil)
				nmapMock.On("StartScan", mock.Anything).Return(newInstances, nil)
				nmapMock.On("DiffScans", mock.Anything).Return(instancesExposed, instancesRemoved, nil)
				nmapMock.On("CurrentScanResults", mock.Anything).Return(currentScanSlice, fmt.Errorf("Error"))
			},
			shouldError: true,
		},
		{
			desc: "Error if the current report is not able to be uploaded to S3",
			setup: func() {
				currentScanSlice := make([]byte, 0)
				oldInstances := make(map[string]map[uint16]bool)
				newInstances := make(map[string]map[uint16]bool)
				instancesExposed := make(map[string]map[uint16]bool)
				instancesRemoved := make(map[string]map[uint16]bool)
				nmapMock.Reset()
				awsMock.Reset()
				gcloudMock.Reset()
				slackMock.Reset()
				awsMock.On("Instances", mock.Anything).Return(nil)
				gcloudMock.On("Instances", mock.Anything).Return(nil)
				awsMock.On("GetFileFromS3", mock.Anything).Return(nil, nil)
				nmapMock.On("ParsePreviousScan", mock.Anything).Return(oldInstances, nil)
				nmapMock.On("StartScan", mock.Anything).Return(newInstances, nil)
				nmapMock.On("DiffScans", mock.Anything).Return(instancesExposed, instancesRemoved, nil)
				nmapMock.On("CurrentScanResults", mock.Anything).Return(currentScanSlice, nil)
				awsMock.On("UploadObjectToS3", mock.Anything).Return(fmt.Errorf("Error"))
			},
			shouldError: true,
		},
		{
			desc: "Error if the opened ports are not able to be posted to slack",
			setup: func() {
				currentScanSlice := make([]byte, 0)
				oldInstances := make(map[string]map[uint16]bool)
				newInstances := make(map[string]map[uint16]bool)
				instancesExposed := make(map[string]map[uint16]bool)
				instancesExposed["1.1.1.1"] = make(map[uint16]bool)
				instancesExposed["1.1.1.1"][1] = true
				instancesRemoved := make(map[string]map[uint16]bool)
				nmapMock.Reset()
				awsMock.Reset()
				gcloudMock.Reset()
				slackMock.Reset()
				awsMock.On("Instances", mock.Anything).Return(nil)
				gcloudMock.On("Instances", mock.Anything).Return(nil)
				awsMock.On("GetFileFromS3", mock.Anything).Return(nil, nil)
				nmapMock.On("ParsePreviousScan", mock.Anything).Return(oldInstances, nil)
				nmapMock.On("StartScan", mock.Anything).Return(newInstances, nil)
				nmapMock.On("DiffScans", mock.Anything).Return(instancesExposed, instancesRemoved, nil)
				nmapMock.On("CurrentScanResults", mock.Anything).Return(currentScanSlice, nil)
				awsMock.On("UploadObjectToS3", mock.Anything).Return(nil)
				slackMock.On("PrintOpenedPorts", mock.Anything).Return(fmt.Errorf("Error"))
			},
			shouldError: true,
		},
		{
			desc: "Error if the closed ports are not able to be posted to slack",
			setup: func() {
				currentScanSlice := make([]byte, 0)
				oldInstances := make(map[string]map[uint16]bool)
				newInstances := make(map[string]map[uint16]bool)
				instancesExposed := make(map[string]map[uint16]bool)
				instancesExposed["1.1.1.1"] = make(map[uint16]bool)
				instancesExposed["1.1.1.1"][1] = true
				instancesRemoved := make(map[string]map[uint16]bool)
				instancesRemoved["2.2.2.2"] = make(map[uint16]bool)
				instancesRemoved["2.2.2.2"][1] = true
				nmapMock.Reset()
				awsMock.Reset()
				gcloudMock.Reset()
				slackMock.Reset()
				awsMock.On("Instances", mock.Anything).Return(nil)
				gcloudMock.On("Instances", mock.Anything).Return(nil)
				awsMock.On("GetFileFromS3", mock.Anything).Return(nil, nil)
				nmapMock.On("ParsePreviousScan", mock.Anything).Return(oldInstances, nil)
				nmapMock.On("StartScan", mock.Anything).Return(newInstances, nil)
				nmapMock.On("DiffScans", mock.Anything).Return(instancesExposed, instancesRemoved, nil)
				nmapMock.On("CurrentScanResults", mock.Anything).Return(currentScanSlice, nil)
				awsMock.On("UploadObjectToS3", mock.Anything).Return(nil)
				slackMock.On("PrintOpenedPorts", mock.Anything).Return(nil)
				slackMock.On("PrintClosedPorts", mock.Anything).Return(fmt.Errorf("Error"))
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

		err := testRunner.run(configObject)

		if testCase.shouldError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}
