package runner

import (
	"fmt"
	"github.com/Invoca/nmap-diff/pkg/wrapper"
	"strconv"
	"testing"

	"github.com/Invoca/nmap-diff/pkg/config"
	"github.com/Invoca/nmap-diff/pkg/mocks"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

	testRunner := Runner{
		awsSvc:       &awsMock,
		gCloudSvc:    &gcloudMock,
		slackSvc:     &slackMock,
		nmapSvc:      &nmapMock,
		enableGCloud: true,
		enableAWS:    true,
	}

	testCases := []runnerTestCase{
		{
			desc: "Run without error if other packages return successfully",
			setup: func() {
				currentScanSlice := []byte{0x00}
				instancesExposed := make(map[string]wrapper.PortMap)
				nmapMock.Reset()
				awsMock.Reset()
				gcloudMock.Reset()
				slackMock.Reset()
				awsMock.On("Instances", mock.Anything).Return(nil)
				gcloudMock.On("Instances", mock.Anything).Return(nil)
				awsMock.On("GetFileFromS3", mock.Anything).Return(nil, nil)
				nmapMock.On("ParsePreviousScan", mock.Anything).Return(nil)
				nmapMock.On("StartScan", mock.Anything).Return(nil)
				nmapMock.On("DiffScans", mock.Anything).Return(instancesExposed)
				nmapMock.On("CurrentScanResults", mock.Anything).Return(currentScanSlice, nil)
				awsMock.On("UploadObjectToS3", mock.Anything).Return(nil)
				slackMock.On("PrintOpenedPorts", mock.Anything).Return(nil)
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
				nmapMock.Reset()
				awsMock.Reset()
				gcloudMock.Reset()
				slackMock.Reset()
				awsMock.On("Instances", mock.Anything).Return(nil)
				gcloudMock.On("Instances", mock.Anything).Return(nil)
				awsMock.On("GetFileFromS3", mock.Anything).Return(nil, nil)
				nmapMock.On("ParsePreviousScan", mock.Anything).Return(fmt.Errorf("Error"))
			},
			shouldError: true,
		},
		{
			desc: "Error if the scan was not able to be started",
			setup: func() {
				nmapMock.Reset()
				awsMock.Reset()
				gcloudMock.Reset()
				slackMock.Reset()
				awsMock.On("Instances", mock.Anything).Return(nil)
				gcloudMock.On("Instances", mock.Anything).Return(nil)
				awsMock.On("GetFileFromS3", mock.Anything).Return(nil, nil)
				nmapMock.On("ParsePreviousScan", mock.Anything).Return(nil)
				nmapMock.On("StartScan", mock.Anything).Return(fmt.Errorf("Error"))
			},
			shouldError: true,
		},
		{
			desc: "Error if the byte slice of the current scan is not able to be retrieved",
			setup: func() {
				currentScanSlice := []byte{0x00}
				instancesExposed := make(map[string]wrapper.PortMap)
				nmapMock.Reset()
				awsMock.Reset()
				gcloudMock.Reset()
				slackMock.Reset()
				awsMock.On("Instances", mock.Anything).Return(nil)
				gcloudMock.On("Instances", mock.Anything).Return(nil)
				awsMock.On("GetFileFromS3", mock.Anything).Return(nil, nil)
				nmapMock.On("ParsePreviousScan", mock.Anything).Return(nil)
				nmapMock.On("StartScan", mock.Anything).Return(nil)
				nmapMock.On("DiffScans", mock.Anything).Return(instancesExposed)
				nmapMock.On("CurrentScanResults", mock.Anything).Return(currentScanSlice, fmt.Errorf("Error"))
			},
			shouldError: true,
		},
		{
			desc: "Error if the current report is not able to be uploaded to S3",
			setup: func() {
				currentScanSlice := []byte{0x00}
				instancesExposed := make(map[string]wrapper.PortMap)
				nmapMock.Reset()
				awsMock.Reset()
				gcloudMock.Reset()
				slackMock.Reset()
				awsMock.On("Instances", mock.Anything).Return(nil)
				gcloudMock.On("Instances", mock.Anything).Return(nil)
				awsMock.On("GetFileFromS3", mock.Anything).Return(nil, nil)
				nmapMock.On("ParsePreviousScan", mock.Anything).Return(nil)
				nmapMock.On("StartScan", mock.Anything).Return(nil)
				nmapMock.On("DiffScans", mock.Anything).Return(instancesExposed)
				nmapMock.On("CurrentScanResults", mock.Anything).Return(currentScanSlice, nil)
				awsMock.On("UploadObjectToS3", mock.Anything).Return(fmt.Errorf("Error"))
			},
			shouldError: true,
		},
		{
			desc: "Error if the opened ports are not able to be posted to slack",
			setup: func() {
				currentScanSlice := []byte{0x00}
				instancesExposed := make(map[string]wrapper.PortMap)
				instancesExposed["1.1.1.1"] = make(wrapper.PortMap)
				instancesExposed["1.1.1.1"][1] = true
				nmapMock.Reset()
				awsMock.Reset()
				gcloudMock.Reset()
				slackMock.Reset()
				awsMock.On("Instances", mock.Anything).Return(nil)
				gcloudMock.On("Instances", mock.Anything).Return(nil)
				awsMock.On("GetFileFromS3", mock.Anything).Return(nil, nil)
				nmapMock.On("ParsePreviousScan", mock.Anything).Return(nil)
				nmapMock.On("StartScan", mock.Anything).Return(nil)
				nmapMock.On("DiffScans", mock.Anything).Return(instancesExposed)
				nmapMock.On("CurrentScanResults", mock.Anything).Return(currentScanSlice, nil)
				awsMock.On("UploadObjectToS3", mock.Anything).Return(nil)
				slackMock.On("PrintOpenedPorts", mock.Anything).Return(fmt.Errorf("Error"))
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
