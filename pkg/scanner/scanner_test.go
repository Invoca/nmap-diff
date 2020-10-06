package scanner

import (
	"fmt"
	"github.com/Ullaakut/nmap"
	"github.com/port-scanner/pkg/mocks"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"io/ioutil"
	"strconv"
	"testing"
)

type scannerParseTestCase struct {
	desc        string
	setup       func() []byte
	shouldError bool
}

type scannerTestCase struct {
	desc        string
	setup       func()
	shouldError bool
}

type scannerDiffTestCase struct {
	desc       string
	setup      func()
	assertions func()
}

func TestParsePreviousScan(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	log.Debug("Starting TestParsePreviousScan")

	ipAddresses := []string{
		"1.1.1.1",
		"2.2.2.2",
	}

	nmapInterface, _ := SetupNmap(ipAddresses)

	testCases := []scannerParseTestCase{
		{
			desc: "Successfully parse buffer of a valid xml output of an nmap scan",
			setup: func() []byte {
				fileContents, err := ioutil.ReadFile("./test_scan.xml")
				fmt.Println("File Size: " + strconv.FormatInt(int64(len(fileContents)), 10))
				if err != nil {
					log.Fatal("Error opening file", err)
				}
				return fileContents
			},
			shouldError: false,
		},
		{
			desc: "Will return an error when an invalid buffer is given",
			setup: func() []byte {
				return []byte("This is not xml")
			},
			shouldError: true,
		},
		{
			desc: "Will return an error when an an empty file is given",
			setup: func() []byte {
				return []byte("")
			},
			shouldError: true,
		},
	}

	for index, testCase := range testCases {
		log.WithFields(log.Fields{
			"desc":        testCase.desc,
			"shouldError": testCase.shouldError,
		}).Debug("Starting testCase " + strconv.Itoa(index))

		fileContentsToTest := testCase.setup()

		_, err := nmapInterface.ParsePreviousScan(fileContentsToTest)

		if testCase.shouldError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestNmapDiffScans(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	firstInstanceName := "Ready Instance 1"
	firstInstancePort := uint16(16)

	secondInstanceName := "Over Port 9000"
	secondInstancePort := uint16(9001)

	thirdInstanceName := "An Instance Of The Impossible"
	thirdInstancePort := uint16(0)

	instancesFromCurrentScan := make(map[string]map[uint16]bool)
	instancesFromPreviousScan := make(map[string]map[uint16]bool)

	newInstancesExposed := make(map[string]map[uint16]bool)
	instancesClosed := make(map[string]map[uint16]bool)

	n, _ := SetupNmap([]string{})

	testCases := []scannerDiffTestCase{
		{
			desc: "Three new instances are found and should be added to NewInstancesExposed",
			setup: func() {
				instancesFromCurrentScan = make(map[string]map[uint16]bool)
				instancesFromPreviousScan = make(map[string]map[uint16]bool)
				instancesClosed = make(map[string]map[uint16]bool)
				newInstancesExposed = make(map[string]map[uint16]bool)
				instancesFromCurrentScan[firstInstanceName] = make(map[uint16]bool)
				instancesFromCurrentScan[secondInstanceName] = make(map[uint16]bool)
				instancesFromCurrentScan[thirdInstanceName] = make(map[uint16]bool)
				instancesFromCurrentScan[firstInstanceName][firstInstancePort] = true
				instancesFromCurrentScan[thirdInstanceName][thirdInstancePort] = true
				instancesFromCurrentScan[secondInstanceName][secondInstancePort] = true
			},
			assertions: func() {
				assert.Equal(t, true, newInstancesExposed[firstInstanceName][firstInstancePort])
				assert.Equal(t, true, newInstancesExposed[secondInstanceName][secondInstancePort])
				assert.Equal(t, true, newInstancesExposed[thirdInstanceName][thirdInstancePort])
			},
		},
		{
			desc: "One new instances was found and an old one was removed",
			setup: func() {
				instancesFromCurrentScan = make(map[string]map[uint16]bool)
				instancesFromPreviousScan = make(map[string]map[uint16]bool)
				instancesClosed = make(map[string]map[uint16]bool)
				newInstancesExposed = make(map[string]map[uint16]bool)
				instancesFromPreviousScan[firstInstanceName] = make(map[uint16]bool)
				instancesFromCurrentScan[secondInstanceName] = make(map[uint16]bool)
				instancesFromPreviousScan[firstInstanceName][firstInstancePort] = true
				instancesFromCurrentScan[secondInstanceName][secondInstancePort] = true
			},
			assertions: func() {
				assert.Equal(t, true, instancesClosed[firstInstanceName][firstInstancePort])
				assert.Equal(t, true, newInstancesExposed[secondInstanceName][secondInstancePort])
			},
		},
		{
			desc: "One new instance was found and nothing was previously exposed",
			setup: func() {
				instancesFromCurrentScan = make(map[string]map[uint16]bool)
				instancesFromPreviousScan = make(map[string]map[uint16]bool)
				instancesClosed = make(map[string]map[uint16]bool)
				newInstancesExposed = make(map[string]map[uint16]bool)
				instancesFromCurrentScan[firstInstanceName] = make(map[uint16]bool)
				instancesFromCurrentScan[firstInstanceName][firstInstancePort] = true
			},
			assertions: func() {
				assert.Equal(t, true, newInstancesExposed[firstInstanceName][firstInstancePort])
			},
		},
		{
			desc: "One instance was previously found and now nothing is exposed",
			setup: func() {
				instancesFromCurrentScan = make(map[string]map[uint16]bool)
				instancesFromPreviousScan = make(map[string]map[uint16]bool)
				instancesClosed = make(map[string]map[uint16]bool)
				newInstancesExposed = make(map[string]map[uint16]bool)
				instancesFromPreviousScan[firstInstanceName] = make(map[uint16]bool)
				instancesFromPreviousScan[firstInstanceName][firstInstancePort] = true
			},
			assertions: func() {
				assert.Equal(t, true, instancesClosed[firstInstanceName][firstInstancePort])
			},
		},
		{
			desc: "Nothing was previously found and now nothing is exposed",
			setup: func() {
				instancesFromCurrentScan = make(map[string]map[uint16]bool)
				instancesFromPreviousScan = make(map[string]map[uint16]bool)
				instancesClosed = make(map[string]map[uint16]bool)
				newInstancesExposed = make(map[string]map[uint16]bool)
			},
			assertions: func() {
				assert.Equal(t, 0, len(newInstancesExposed))
				assert.Equal(t, 0, len(instancesClosed))
			},
		},
	}

	for index, testCase := range testCases {
		log.WithFields(log.Fields{
			"desc": testCase.desc,
		}).Debug("Starting testCase " + strconv.Itoa(index))

		testCase.setup()
		newInstancesExposed, instancesClosed, _ = n.DiffScans(instancesFromCurrentScan, instancesFromPreviousScan)
		testCase.assertions()
	}
}

func TestRunNmapScan(t *testing.T) {
	log.SetLevel(log.DebugLevel)
	serviceMock := mocks.ScannerMock{}
	n, _ := SetupNmap([]string{"1.1.1.1", "2.2.2.2"})
	n.nmapClientSvc = &serviceMock

	result := nmap.Run{Hosts: []nmap.Host{
		{
			Addresses: []nmap.Address{
				{
					Addr: "1.1.1.1",
				},
			},
			Ports: []nmap.Port{
				{
					ID: uint16(1),
				},
			},
		},
		{
			Addresses: []nmap.Address{
				{
					Addr: "0.0.0.0",
				},
			},
			Ports: []nmap.Port{
				{
					ID: uint16(0),
				},
			},
		},
	}}

	testCases := []scannerTestCase{
		{
			desc: "Scan runs without and returns instances",
			setup: func() {
				serviceMock.Reset()
				serviceMock.On("Run", mock.Anything).Return(&result, []string{}, nil)
			},
			shouldError: false,
		},
		{
			desc: "Scan runs without issue but returns no instances",
			setup: func() {
				serviceMock.Reset()
				serviceMock.On("Run", mock.Anything).Return(&nmap.Run{}, []string{}, nil)
			},
			shouldError: false,
		},
		{
			desc: "Scan runs without issue but returns no instances",
			setup: func() {
				serviceMock.Reset()
				serviceMock.On("Run", mock.Anything).Return(&nmap.Run{}, []string{}, fmt.Errorf("Error"))
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
		_, err := n.StartScan()
		if testCase.shouldError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}

	}

}
