package main

import (
"bytes"
"encoding/json"
"fmt"
"github.com/port-scanner/pkg/mocks"
log "github.com/sirupsen/logrus"
"github.com/stretchr/testify/assert"
"github.com/stretchr/testify/mock"
"net/http"
"net/http/httptest"
"strconv"
"testing"
)

type scanHandlerTestCase struct {
	desc        string
	setup       func()
	requestBody func() []byte
	shouldError bool
}

func TestSetupScanner(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	runnerMock := mocks.RunnerMock{}
	serverMock := server{runner: &runnerMock}

	testCases := []scanHandlerTestCase{
		{
			desc: "It should not return a 500 code if an empty Config object is passed",
			requestBody: func() []byte {
				body, _ := json.Marshal(Config{})
				return body
			},
			shouldError: false,
			setup: func() {
				runnerMock.Reset()
				runnerMock.On("Execute", mock.Anything).Return(nil)
			},
		},
		{
			desc: "It should return a 500 code if invalid json is passed",
			requestBody: func() []byte {
				return []byte("This is not json")
			},
			shouldError: true,
			setup: func() {
				runnerMock.Reset()
				runnerMock.On("Execute", mock.Anything).Return(nil)
			},
		},
		{
			desc: "It should not return a 500 code if a valid config is passed, and finishes executes without issues",
			requestBody: func() []byte {
				body, _ := json.Marshal(Config{
					IncludeAWS:         true,
					BucketName:         "bucket",
					PreviousFileName:   "dev/random",
					IncludeGCloud:      true,
					ServiceAccountPath: "path/to/json/file",
					SlackURL:           "http://test.com/aaa/bbb/ccc",
					ProjectName:        "astral-projection",
				})
				return body
			},
			shouldError: false,
			setup: func() {
				runnerMock.Reset()
				runnerMock.On("Execute", mock.Anything).Return(nil)
			},
		},
		{
			desc: "It should return a 500 code if a valid config is passed, and does not manage to finish executing",
			requestBody: func() []byte {
				body, _ := json.Marshal(Config{
					IncludeAWS:         true,
					BucketName:         "bucket",
					PreviousFileName:   "dev/random",
					IncludeGCloud:      true,
					ServiceAccountPath: "path/to/json/file",
					SlackURL:           "http://test.com/aaa/bbb/ccc",
					ProjectName:        "astral-projection",
				})
				return body
			},
			shouldError: true,
			setup: func() {
				runnerMock.Reset()
				runnerMock.On("Execute", mock.Anything).Return(fmt.Errorf("Error"))
			},
		},
	}

	for index, testCase := range testCases {
		log.WithFields(log.Fields{
			"desc":        testCase.desc,
			"shouldError": testCase.shouldError,
		}).Debug("Starting testCase " + strconv.Itoa(index))
		testCase.setup()

		server := httptest.NewServer(http.HandlerFunc(serverMock.scanHandler))

		resp, err := http.Post(server.URL, "", bytes.NewReader(testCase.requestBody()))
		server.Close()

		if err != nil {
			t.Fatal(err)
		}

		log.WithFields(log.Fields{
			"body": resp.Body,
			"resp": resp.StatusCode,
		}).Debug("Got Response")

		successfulResponse := resp.StatusCode == 200
		if testCase.shouldError {
			assert.Equal(t, successfulResponse, false)
		} else {
			assert.Equal(t, successfulResponse, true)
		}
	}
}
