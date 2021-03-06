package slack

import (
	"github.com/Invoca/nmap-diff/pkg/server"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

type slackTestCase struct {
	desc        string
	setup       func() *httptest.Server
	shouldError bool
}


func TestPrintOpenedPorts(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	slackInterface := slack{}
	slackInterface.rateLimit = &rateLimitedHTTPClient{
		client:   http.DefaultClient,
		rlClient: rate.NewLimiter(rate.Every(10*time.Second), 10),
	}

	serverTag := make(map[string]string)
	serverTag["tagName"] = "tagValue"

	serverInterface := server.Server{
		Name:    "Instance1",
		Address: "1.1.1.1",
		Tags:    serverTag,
	}

	testCases := []slackTestCase{
		{
			desc: "Able to post to slack",
			setup: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			},
			shouldError: false,
		},
		{
			desc: "Error posting to slack",
			setup: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(500)
				}))
			},
			shouldError: true,
		},
	}

	for index, testCase := range testCases {
		log.WithFields(log.Fields{
			"desc":        testCase.desc,
			"shouldError": testCase.shouldError,
		}).Debug("Starting testCase " + strconv.Itoa(index))

		testServer := testCase.setup()
		slackInterface.slackUrl = testServer.URL

		err := slackInterface.PrintOpenedPorts(serverInterface, []uint16{20, 22})

		testServer.Close()

		if testCase.shouldError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}
