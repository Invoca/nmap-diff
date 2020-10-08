package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"testing"
)


type loggingPair struct {
	loglevelFromFlag string
	expectedLoglevel log.Level
}

//TODO: Add method of testing logging type. Not currently possible as far as I know.
func TestSetupLogging(t *testing.T) {

	lp := []loggingPair{
		{
			loglevelFromFlag: "trace",
			expectedLoglevel: log.TraceLevel,
		},
		{
			loglevelFromFlag: "debug",
			expectedLoglevel: log.DebugLevel,
		},
		{
			loglevelFromFlag: "info",
			expectedLoglevel: log.InfoLevel,
		},
		{
			loglevelFromFlag: "panic",
			expectedLoglevel: log.PanicLevel,
		},
		{
			loglevelFromFlag: "fatal",
			expectedLoglevel: log.FatalLevel,
		},
	}

	lc := &logConfig{}

	for _, logPair := range lp {
		lc.LogLevel = logPair.loglevelFromFlag
		err := setupLogging(lc)
		if err != nil {
			t.Fatalf("Error! %s", err)
		}

		assert.Equal(t, logPair.expectedLoglevel, log.GetLevel())
	}
}
