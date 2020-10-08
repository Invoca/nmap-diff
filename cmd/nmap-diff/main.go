package main

import (
	"os"
	log "github.com/sirupsen/logrus"
)

func main() {
	cmd := NewRootCmd()
	err := cmd.Execute()
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}
	log.Debug("Scan Complete")
}
