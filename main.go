package main

import (
	"github.com/port-scanner/pkg/config"
	"github.com/port-scanner/pkg/runner"
	log "github.com/sirupsen/logrus"
	"os"
)

func main() {
	log.SetLevel(log.DebugLevel)

	//TODO: Implement Cobra to populate configObject
	configObject := config.BaseConfig{
		IncludeAWS:       true,
		BucketName:       os.Getenv("S3_BUCKET"),
		PreviousFileName: os.Getenv("FILE_KEY"),
		IncludeGCloud:    true,
		GCloudConfig: &config.GCloudConfig{
			ServiceAccountPath: "",
			ProjectName:        os.Getenv("GCLOUD_REGION"),
		},
		SlackConfig: &config.SlackConfig{
			SlackURL: os.Getenv("SLACK_URL"),
		},
	}

	log.Info("Starting Run")
	runnerSvc, err := runner.SetupRunner(configObject)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	err = runnerSvc.Run(configObject)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	log.Info("Run Complete")
}
