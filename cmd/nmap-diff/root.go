package main

import (
	"fmt"
	"github.com/port-scanner/pkg/config"
	"github.com/port-scanner/pkg/runner"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func NewRootCmd() *cobra.Command {
	baseConfig := config.BaseConfig{}
	gcloudConfig := config.GCloudConfig{}
	slackConfig := config.SlackConfig{}

	baseConfig.GCloudConfig = &gcloudConfig
	baseConfig.SlackConfig = &slackConfig

	logConfig := logConfig{}

	cmd := &cobra.Command{
		Use:   "nmap-diff",
		Short: "compares nmap results of cloud providers with previous runs",
		Long: `nmap-diff fetches the xml output of a previous scan from S3, runs a scan from the list of public instances,
		outputs the diff to slack, and then stores the current scan results to S3`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return setupLogging(&logConfig)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Debug("Setting up runner")

			err := runner.Execute(baseConfig)
			if err != nil {
				return fmt.Errorf("RunE: Error seting up runner %s", err)
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&logConfig.LogLevel, "log-level", "", "", "Log level (trace,info,fatal,panic,warn, debug) default is debug")
	f.StringVarP(&logConfig.LogType, "log-type", "", "", "Log type (text,json)")

	f.BoolVarP(&baseConfig.IncludeAWS, "include-aws", "a", false, "Include AWS Instances In Report")
	f.StringVarP(&baseConfig.BucketName, "s3-bucket", "s", "", "Name of S3 bucket to store reports in")
	f.StringVarP(&baseConfig.PreviousFileName, "report-path", "f", "", "Path of report in service account")

	f.BoolVarP(&baseConfig.IncludeGCloud, "include-gcloud", "g", false, "Include Google Cloud Instances In Report")
	f.StringVarP(&baseConfig.GCloudConfig.ServiceAccountPath, "gcloud-service-account-path", "", "", "Path of service account token. Uses default if not specified")
	f.StringVarP(&baseConfig.GCloudConfig.ProjectName, "gcloud-project", "p", "", "GCloud project to list instances from")

	f.StringVarP(&baseConfig.SlackConfig.SlackURL, "slack-url", "u", "", "Slack URL to post messages to")
	return cmd
}

type logConfig struct {
	LogLevel string
	LogType  string
}

func setupLogging(logConfig *logConfig) error {

	if logConfig.LogType == "json" {
		log.SetFormatter(&log.JSONFormatter{})
	} else {
		log.SetFormatter(&log.TextFormatter{
			ForceColors:   true,
			FullTimestamp: true,
		})
	}

	if logConfig.LogLevel == "debug" {
		log.SetLevel(log.DebugLevel)
	} else if logConfig.LogLevel == "info" {
		log.SetLevel(log.InfoLevel)
	} else if logConfig.LogLevel == "panic" {
		log.SetLevel(log.PanicLevel)
	} else if logConfig.LogLevel == "fatal" {
		log.SetLevel(log.FatalLevel)
	} else if logConfig.LogLevel == "trace" {
		log.SetLevel(log.TraceLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}
	return nil
}
