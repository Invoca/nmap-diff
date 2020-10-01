package main

import (
	"fmt"
	"github.com/port-scanner/pkg/aws"
	"github.com/port-scanner/pkg/config"
	"github.com/port-scanner/pkg/gcloud"
	"github.com/port-scanner/pkg/scanner"
	"github.com/port-scanner/pkg/slack"
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

	awsSvc, err := aws.SetupAWS(configObject)
	if err != nil {
		fmt.Errorf("Error configuring AWS %s", err)
	}

	serversMap, err := awsSvc.GetInstances()
	if err != nil {
		fmt.Errorf("unable to run get AWS Instances: %s", err)
	}

	gCloudSvc, err := gcloud.Setup(configObject)
	if err != nil {
		fmt.Errorf("Error Setting up gCloud interface %s", err)
	}

	err = gCloudSvc.Instances(serversMap)
	if err != nil {
		fmt.Errorf("unable to run get Google Cloud Instances: %s", err)
	}

	ipAddresses := make([]string, len(serversMap))
	i := 0
	for k, _ := range serversMap {
		ipAddresses[i] = k
		i += 1
	}

	nmapScanner, err := scanner.SetupNmap(ipAddresses)
	if err != nil {
		fmt.Errorf("Error setting up nmapStruct interface: %s", err)
	}

	scanBytes, err := awsSvc.GetFileFromS3(configObject.PreviousFileName)
	if err != nil {
		fmt.Errorf("Error getting object %s", err)
	}

	oldInstances, err := nmapScanner.ParsePreviousScan(scanBytes)
	if err != nil {
		fmt.Errorf("unable to parse previous results in scanner")
	}

	err = nmapScanner.SetupScan()
	if err != nil {
		fmt.Errorf("Unable to setup nmap scanner")
	}

	newInstances, err := nmapScanner.StartScan()
	if err != nil {
		fmt.Errorf("unable to run nmap scan: %s", err)
	}

	instancesExposed, instancesRemoved, err := nmapScanner.DiffScans(newInstances, oldInstances)
	if err != nil {
		fmt.Errorf("Error Diffing Scans %s", err)
	}

	err = awsSvc.UploadObjectToS3(nmapScanner.CurrentScan, configObject.PreviousFileName)
	if err != nil {
		fmt.Errorf("Unable to upload object to S3")
	}

	slackSvc, err := slack.SetupSlack(configObject)
	if err != nil {
		fmt.Errorf("Unable to create slack Interface %s", err)
	}

	for host, portsMap := range instancesExposed {
		if len(portsMap) == 0 {
			continue
		}

		//TODO: Refactor to remove the map to slice conversion.
		portsSlice := make([]uint16, len(portsMap))
		for port, _ := range portsMap {
			portsSlice = append(portsSlice, port)
		}

		err = slackSvc.PrintOpenedPorts(serversMap[host], portsSlice)
		if err != nil {
			fmt.Errorf("Error posting to slack %s", err)
		}
	}

	for host, portsMap := range instancesRemoved {
		if len(portsMap) == 0 {
			continue
		}

		//TODO: Refactor to remove the map to slice conversion.
		portsSlice := make([]uint16, len(portsMap))
		for port, _ := range portsMap {
			portsSlice = append(portsSlice, port)
		}

		err = slackSvc.PrintClosedPorts(serversMap[host], portsSlice)
		if err != nil {
			fmt.Errorf("Error posting to slack %s", err)
		}
	}
}
